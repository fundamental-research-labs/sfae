use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use crate::error::SfaeError;

/// Collect a secret from the user via a local web page opened in the default browser.
///
/// - `label` — heading shown on the page (e.g., "Enter API_KEY for github.com").
/// - `url`   — optional link displayed on the page to help the user find where to create the secret.
///
/// Starts a temporary HTTP server on `127.0.0.1` (random port), opens the browser,
/// waits for the user to submit the form, then returns the secret.
/// Times out after 120 seconds with `SfaeError::Cancelled`.
pub fn browser_prompt(label: &str, url: Option<&str>) -> Result<String, SfaeError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| SfaeError::Other(format!("failed to bind local server: {e}")))?;

    let port = listener
        .local_addr()
        .map_err(|e| SfaeError::Other(format!("failed to get local address: {e}")))?
        .port();

    // 120-second timeout so the CLI doesn't hang forever.
    listener
        .set_nonblocking(false)
        .map_err(|e| SfaeError::Other(format!("failed to configure listener: {e}")))?;
    let timeout = Duration::from_secs(120);
    set_accept_timeout(&listener, timeout)?;

    // Open the default browser (macOS-only for now).
    let local_url = format!("http://127.0.0.1:{port}/");
    let status = Command::new("open")
        .arg(&local_url)
        .status()
        .map_err(|e| SfaeError::Other(format!("failed to open browser: {e}")))?;
    if !status.success() {
        return Err(SfaeError::Other(
            "failed to open browser: non-zero exit code".into(),
        ));
    }

    // Serve requests until we receive the secret via POST.
    loop {
        let (mut stream, _addr) = listener.accept().map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => SfaeError::Cancelled,
            _ => SfaeError::Other(format!("accept error: {e}")),
        })?;

        let mut reader = BufReader::new(&stream);

        // Read the request line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }

        let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let method = parts[0];
        let path = parts[1];

        // Read headers to find Content-Length (needed for POST body).
        let mut content_length: usize = 0;
        loop {
            let mut header_line = String::new();
            if reader.read_line(&mut header_line).is_err() {
                break;
            }
            let trimmed = header_line.trim();
            if trimmed.is_empty() {
                break; // End of headers.
            }
            // Case-insensitive Content-Length check.
            let lower = trimmed.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("content-length:")
                && let Ok(len) = val.trim().parse::<usize>()
            {
                content_length = len;
            }
        }

        match (method, path) {
            ("GET", "/") => {
                let html = build_form_page(label, url);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            ("POST", "/") => {
                // Read the POST body.
                let mut body = vec![0u8; content_length];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let body_str = String::from_utf8_lossy(&body);

                // Parse form-urlencoded body: "secret=<value>"
                let secret = parse_form_secret(&body_str).unwrap_or_default();

                // Send the confirmation page.
                let html = build_done_page();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();

                if secret.is_empty() {
                    return Err(SfaeError::Other("credential value cannot be empty".into()));
                }

                return Ok(secret);
            }
            _ => {
                // Ignore other requests (favicon, etc.).
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    }
}

/// Build the HTML form page.
fn build_form_page(label: &str, url: Option<&str>) -> String {
    let url_section = match url {
        Some(u) => format!(
            r#"<p>Obtain your credential here: <a href="{}" target="_blank">{}</a></p>"#,
            html_escape(u),
            html_escape(u),
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>sfae — enter credential</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 16px; }}
  h1 {{ font-size: 1.3em; }}
  input[type="password"] {{ width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; font-size: 1em; }}
  button {{ padding: 8px 24px; font-size: 1em; cursor: pointer; }}
</style>
</head>
<body>
<h1>{}</h1>
{}
<form method="POST" action="/">
  <input type="password" name="secret" autofocus placeholder="Paste your secret here">
  <br><br>
  <button type="submit">Submit</button>
</form>
</body>
</html>"#,
        html_escape(label),
        url_section,
    )
}

/// Build the confirmation page shown after the secret is submitted.
fn build_done_page() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>sfae — done</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 16px; }
</style>
</head>
<body>
<h1>Done</h1>
<p>Your credential has been saved. You can close this tab.</p>
</body>
</html>"#
        .to_string()
}

/// Minimal HTML escaping for user-provided strings embedded in HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Extract the `secret` field from a `application/x-www-form-urlencoded` body.
fn parse_form_secret(body: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some(value) = pair.strip_prefix("secret=") {
            return Some(url_decode(value));
        }
    }
    None
}

/// Minimal percent-decoding for form values.
fn url_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
                result.push(byte);
                i += 3;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// Set an accept timeout on the listener using socket options.
fn set_accept_timeout(listener: &TcpListener, timeout: Duration) -> Result<(), SfaeError> {
    use std::os::fd::AsRawFd;

    let fd = listener.as_raw_fd();
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(SfaeError::Other("failed to set socket timeout".into()));
    }
    Ok(())
}
