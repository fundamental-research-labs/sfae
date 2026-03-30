use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use crate::error::SfaeError;

/// A temporary local HTTP server bound to `127.0.0.1` on a random port.
///
/// Shared infrastructure used by both the browser-based secret prompt
/// and the OAuth2 callback flow.
pub struct LocalServer {
    listener: TcpListener,
    port: u16,
}

impl LocalServer {
    /// Bind a new server to `127.0.0.1:0` with a 120-second accept timeout.
    pub fn new() -> Result<Self, SfaeError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| SfaeError::Other(format!("failed to bind local server: {e}")))?;

        let port = listener
            .local_addr()
            .map_err(|e| SfaeError::Other(format!("failed to get local address: {e}")))?
            .port();

        listener
            .set_nonblocking(false)
            .map_err(|e| SfaeError::Other(format!("failed to configure listener: {e}")))?;
        set_accept_timeout(&listener, Duration::from_secs(120))?;

        Ok(Self { listener, port })
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Open the given URL in the default browser (macOS-only for now).
    pub fn open_browser(&self, url: &str) -> Result<(), SfaeError> {
        let status = Command::new("open")
            .arg(url)
            .status()
            .map_err(|e| SfaeError::Other(format!("failed to open browser: {e}")))?;
        if !status.success() {
            return Err(SfaeError::Other(
                "failed to open browser: non-zero exit code".into(),
            ));
        }
        Ok(())
    }

    /// Accept one HTTP request. Returns (method, path, headers, body).
    ///
    /// On timeout returns `SfaeError::Cancelled`.
    /// The caller is responsible for sending a response via `send_response`.
    pub fn accept_request(&self) -> Result<HttpRequest, SfaeError> {
        let (stream, _addr) = self.listener.accept().map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => SfaeError::Cancelled,
            _ => SfaeError::Other(format!("accept error: {e}")),
        })?;

        let mut reader = BufReader::new(&stream);

        // Read request line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return Ok(HttpRequest {
                method: String::new(),
                path: String::new(),
                body: String::new(),
                stream,
            });
        }

        let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
        let (method, path) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (String::new(), String::new())
        };

        // Read headers.
        let mut content_length: usize = 0;
        loop {
            let mut header_line = String::new();
            if reader.read_line(&mut header_line).is_err() {
                break;
            }
            let trimmed = header_line.trim();
            if trimmed.is_empty() {
                break;
            }
            let lower = trimmed.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("content-length:")
                && let Ok(len) = val.trim().parse::<usize>()
            {
                content_length = len;
            }
        }

        // Read body if present.
        let mut body = String::new();
        if content_length > 0 {
            let mut buf = vec![0u8; content_length];
            if reader.read_exact(&mut buf).is_ok() {
                body = String::from_utf8_lossy(&buf).into_owned();
            }
        }

        Ok(HttpRequest {
            method,
            path,
            body,
            stream,
        })
    }
}

/// An incoming HTTP request with its underlying TCP stream for sending the response.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: String,
    stream: std::net::TcpStream,
}

impl HttpRequest {
    /// Send an HTTP response with the given status code and HTML body.
    pub fn respond(&mut self, status: u16, html: &str) {
        let status_text = match status {
            200 => "OK",
            404 => "Not Found",
            _ => "OK",
        };
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
            html.len(),
        );
        let _ = self.stream.write_all(response.as_bytes());
        let _ = self.stream.flush();
    }
}

/// Collect a secret from the user via a local web page opened in the default browser.
///
/// - `label` — heading shown on the page (e.g., "Enter API_KEY for github.com").
/// - `url`   — optional link displayed on the page to help the user find where to create the secret.
///
/// Starts a temporary HTTP server on `127.0.0.1` (random port), opens the browser,
/// waits for the user to submit the form, then returns the secret.
/// Times out after 120 seconds with `SfaeError::Cancelled`.
pub fn browser_prompt(label: &str, url: Option<&str>) -> Result<String, SfaeError> {
    let server = LocalServer::new()?;
    let local_url = format!("http://127.0.0.1:{}/", server.port());
    server.open_browser(&local_url)?;

    loop {
        let mut req = server.accept_request()?;

        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => {
                let html = build_form_page(label, url);
                req.respond(200, &html);
            }
            ("POST", "/") => {
                let secret = parse_form_secret(&req.body).unwrap_or_default();
                req.respond(200, &build_done_page());

                if secret.is_empty() {
                    return Err(SfaeError::Other("credential value cannot be empty".into()));
                }
                return Ok(secret);
            }
            _ => {
                req.respond(404, "");
            }
        }
    }
}

/// Run the OAuth2 callback server: wait for the provider to redirect back with an auth code.
///
/// Returns `(code, state)` extracted from the callback query parameters.
/// The server shows a "Done" page to the user and shuts down.
pub fn oauth_callback(server: &LocalServer) -> Result<(String, String), SfaeError> {
    loop {
        let mut req = server.accept_request()?;

        // We only care about GET /callback?code=...&state=...
        if req.method == "GET" && req.path.starts_with("/callback") {
            let code = extract_query_param(&req.path, "code");
            let state = extract_query_param(&req.path, "state");

            req.respond(200, &build_done_page());

            let code = code.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'code' parameter".into())
            })?;
            let state = state.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'state' parameter".into())
            })?;

            return Ok((code, state));
        }

        // Ignore other requests (favicon, etc.).
        req.respond(404, "");
    }
}

/// Extract a query parameter value from a path like `/callback?code=abc&state=xyz`.
fn extract_query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(&format!("{key}=")) {
            return Some(url_decode(value));
        }
    }
    None
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

/// Build the confirmation page shown after the secret is submitted or OAuth completes.
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
