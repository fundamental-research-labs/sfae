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
            r#"<p class="url-hint">Obtain your credential here:<br><a href="{}" target="_blank">{}</a></p>"#,
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sfae — enter credential</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f5f5f5;
    color: #1a1a1a;
    padding: 16px;
  }}
  .card {{
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 12px;
    padding: 40px;
    width: 100%;
    max-width: 440px;
  }}
  .logo {{
    font-size: 0.85em;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #888;
    margin-bottom: 24px;
  }}
  h1 {{
    font-size: 1.25em;
    font-weight: 600;
    line-height: 1.4;
    margin-bottom: 16px;
  }}
  .url-hint {{
    font-size: 0.9em;
    color: #555;
    margin-bottom: 20px;
    line-height: 1.5;
  }}
  .url-hint a {{
    color: #1a73e8;
    text-decoration: none;
    word-break: break-all;
  }}
  .url-hint a:hover {{
    text-decoration: underline;
  }}
  label {{
    display: block;
    font-size: 0.85em;
    font-weight: 500;
    color: #555;
    margin-bottom: 6px;
  }}
  input[type="password"] {{
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    font-size: 1em;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s;
  }}
  input[type="password"]:focus {{
    border-color: #1a73e8;
    box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.1);
  }}
  button {{
    margin-top: 16px;
    width: 100%;
    padding: 10px;
    font-size: 1em;
    font-weight: 500;
    font-family: inherit;
    background: #1a1a1a;
    color: #fff;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.15s;
  }}
  button:hover {{
    background: #333;
  }}
  button:active {{
    background: #000;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">sfae</div>
  <h1>{}</h1>
  {}
  <form method="POST" action="/">
    <label for="secret">Credential</label>
    <input type="password" id="secret" name="secret" autofocus placeholder="Paste your secret here">
    <button type="submit">Submit</button>
  </form>
</div>
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sfae — done</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f5f5f5;
    color: #1a1a1a;
    padding: 16px;
  }
  .card {
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 12px;
    padding: 40px;
    width: 100%;
    max-width: 440px;
    text-align: center;
  }
  .check {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: #e8f5e9;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 20px;
  }
  .check svg {
    width: 24px;
    height: 24px;
    stroke: #2e7d32;
    fill: none;
    stroke-width: 2.5;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  h1 {
    font-size: 1.25em;
    font-weight: 600;
    margin-bottom: 8px;
  }
  p {
    font-size: 0.95em;
    color: #555;
  }
</style>
</head>
<body>
<div class="card">
  <div class="check"><svg viewBox="0 0 24 24"><polyline points="4 12 10 18 20 6"/></svg></div>
  <h1>Credential saved</h1>
  <p>You can close this tab.</p>
</div>
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
