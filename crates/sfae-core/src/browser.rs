use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
#[cfg(feature = "cli")]
use std::process::Command;
use std::time::Duration;

use crate::error::SfaeError;
#[cfg(feature = "cli")]
use crate::spec::{FieldSpec, GroupSpec, PromptSpec};

/// Shared CSS included in both form and done pages.
const BASE_STYLES: &str = include_str!("base.css");

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
    #[cfg(feature = "cli")]
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

/// Collect credentials from the user via a spec-driven form in the default browser.
///
/// Returns a map of field names to values collected from the form.
/// Times out after 120 seconds with `SfaeError::Cancelled`.
#[cfg(feature = "cli")]
pub fn browser_prompt_spec(
    label: &str,
    spec: &PromptSpec,
) -> Result<HashMap<String, String>, SfaeError> {
    let server = LocalServer::new()?;
    let local_url = format!("http://127.0.0.1:{}/", server.port());
    server.open_browser(&local_url)?;

    loop {
        let mut req = server.accept_request()?;

        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => {
                let html = build_form_page(label, spec);
                req.respond(200, &html);
            }
            ("POST", "/") => {
                let mut values = parse_form_fields(&req.body);
                req.respond(200, &build_done_page());

                // Determine expected fields: common + active group.
                let mut expected = collect_common_fields(spec);
                if let Some(groups) = &spec.groups
                    && let Some(group_idx) = values.remove("_group")
                    && let Ok(idx) = group_idx.parse::<usize>()
                    && let Some(group) = groups.get(idx)
                    && let Some(fields) = &group.fields
                {
                    expected.extend(fields.iter().cloned());
                }

                // Validate no empty values for expected fields.
                for field in &expected {
                    let val = values.get(&field.name).map(|s| s.as_str()).unwrap_or("");
                    if val.is_empty() {
                        return Err(SfaeError::Other(format!(
                            "credential value for {} cannot be empty",
                            field.name
                        )));
                    }
                }

                // Return only expected field values.
                let result = expected
                    .iter()
                    .filter_map(|f| values.remove(&f.name).map(|v| (f.name.clone(), v)))
                    .collect();

                return Ok(result);
            }
            _ => {
                req.respond(404, "");
            }
        }
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
#[cfg(feature = "cli")]
pub fn browser_prompt(label: &str, url: Option<&str>) -> Result<String, SfaeError> {
    // Build a single-field spec and delegate.
    let spec = PromptSpec {
        url: url.map(|s| s.to_string()),
        fields: Some(vec![FieldSpec {
            name: "secret".to_string(),
            label: Some("Credential".to_string()),
            default: None,
            secret: Some(true),
        }]),
        groups: None,
    };
    let mut values = browser_prompt_spec(label, &spec)?;
    values
        .remove("secret")
        .ok_or_else(|| SfaeError::Other("credential value cannot be empty".into()))
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

/// Collect common (non-group) fields from a PromptSpec.
#[cfg(feature = "cli")]
fn collect_common_fields(spec: &PromptSpec) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    if let Some(ref f) = spec.fields {
        fields.extend(f.iter().cloned());
    }
    fields
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

/// Build the HTML form page with data-driven fields and optional groups.
#[cfg(feature = "cli")]
fn build_form_page(label: &str, spec: &PromptSpec) -> String {
    let url_section = match spec.url.as_deref() {
        Some(u) => format!(
            r#"<p class="url-hint">Obtain your credential here:<br><a href="{}" target="_blank">{}</a></p>"#,
            html_escape(u),
            html_escape(u),
        ),
        None => String::new(),
    };

    let common_fields = collect_common_fields(spec);
    let has_common = !common_fields.is_empty();
    let fields_html = build_fields_html(&common_fields, true);
    let groups = spec.groups.as_deref().unwrap_or(&[]);
    let groups_html = build_groups_html(groups, !has_common);

    include_str!("form.html")
        .replace("{{BASE_STYLES}}", BASE_STYLES)
        .replace("{{LABEL}}", &html_escape(label))
        .replace("{{URL_SECTION}}", &url_section)
        .replace("{{FIELDS}}", &fields_html)
        .replace("{{GROUPS}}", &groups_html)
}

/// Generate HTML for a list of field specs.
#[cfg(feature = "cli")]
fn build_fields_html(fields: &[FieldSpec], autofocus_first: bool) -> String {
    let mut html = String::new();
    for (i, field) in fields.iter().enumerate() {
        let input_type = if field.is_secret() {
            "password"
        } else {
            "text"
        };
        let label = html_escape(&field.display_label());
        let name = html_escape(&field.name);
        let id = format!("field_{}", html_escape(&field.name));
        let autofocus = if autofocus_first && i == 0 {
            " autofocus"
        } else {
            ""
        };
        let value = field
            .default
            .as_ref()
            .map(|d| format!(r#" value="{}""#, html_escape(d)))
            .unwrap_or_default();
        let placeholder = if field.is_secret() {
            format!(r#" placeholder="Enter {}""#, label)
        } else {
            String::new()
        };

        html.push_str(&format!(
            r#"<div class="field"><label for="{id}">{label}</label><input type="{input_type}" id="{id}" name="{name}"{value}{autofocus}{placeholder}></div>"#,
        ));
    }
    html
}

/// Generate HTML for alternative field groups with tab selector and toggle script.
#[cfg(feature = "cli")]
fn build_groups_html(groups: &[GroupSpec], autofocus_first_group: bool) -> String {
    if groups.is_empty() {
        return String::new();
    }

    let mut html = String::from(r#"<div class="groups"><div class="group-tabs">"#);

    for (i, group) in groups.iter().enumerate() {
        let checked = if i == 0 { " checked" } else { "" };
        let label = html_escape(&group.label);
        html.push_str(&format!(
            r#"<label class="group-tab"><input type="radio" name="_group" value="{i}"{checked}><span>{label}</span></label>"#,
        ));
    }
    html.push_str("</div>");

    for (i, group) in groups.iter().enumerate() {
        let hidden = if i == 0 {
            ""
        } else {
            r#" style="display:none""#
        };
        html.push_str(&format!(
            r#"<div class="group-panel" data-group="{i}"{hidden}>"#,
        ));
        if let Some(fields) = &group.fields {
            html.push_str(&build_fields_html(fields, autofocus_first_group && i == 0));
        }
        html.push_str("</div>");
    }

    html.push_str("</div>");

    // Inline JS for group toggling: show/hide panels and disable inactive inputs.
    html.push_str(concat!(
        "<script>(function(){",
        "function u(v){",
        "document.querySelectorAll('.group-panel').forEach(function(p){",
        "var a=p.dataset.group===v;",
        "p.style.display=a?'':'none';",
        "p.querySelectorAll('input').forEach(function(i){i.disabled=!a})",
        "})}",
        "var c=document.querySelector('input[name=\"_group\"]:checked');",
        "if(c)u(c.value);",
        "document.querySelectorAll('input[name=\"_group\"]').forEach(function(r){",
        "r.addEventListener('change',function(){u(r.value)})",
        "})",
        "})()</script>",
    ));

    html
}

/// Build the confirmation page shown after the secret is submitted or OAuth completes.
fn build_done_page() -> String {
    include_str!("done.html").replace("{{BASE_STYLES}}", BASE_STYLES)
}

/// Minimal HTML escaping for user-provided strings embedded in HTML.
#[cfg(feature = "cli")]
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Parse all key=value pairs from a `application/x-www-form-urlencoded` body.
#[cfg(feature = "cli")]
fn parse_form_fields(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            map.insert(url_decode(key), url_decode(value));
        }
    }
    map
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
        tv_sec: timeout.as_secs() as _,
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
