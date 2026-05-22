//! Browser-based credential prompt and hosted OAuth handoff flow.
//!
//! Spins up a temporary local HTTP server, opens the user's default browser,
//! and waits for the user to submit credentials or complete a hosted OAuth session.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "cli")]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(feature = "cli")]
use crate::code::CodeRequest;
#[cfg(feature = "cli")]
use crate::code_html::{
    CodePageContext, build_code_cancelled_page, build_code_done_page, build_code_page,
};
use crate::error::SfaeError;
#[cfg(feature = "cli")]
use crate::spec::{FieldSpec, PromptSpec};

#[cfg(feature = "cli")]
pub use crate::browser_html::FormContext;
use crate::browser_html::{QueryLookup, extract_query_param};
#[cfg(feature = "cli")]
use crate::browser_html::{
    build_done_page, build_form_page, collect_common_fields, parse_form_fields,
};

/// A temporary local HTTP server bound to `127.0.0.1` on a random port.
///
/// Shared infrastructure used by the browser-based secret prompt.
pub struct LocalServer {
    listener: TcpListener,
    port: u16,
}

impl LocalServer {
    /// Bind a new server to `127.0.0.1:0`.
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

        Ok(Self { listener, port })
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Open the given URL in the default browser.
    #[cfg(feature = "cli")]
    pub fn open_browser(&self, url: &str) -> Result<(), SfaeError> {
        let mut command = browser_open_command(url);
        let status = command
            .stdout(Stdio::null())
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
    /// The caller is responsible for cancelling the process if it should stop waiting.
    /// The caller is responsible for sending a response via `send_response`.
    pub fn accept_request(&self) -> Result<HttpRequest, SfaeError> {
        let (stream, _addr) = self.listener.accept().map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => SfaeError::Cancelled,
            _ => SfaeError::Other(format!("accept error: {e}")),
        })?;

        read_http_request(RequestRead {
            stream,
            read_timeout: None,
            max_body_len: None,
        })
    }

    /// Accept one HTTP request before a deadline, using nonblocking polling.
    fn accept_request_until(&self, opts: TimedAccept<'_>) -> Result<HttpRequest, SfaeError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|e| SfaeError::Other(format!("failed to configure listener: {e}")))?;

        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    stream.set_nonblocking(false).map_err(|e| {
                        let _ = self.listener.set_nonblocking(false);
                        SfaeError::Other(format!("failed to configure request stream: {e}"))
                    })?;
                    let remaining = match remaining_until(RemainingDeadline {
                        deadline: opts.deadline,
                        timeout_message: opts.timeout_message,
                    }) {
                        Ok(remaining) => remaining,
                        Err(e) => {
                            let _ = self.listener.set_nonblocking(false);
                            return Err(e);
                        }
                    };
                    let result = read_http_request(RequestRead {
                        stream,
                        read_timeout: Some(remaining.min(opts.read_timeout)),
                        max_body_len: opts.max_body_len,
                    });
                    let _ = self.listener.set_nonblocking(false);
                    return result;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let remaining = match remaining_until(RemainingDeadline {
                        deadline: opts.deadline,
                        timeout_message: opts.timeout_message,
                    }) {
                        Ok(remaining) => remaining,
                        Err(e) => {
                            let _ = self.listener.set_nonblocking(false);
                            return Err(e);
                        }
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(50)));
                }
                Err(e) => {
                    let _ = self.listener.set_nonblocking(false);
                    return Err(SfaeError::Other(format!("accept error: {e}")));
                }
            }
        }
    }
}

#[cfg(all(feature = "cli", target_os = "macos"))]
fn browser_open_command(url: &str) -> Command {
    let mut command = Command::new("open");
    command.arg(url);
    command
}

#[cfg(all(feature = "cli", target_os = "windows"))]
fn browser_open_command(url: &str) -> Command {
    let mut command = Command::new("cmd");
    command.args(["/C", "start", "", url]);
    command
}

#[cfg(all(feature = "cli", unix, not(target_os = "macos")))]
fn browser_open_command(url: &str) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url);
    command
}

struct TimedAccept<'a> {
    deadline: Instant,
    read_timeout: Duration,
    max_body_len: Option<usize>,
    timeout_message: &'a str,
}

struct RequestRead {
    stream: TcpStream,
    read_timeout: Option<Duration>,
    max_body_len: Option<usize>,
}

struct RemainingDeadline<'a> {
    deadline: Instant,
    timeout_message: &'a str,
}

fn remaining_until(args: RemainingDeadline<'_>) -> Result<Duration, SfaeError> {
    args.deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| SfaeError::Other(args.timeout_message.to_string()))
}

fn read_http_request(read: RequestRead) -> Result<HttpRequest, SfaeError> {
    let RequestRead {
        stream,
        read_timeout,
        max_body_len,
    } = read;

    if let Some(timeout) = read_timeout {
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| SfaeError::Other(format!("failed to configure read timeout: {e}")))?;
    }

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

    // Read body if present. Code-request callers pass a cap to avoid
    // unbounded local POST bodies; existing prompt callers preserve old behavior.
    let mut body = String::new();
    if content_length > 0 {
        let read_len = max_body_len
            .map(|max| content_length.min(max.saturating_add(1)))
            .unwrap_or(content_length);
        let mut buf = vec![0u8; read_len];
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

/// An incoming HTTP request with its underlying TCP stream for sending the response.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: String,
    stream: std::net::TcpStream,
}

/// A simple HTML HTTP reply: status code plus body.
pub struct Reply<'a> {
    pub status: u16,
    pub html: &'a str,
}

impl HttpRequest {
    /// Send an HTML HTTP response.
    pub fn respond(&mut self, reply: Reply<'_>) {
        self.respond_html(HtmlResponse {
            reply,
            no_store: false,
        });
    }

    /// Send an HTML HTTP response that should not be cached by the browser.
    pub fn respond_no_store(&mut self, reply: Reply<'_>) {
        self.respond_html(HtmlResponse {
            reply,
            no_store: true,
        });
    }

    fn respond_html(&mut self, response: HtmlResponse<'_>) {
        let HtmlResponse { reply, no_store } = response;
        let status_text = match reply.status {
            200 => "OK",
            400 => "Bad Request",
            413 => "Payload Too Large",
            404 => "Not Found",
            _ => "OK",
        };
        let status = reply.status;
        let html = reply.html;
        let cache_headers = if no_store {
            "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n"
        } else {
            ""
        };
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\n{cache_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{html}",
            html.len(),
        );
        let _ = self.stream.write_all(response.as_bytes());
        let _ = self.stream.flush();
    }

    /// Send an HTTP 302 redirect response.
    pub fn redirect(&mut self, url: &str) {
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = self.stream.write_all(response.as_bytes());
        let _ = self.stream.flush();
    }

    /// Send a JSON response.
    pub fn respond_json(&mut self, json: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len(),
        );
        let _ = self.stream.write_all(response.as_bytes());
        let _ = self.stream.flush();
    }
}

struct HtmlResponse<'a> {
    reply: Reply<'a>,
    no_store: bool,
}

/// Parameters for the single-field `browser_prompt` helper.
#[cfg(feature = "cli")]
pub struct BrowserPromptArgs<'a> {
    pub label: &'a str,
    pub url: Option<&'a str>,
}

const MAX_CODE_REQUEST_BODY: usize = 2048;
const CODE_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Request a transient one-time code from the user via the default browser.
///
/// The returned code is not stored. The caller decides what to do with it,
/// typically printing it to stdout so an agent can complete a 2FA challenge.
#[cfg(feature = "cli")]
pub fn browser_code_request(request: CodeRequest) -> Result<String, SfaeError> {
    request.validate()?;
    let server = LocalServer::new()?;
    let local_url = format!("http://127.0.0.1:{}/", server.port());
    server.open_browser(&local_url)?;
    serve_code_request(CodeServe { request, server })
}

#[cfg(feature = "cli")]
struct CodeServe {
    request: CodeRequest,
    server: LocalServer,
}

#[cfg(feature = "cli")]
fn serve_code_request(args: CodeServe) -> Result<String, SfaeError> {
    let CodeServe { request, server } = args;
    let csrf_token = uuid::Uuid::new_v4().to_string();
    let timeout_message = format!("code request timed out after {}s", request.timeout_secs());
    let deadline = Instant::now()
        .checked_add(request.timeout)
        .ok_or_else(|| SfaeError::ConfigError("timeout is too large".into()))?;

    loop {
        let mut req = server.accept_request_until(TimedAccept {
            deadline,
            read_timeout: CODE_REQUEST_READ_TIMEOUT,
            max_body_len: Some(MAX_CODE_REQUEST_BODY),
            timeout_message: &timeout_message,
        })?;
        let path = req.path.split('?').next().unwrap_or(&req.path).to_string();

        match (req.method.as_str(), path.as_str()) {
            ("GET", "/") => {
                let html = build_code_page(CodePageContext {
                    request: &request,
                    csrf_token: &csrf_token,
                    error: None,
                    timeout_secs: seconds_remaining(deadline),
                });
                req.respond_no_store(Reply {
                    status: 200,
                    html: &html,
                });
            }
            ("POST", "/") => {
                if req.body.len() > MAX_CODE_REQUEST_BODY {
                    respond_body_too_large(&mut req);
                    continue;
                }
                let raw = parse_form_fields(&req.body);
                if raw.get("_csrf").map(String::as_str) != Some(csrf_token.as_str()) {
                    req.respond_no_store(Reply {
                        status: 400,
                        html: "invalid request token",
                    });
                    continue;
                }
                let submitted = raw.get("_code").map(String::as_str).unwrap_or("");
                match request.normalize_code(submitted) {
                    Ok(code) => {
                        let html = build_code_done_page();
                        req.respond_no_store(Reply {
                            status: 200,
                            html: &html,
                        });
                        return Ok(code);
                    }
                    Err(e) => {
                        let message = e.to_string();
                        let html = build_code_page(CodePageContext {
                            request: &request,
                            csrf_token: &csrf_token,
                            error: Some(&message),
                            timeout_secs: seconds_remaining(deadline),
                        });
                        req.respond_no_store(Reply {
                            status: 400,
                            html: &html,
                        });
                    }
                }
            }
            ("POST", "/cancel") => {
                if req.body.len() > MAX_CODE_REQUEST_BODY {
                    respond_body_too_large(&mut req);
                    continue;
                }
                let raw = parse_form_fields(&req.body);
                if raw.get("_csrf").map(String::as_str) != Some(csrf_token.as_str()) {
                    req.respond_no_store(Reply {
                        status: 400,
                        html: "invalid request token",
                    });
                    continue;
                }
                let html = build_code_cancelled_page();
                req.respond_no_store(Reply {
                    status: 200,
                    html: &html,
                });
                return Err(SfaeError::Cancelled);
            }
            _ => {
                req.respond_no_store(Reply {
                    status: 404,
                    html: "",
                });
            }
        }
    }
}

fn seconds_remaining(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_secs()
}

fn respond_body_too_large(req: &mut HttpRequest) {
    req.respond_no_store(Reply {
        status: 413,
        html: "request body too large",
    });
}

/// Result of a browser prompt.
#[cfg(feature = "cli")]
pub enum BrowserPromptResult {
    /// The user supplied local credential fields that the caller should store.
    Values(HashMap<String, String>),
    /// Hosted OAuth completed and any local credential material has been stored.
    HostedOAuth {
        session_id: String,
        credential_id: Option<String>,
    },
}

/// Callback used by the CLI to durably store redeemed local OAuth credentials.
#[cfg(feature = "cli")]
pub type OAuthCredentialSink<'a> =
    dyn FnMut(crate::oauth::HostedOAuthCredential) -> Result<String, SfaeError> + 'a;

/// Mutable state for one hosted OAuth flow started from the form.
#[cfg(feature = "cli")]
struct HostedOAuthFlow {
    group_idx: usize,
    session_id: String,
    redeem_verifier: Option<String>,
    completion_verifier: Option<String>,
    credential_id: Option<String>,
    status: String,
}

/// Collect credentials from the user via a spec-driven form in the default browser.
///
/// Returns local field values to store, or a hosted OAuth completion marker.
/// Waits until the user submits the form or completes the hosted OAuth flow.
/// There is no built-in timeout.
#[cfg(feature = "cli")]
// xtask: allow-multi-param - form context plus optional OAuth manager dependency
pub fn browser_prompt_spec(
    ctx: FormContext<'_>,
    mut oauth_manager: Option<&mut crate::oauth::OAuthCredentialManager<'_>>,
    mut oauth_credential_sink: Option<&mut OAuthCredentialSink<'_>>,
) -> Result<BrowserPromptResult, SfaeError> {
    let FormContext {
        domain,
        label,
        credential_label,
        spec,
    } = ctx;
    let groups = spec.groups.as_deref().unwrap_or(&[]);
    if spec
        .fields
        .as_ref()
        .is_some_and(|fields| !fields.is_empty())
        && groups.iter().any(|group| group.oauth.is_some())
    {
        return Err(SfaeError::ConfigError(
            "hosted OAuth groups cannot be combined with common fields in this phase".into(),
        ));
    }

    let server = LocalServer::new()?;
    let local_url = format!("http://127.0.0.1:{}/", server.port());
    server.open_browser(&local_url)?;

    let mut hosted_oauth: Option<HostedOAuthFlow> = None;

    loop {
        let mut req = server.accept_request()?;
        let path = req.path.split('?').next().unwrap_or(&req.path).to_string();

        match (req.method.as_str(), path.as_str()) {
            ("GET", "/") => {
                let html = build_form_page(FormContext {
                    domain,
                    label,
                    credential_label,
                    spec,
                });
                req.respond(Reply {
                    status: 200,
                    html: &html,
                });
            }
            ("GET", "/auth") => {
                let group_idx = extract_query_param(QueryLookup {
                    path: &req.path,
                    key: "group",
                })
                .and_then(|s| s.parse::<usize>().ok());
                let Some(idx) = group_idx else {
                    req.respond(Reply {
                        status: 400,
                        html: "missing group parameter",
                    });
                    continue;
                };
                let Some(Some(oauth)) = groups.get(idx).map(|g| g.oauth.as_ref()) else {
                    req.respond(Reply {
                        status: 400,
                        html: "invalid group or not an OAuth group",
                    });
                    continue;
                };

                let Some(manager) = oauth_manager.as_mut() else {
                    req.respond(Reply {
                        status: 400,
                        html: "hosted OAuth is not configured",
                    });
                    return Err(SfaeError::ConfigError(
                        "hosted OAuth is not configured".into(),
                    ));
                };
                let provider = manager.resolve_provider(domain, oauth.provider.as_deref())?;
                let session = manager.start_session(crate::oauth::HostedOAuthStart {
                    provider: &provider,
                    domain,
                    label: credential_label,
                    scopes: oauth.requested_scopes(),
                    return_url: Some(&format!(
                        "http://127.0.0.1:{}/oauth-complete",
                        server.port()
                    )),
                })?;

                let authorization_url = session.authorization_url;
                hosted_oauth = Some(HostedOAuthFlow {
                    group_idx: idx,
                    session_id: session.session_id,
                    redeem_verifier: session.redeem_verifier,
                    completion_verifier: None,
                    credential_id: None,
                    status: "pending".to_string(),
                });

                req.redirect(&authorization_url);
            }
            ("GET", "/oauth-complete") => {
                if let Some(flow) = hosted_oauth.as_mut() {
                    let session_id = extract_query_param(QueryLookup {
                        path: &req.path,
                        key: "session_id",
                    });
                    let status = extract_query_param(QueryLookup {
                        path: &req.path,
                        key: "status",
                    });
                    if session_id.as_deref() == Some(flow.session_id.as_str()) {
                        if let Some(status) = status {
                            flow.status = status;
                        }
                        flow.completion_verifier = extract_query_param(QueryLookup {
                            path: &req.path,
                            key: "completion_verifier",
                        });
                    }
                }
                req.respond(Reply {
                    status: 200,
                    html: local_oauth_complete_page(),
                });
            }
            ("GET", "/oauth-status") => {
                let mut authorized = false;
                let mut error = false;
                if let Some(flow) = hosted_oauth.as_mut() {
                    match oauth_manager
                        .as_mut()
                        .ok_or_else(|| {
                            SfaeError::ConfigError("hosted OAuth is not configured".into())
                        })
                        .and_then(|manager| manager.session_status(&flow.session_id))
                    {
                        Ok(status) => {
                            flow.status = status.status.clone();
                            flow.credential_id = status.credential_id.clone();
                            authorized = status.is_success()
                                && (flow.redeem_verifier.is_none()
                                    || flow.completion_verifier.is_some());
                            error = status.is_error();
                        }
                        Err(_) => {
                            flow.status = "error".to_string();
                            error = true;
                        }
                    }
                }
                let json = format!(r#"{{"authorized":{authorized},"error":{error}}}"#);
                req.respond_json(&json);
            }
            ("POST", "/") => {
                let raw = parse_form_fields(&req.body);

                // Determine expected fields: common fields first, then
                // the active group's fields.  The HTML used opaque names
                // `_f0`, `_f1`, … — the index matches this ordered list.
                let common = collect_common_fields(spec);
                let mut expected = common.clone();
                let selected_group_idx = selected_group_idx(&raw);
                let selected_oauth = selected_group_idx
                    .and_then(|idx| groups.get(idx).map(|group| (idx, group.oauth.is_some())));
                if let Some((idx, false)) = selected_oauth
                    && let Some(fields) = groups.get(idx).and_then(|group| group.fields.as_ref())
                {
                    expected.extend(fields.iter().cloned());
                }

                // Map opaque `_fN` keys back to real field names.
                // Common fields: _f0 … _f(common.len()-1)
                // Group fields:  _f(common.len()) … _f(common.len()+group.len()-1)
                let mut values: HashMap<String, String> = HashMap::new();
                for (i, field) in common.iter().enumerate() {
                    if let Some(v) = raw.get(&format!("_f{i}")) {
                        values.insert(field.name.clone(), v.clone());
                    }
                }
                let offset = common.len();
                for (i, field) in expected.iter().skip(offset).enumerate() {
                    if let Some(v) = raw.get(&format!("_f{}", offset + i)) {
                        values.insert(field.name.clone(), v.clone());
                    }
                }
                // Validate no empty values for expected required fields.
                for field in &expected {
                    if field.is_optional() {
                        continue;
                    }
                    let val = values.get(&field.name).map(|s| s.as_str()).unwrap_or("");
                    if val.is_empty() {
                        let message =
                            format!("credential value for {} cannot be empty", field.name);
                        req.respond(Reply {
                            status: 400,
                            html: &message,
                        });
                        return Err(SfaeError::Other(message));
                    }
                }

                // Return expected field values. Omit empty optional fields.
                let result: HashMap<String, String> = expected
                    .iter()
                    .filter_map(|f| {
                        values.remove(&f.name).and_then(|v| {
                            if v.is_empty() && f.is_optional() {
                                None
                            } else {
                                Some((f.name.clone(), v))
                            }
                        })
                    })
                    .collect();

                if let Some((group_idx, true)) = selected_oauth {
                    let Some(flow) = hosted_oauth.as_ref() else {
                        req.respond(Reply {
                            status: 400,
                            html: "OAuth authorization has not started",
                        });
                        return Err(SfaeError::Other(
                            "OAuth authorization has not started".into(),
                        ));
                    };
                    if flow.group_idx != group_idx {
                        req.respond(Reply {
                            status: 400,
                            html: "OAuth authorization was started for a different group",
                        });
                        return Err(SfaeError::Other(
                            "OAuth authorization was started for a different group".into(),
                        ));
                    }
                    if flow.status != "success" {
                        req.respond(Reply {
                            status: 400,
                            html: "OAuth authorization has not completed",
                        });
                        return Err(SfaeError::Other(
                            "OAuth authorization has not completed".into(),
                        ));
                    }
                    if !result.is_empty() {
                        req.respond(Reply {
                            status: 400,
                            html: "Hosted OAuth cannot store local form fields in this phase",
                        });
                        return Err(SfaeError::ConfigError(
                            "hosted OAuth cannot store local form fields in this phase".into(),
                        ));
                    }
                    let credential = oauth_manager
                        .as_mut()
                        .ok_or_else(|| {
                            SfaeError::ConfigError("hosted OAuth is not configured".into())
                        })?
                        .redeem_session(
                            &flow.session_id,
                            flow.redeem_verifier.as_deref(),
                            flow.completion_verifier.as_deref(),
                        )?;
                    let credential_id = if let Some(credential) = credential {
                        let Some(sink) = oauth_credential_sink.as_mut() else {
                            req.respond(Reply {
                                status: 500,
                                html: "OAuth credential storage is not configured",
                            });
                            return Err(SfaeError::ConfigError(
                                "OAuth credential storage is not configured".into(),
                            ));
                        };
                        Some(sink(credential)?)
                    } else {
                        flow.credential_id.clone()
                    };
                    req.respond(Reply {
                        status: 200,
                        html: &build_done_page(),
                    });
                    return Ok(BrowserPromptResult::HostedOAuth {
                        session_id: flow.session_id.clone(),
                        credential_id,
                    });
                }

                req.respond(Reply {
                    status: 200,
                    html: &build_done_page(),
                });
                return Ok(BrowserPromptResult::Values(result));
            }
            _ => {
                req.respond(Reply {
                    status: 404,
                    html: "",
                });
            }
        }
    }
}

#[cfg(feature = "cli")]
fn selected_group_idx(raw: &HashMap<String, String>) -> Option<usize> {
    raw.get("_group").and_then(|idx| idx.parse::<usize>().ok())
}

#[cfg(feature = "cli")]
fn local_oauth_complete_page() -> &'static str {
    "<!doctype html><meta charset=\"utf-8\"><title>SFAE OAuth</title>\
     <body style=\"font-family:system-ui;margin:3rem;line-height:1.5\">\
     <h1>Authorization complete</h1><p>You can return to the SFAE credential window.</p></body>"
}

/// Collect a secret from the user via a local web page opened in the default browser.
///
/// - `label` — heading shown on the page (e.g., "Enter API_KEY for github.com").
/// - `url`   — optional link displayed on the page to help the user find where to create the secret.
///
/// Starts a temporary HTTP server on `127.0.0.1` (random port), opens the browser,
/// waits for the user to submit the form, then returns the secret.
/// There is no built-in timeout.
#[cfg(feature = "cli")]
pub fn browser_prompt(args: BrowserPromptArgs<'_>) -> Result<String, SfaeError> {
    let BrowserPromptArgs { label, url } = args;
    // Build a single-field spec and delegate.
    let spec = PromptSpec {
        help_url: url.map(|s| s.to_string()),
        fields: Some(vec![FieldSpec {
            name: "secret".to_string(),
            label: Some("Credential".to_string()),
            default: None,
            secret: Some(true),
            optional: None,
        }]),
        groups: None,
    };
    match browser_prompt_spec(
        FormContext {
            domain: "",
            label,
            credential_label: None,
            spec: &spec,
        },
        None,
        None,
    )? {
        BrowserPromptResult::Values(mut values) => values
            .remove("secret")
            .ok_or_else(|| SfaeError::Other("credential value cannot be empty".into())),
        BrowserPromptResult::HostedOAuth { .. } => Err(SfaeError::Other(
            "single-field browser prompt cannot complete hosted OAuth".into(),
        )),
    }
}

#[cfg(test)]
#[path = "browser_code_tests.rs"]
mod browser_code_tests;
