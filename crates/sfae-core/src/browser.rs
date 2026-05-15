//! Browser-based credential prompt and hosted OAuth handoff flow.
//!
//! Spins up a temporary local HTTP server, opens the user's default browser,
//! and waits for the user to submit credentials or complete a hosted OAuth session.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
#[cfg(feature = "cli")]
use std::process::Command;

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
    /// The caller is responsible for cancelling the process if it should stop waiting.
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

/// A simple HTML HTTP reply: status code plus body.
pub struct Reply<'a> {
    pub status: u16,
    pub html: &'a str,
}

impl HttpRequest {
    /// Send an HTML HTTP response.
    pub fn respond(&mut self, reply: Reply<'_>) {
        let status_text = match reply.status {
            200 => "OK",
            404 => "Not Found",
            _ => "OK",
        };
        let status = reply.status;
        let html = reply.html;
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
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

/// Parameters for the single-field `browser_prompt` helper.
#[cfg(feature = "cli")]
pub struct BrowserPromptArgs<'a> {
    pub label: &'a str,
    pub url: Option<&'a str>,
}

/// Result of a browser prompt.
#[cfg(feature = "cli")]
pub enum BrowserPromptResult {
    /// The user supplied local credential fields that the caller should store.
    Values(HashMap<String, String>),
    /// Hosted OAuth completed and the hosted broker materialized the credential.
    HostedOAuth {
        session_id: String,
        credential_id: Option<String>,
    },
}

/// Mutable state for one hosted OAuth flow started from the form.
#[cfg(feature = "cli")]
struct HostedOAuthFlow {
    group_idx: usize,
    session_id: String,
    credential_id: Option<String>,
    status: String,
}

/// Collect credentials from the user via a spec-driven form in the default browser.
///
/// Returns local field values to store, or a hosted OAuth completion marker.
/// Waits until the user submits the form or completes the hosted OAuth flow.
/// There is no built-in timeout.
#[cfg(feature = "cli")]
pub fn browser_prompt_spec(ctx: FormContext<'_>) -> Result<BrowserPromptResult, SfaeError> {
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

                let provider =
                    crate::oauth::resolve_hosted_provider(crate::oauth::HostedProviderResolve {
                        domain,
                        requested_provider: oauth.provider.as_deref(),
                    })?;
                let client = crate::oauth::HostedOAuthClient::from_env()?;
                let session = client.create_session(crate::oauth::HostedOAuthSessionInput {
                    provider: &provider,
                    domain,
                    label: credential_label,
                    scopes: oauth.requested_scopes(),
                })?;

                let authorization_url = session.authorization_url;
                hosted_oauth = Some(HostedOAuthFlow {
                    group_idx: idx,
                    session_id: session.session_id,
                    credential_id: None,
                    status: "pending".to_string(),
                });

                req.redirect(&authorization_url);
            }
            ("GET", "/oauth-status") => {
                let mut authorized = false;
                let mut error = false;
                if let Some(flow) = hosted_oauth.as_mut() {
                    match crate::oauth::HostedOAuthClient::from_env()
                        .and_then(|client| client.session_status(&flow.session_id))
                    {
                        Ok(status) => {
                            flow.status = status.status.clone();
                            flow.credential_id = status.credential_id.clone();
                            authorized = status.is_success();
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
                    req.respond(Reply {
                        status: 200,
                        html: &build_done_page(),
                    });
                    return Ok(BrowserPromptResult::HostedOAuth {
                        session_id: flow.session_id.clone(),
                        credential_id: flow.credential_id.clone(),
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
    match browser_prompt_spec(FormContext {
        domain: "",
        label,
        credential_label: None,
        spec: &spec,
    })? {
        BrowserPromptResult::Values(mut values) => values
            .remove("secret")
            .ok_or_else(|| SfaeError::Other("credential value cannot be empty".into())),
        BrowserPromptResult::HostedOAuth { .. } => Err(SfaeError::Other(
            "single-field browser prompt cannot complete hosted OAuth".into(),
        )),
    }
}
