//! Browser-based credential prompt and OAuth2 callback flow.
//!
//! Spins up a temporary local HTTP server, opens the user's default browser,
//! and waits for the user to submit credentials or complete an OAuth handshake.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
#[cfg(feature = "cli")]
use std::process::Command;
use std::time::Duration;

use crate::error::SfaeError;
#[cfg(feature = "cli")]
use crate::spec::{FieldSpec, OAuthSpec, PromptSpec};

#[cfg(feature = "cli")]
pub use crate::browser_html::FormContext;
use crate::browser_html::{QueryLookup, extract_query_param};
#[cfg(feature = "cli")]
use crate::browser_html::{
    build_done_page, build_form_page, build_oauth_done_page, collect_common_fields,
    parse_form_fields,
};

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

        // Set an accept timeout via SO_RCVTIMEO so blocking accept() times out.
        {
            use std::os::fd::AsRawFd;
            let timeout = Duration::from_secs(120);
            let tv = libc::timeval {
                tv_sec: timeout.as_secs() as _,
                tv_usec: 0,
            };
            let ret = unsafe {
                libc::setsockopt(
                    listener.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(SfaeError::Other("failed to set socket timeout".into()));
            }
        }

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

/// Resolved OAuth configuration with all URLs and app credentials populated.
#[cfg(feature = "cli")]
struct ResolvedOAuth {
    auth_url: String,
    token_url: String,
    revocation_url: Option<String>,
    scope: String,
    client_id: String,
    client_secret: Option<String>,
}

/// Parameters for `resolve_oauth_spec`.
#[cfg(feature = "cli")]
struct OAuthResolve<'a> {
    domain: &'a str,
    spec: &'a OAuthSpec,
}

/// Parameters for the single-field `browser_prompt` helper.
#[cfg(feature = "cli")]
pub struct BrowserPromptArgs<'a> {
    pub label: &'a str,
    pub url: Option<&'a str>,
}

/// Resolve an OAuthSpec against provider presets for the given domain.
///
/// Merges spec-provided URLs with preset defaults. Errors if required URLs
/// or app credentials are missing and no preset covers this domain.
#[cfg(feature = "cli")]
fn resolve_oauth_spec(args: OAuthResolve<'_>) -> Result<ResolvedOAuth, SfaeError> {
    let OAuthResolve { domain, spec } = args;
    let preset = crate::oauth::get_provider_preset(domain);

    let auth_url = spec
        .auth_url
        .clone()
        .or_else(|| preset.as_ref().map(|p| p.auth_url.to_string()))
        .ok_or_else(|| {
            SfaeError::ConfigError(format!(
                "OAuth auth_url is required (no built-in preset for \"{domain}\")"
            ))
        })?;

    let token_url = spec
        .token_url
        .clone()
        .or_else(|| preset.as_ref().map(|p| p.token_url.to_string()))
        .ok_or_else(|| {
            SfaeError::ConfigError(format!(
                "OAuth token_url is required (no built-in preset for \"{domain}\")"
            ))
        })?;

    let revocation_url = spec.revocation_url.clone().or_else(|| {
        preset
            .as_ref()
            .and_then(|p| p.revocation_url.map(|s| s.to_string()))
    });

    let client_id = preset
        .as_ref()
        .map(|p| p.client_id.to_string())
        .ok_or_else(|| {
            SfaeError::ConfigError(format!(
                "no OAuth app configured for \"{domain}\" — register app credentials or use a supported provider"
            ))
        })?;

    let client_secret = preset
        .as_ref()
        .and_then(|p| p.client_secret.map(|s| s.to_string()));

    Ok(ResolvedOAuth {
        auth_url,
        token_url,
        revocation_url,
        scope: spec.scope.clone(),
        client_id,
        client_secret,
    })
}

/// Collect credentials from the user via a spec-driven form in the default browser.
///
/// Returns a map of field names to values collected from the form.
/// Times out after 120 seconds with `SfaeError::Cancelled`.
#[cfg(feature = "cli")]
pub fn browser_prompt_spec(ctx: FormContext<'_>) -> Result<HashMap<String, String>, SfaeError> {
    let FormContext {
        domain,
        label,
        spec,
    } = ctx;
    // Resolve OAuth specs for all groups upfront.
    let groups = spec.groups.as_deref().unwrap_or(&[]);
    let resolved_oauth: Vec<Option<ResolvedOAuth>> = groups
        .iter()
        .map(|g| {
            g.oauth
                .as_ref()
                .map(|oauth_spec| {
                    resolve_oauth_spec(OAuthResolve {
                        domain,
                        spec: oauth_spec,
                    })
                })
                .transpose()
        })
        .collect::<Result<_, _>>()?;

    let server = LocalServer::new()?;
    let local_url = format!("http://127.0.0.1:{}/", server.port());
    server.open_browser(&local_url)?;

    // Mutable state for the ongoing OAuth flow.
    let mut pending_verifier: Option<String> = None;
    let mut pending_state: Option<String> = None;
    let mut pending_group: Option<usize> = None;
    let mut oauth_tokens: Option<HashMap<String, String>> = None;

    loop {
        let mut req = server.accept_request()?;
        let path = req.path.split('?').next().unwrap_or(&req.path).to_string();

        match (req.method.as_str(), path.as_str()) {
            ("GET", "/") => {
                let html = build_form_page(FormContext {
                    domain,
                    label,
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
                let Some(Some(resolved)) = resolved_oauth.get(idx) else {
                    req.respond(Reply {
                        status: 400,
                        html: "invalid group or not an OAuth group",
                    });
                    continue;
                };

                let verifier = crate::oauth::generate_code_verifier();
                let challenge = crate::oauth::compute_code_challenge(&verifier);
                let state = crate::oauth::generate_state();
                let redirect_uri = format!("http://127.0.0.1:{}/callback", server.port());

                let auth_url = crate::oauth::AuthorizationUrl {
                    auth_url: &resolved.auth_url,
                    client_id: &resolved.client_id,
                    redirect_uri: &redirect_uri,
                    code_challenge: &challenge,
                    scope: Some(&resolved.scope),
                    state: &state,
                }
                .build();

                pending_verifier = Some(verifier);
                pending_state = Some(state);
                pending_group = Some(idx);

                req.redirect(&auth_url);
            }
            ("GET", "/callback") => {
                let code = extract_query_param(QueryLookup {
                    path: &req.path,
                    key: "code",
                });
                let state = extract_query_param(QueryLookup {
                    path: &req.path,
                    key: "state",
                });

                let (Some(code), Some(state)) = (code, state) else {
                    req.respond(Reply {
                        status: 400,
                        html: "missing code or state parameter",
                    });
                    continue;
                };

                // Validate state matches the pending OAuth flow.
                if pending_state.as_deref() != Some(&state) {
                    req.respond(Reply {
                        status: 400,
                        html: "invalid state parameter",
                    });
                    continue;
                }

                let Some(verifier) = pending_verifier.take() else {
                    req.respond(Reply {
                        status: 400,
                        html: "no pending OAuth flow",
                    });
                    continue;
                };
                let Some(idx) = pending_group.take() else {
                    req.respond(Reply {
                        status: 400,
                        html: "no pending OAuth flow",
                    });
                    continue;
                };
                let Some(Some(resolved)) = resolved_oauth.get(idx) else {
                    req.respond(Reply {
                        status: 400,
                        html: "invalid OAuth group",
                    });
                    continue;
                };
                pending_state = None;

                let redirect_uri = format!("http://127.0.0.1:{}/callback", server.port());
                let token_resp = crate::oauth::TokenRequest {
                    token_url: &resolved.token_url,
                    client_id: &resolved.client_id,
                    client_secret: resolved.client_secret.as_deref(),
                    grant: crate::oauth::Grant::AuthorizationCode {
                        code: &code,
                        redirect_uri: &redirect_uri,
                        code_verifier: &verifier,
                    },
                }
                .send()?;

                // Save OAuth metadata for future token refresh.
                crate::oauth::MetadataKey {
                    domain,
                    username: None,
                }
                .save(crate::oauth::OAuthMetadata {
                    token_url: resolved.token_url.clone(),
                    client_id: resolved.client_id.clone(),
                    revocation_url: resolved.revocation_url.clone(),
                })?;

                let mut tokens = HashMap::new();
                tokens.insert("OAUTH_ACCESS_TOKEN".to_string(), token_resp.access_token);
                if let Some(rt) = token_resp.refresh_token {
                    tokens.insert("OAUTH_REFRESH_TOKEN".to_string(), rt);
                }
                tokens.insert("OAUTH_TOKEN_URL".to_string(), resolved.token_url.clone());
                if let Some(rev) = &resolved.revocation_url {
                    tokens.insert("OAUTH_REVOCATION_URL".to_string(), rev.clone());
                }
                oauth_tokens = Some(tokens);

                req.respond(Reply {
                    status: 200,
                    html: &build_oauth_done_page(),
                });
            }
            ("GET", "/oauth-status") => {
                let json = if oauth_tokens.is_some() {
                    r#"{"authorized":true}"#
                } else {
                    r#"{"authorized":false}"#
                };
                req.respond_json(json);
            }
            ("POST", "/") => {
                let raw = parse_form_fields(&req.body);
                req.respond(Reply {
                    status: 200,
                    html: &build_done_page(),
                });

                // Determine expected fields: common fields first, then
                // the active group's fields.  The HTML used opaque names
                // `_f0`, `_f1`, … — the index matches this ordered list.
                let common = collect_common_fields(spec);
                let mut expected = common.clone();
                if let Some(groups) = &spec.groups
                    && let Some(group_idx) = raw.get("_group")
                    && let Ok(idx) = group_idx.parse::<usize>()
                    && let Some(group) = groups.get(idx)
                    && let Some(fields) = &group.fields
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
                // Pass through the _group selector as-is.
                if let Some(g) = raw.get("_group") {
                    values.insert("_group".to_string(), g.clone());
                }

                // Validate no empty values for expected required fields.
                for field in &expected {
                    if field.is_optional() {
                        continue;
                    }
                    let val = values.get(&field.name).map(|s| s.as_str()).unwrap_or("");
                    if val.is_empty() {
                        return Err(SfaeError::Other(format!(
                            "credential value for {} cannot be empty",
                            field.name
                        )));
                    }
                }

                // Return expected field values plus any OAuth tokens.
                // Omit empty optional fields from the result.
                let mut result: HashMap<String, String> = expected
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

                if let Some(tokens) = oauth_tokens.take() {
                    result.extend(tokens);
                }

                return Ok(result);
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

/// Collect a secret from the user via a local web page opened in the default browser.
///
/// - `label` — heading shown on the page (e.g., "Enter API_KEY for github.com").
/// - `url`   — optional link displayed on the page to help the user find where to create the secret.
///
/// Starts a temporary HTTP server on `127.0.0.1` (random port), opens the browser,
/// waits for the user to submit the form, then returns the secret.
/// Times out after 120 seconds with `SfaeError::Cancelled`.
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
    let mut values = browser_prompt_spec(FormContext {
        domain: "",
        label,
        spec: &spec,
    })?;
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
            let code = extract_query_param(QueryLookup {
                path: &req.path,
                key: "code",
            });
            let state = extract_query_param(QueryLookup {
                path: &req.path,
                key: "state",
            });

            req.respond(Reply {
                status: 200,
                html: &build_done_page(),
            });

            let code = code.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'code' parameter".into())
            })?;
            let state = state.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'state' parameter".into())
            })?;

            return Ok((code, state));
        }

        // Ignore other requests (favicon, etc.).
        req.respond(Reply {
            status: 404,
            html: "",
        });
    }
}
