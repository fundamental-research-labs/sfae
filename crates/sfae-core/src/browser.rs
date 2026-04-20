use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
#[cfg(feature = "cli")]
use std::process::Command;
use std::time::Duration;

use crate::error::SfaeError;
#[cfg(feature = "cli")]
use crate::spec::{FieldSpec, GroupSpec, OAuthSpec, PromptSpec};

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

/// Shared context for the browser-based form flow.
#[cfg(feature = "cli")]
pub struct FormContext<'a> {
    pub domain: &'a str,
    pub label: &'a str,
    pub spec: &'a PromptSpec,
}

/// Parameters for the single-field `browser_prompt` helper.
#[cfg(feature = "cli")]
pub struct BrowserPromptArgs<'a> {
    pub label: &'a str,
    pub url: Option<&'a str>,
}

/// A path string paired with the query-parameter key to extract.
pub struct QueryLookup<'a> {
    pub path: &'a str,
    pub key: &'a str,
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
                req.respond(Reply { status: 200, html: &html });
            }
            ("GET", "/auth") => {
                let group_idx = extract_query_param(QueryLookup {
                    path: &req.path,
                    key: "group",
                })
                .and_then(|s| s.parse::<usize>().ok());
                let Some(idx) = group_idx else {
                    req.respond(Reply { status: 400, html: "missing group parameter" });
                    continue;
                };
                let Some(Some(resolved)) = resolved_oauth.get(idx) else {
                    req.respond(Reply { status: 400, html: "invalid group or not an OAuth group" });
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
                    req.respond(Reply { status: 400, html: "missing code or state parameter" });
                    continue;
                };

                // Validate state matches the pending OAuth flow.
                if pending_state.as_deref() != Some(&state) {
                    req.respond(Reply { status: 400, html: "invalid state parameter" });
                    continue;
                }

                let Some(verifier) = pending_verifier.take() else {
                    req.respond(Reply { status: 400, html: "no pending OAuth flow" });
                    continue;
                };
                let Some(idx) = pending_group.take() else {
                    req.respond(Reply { status: 400, html: "no pending OAuth flow" });
                    continue;
                };
                let Some(Some(resolved)) = resolved_oauth.get(idx) else {
                    req.respond(Reply { status: 400, html: "invalid OAuth group" });
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

                req.respond(Reply { status: 200, html: &build_oauth_done_page() });
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
                req.respond(Reply { status: 200, html: &build_done_page() });

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
                req.respond(Reply { status: 404, html: "" });
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

            req.respond(Reply { status: 200, html: &build_done_page() });

            let code = code.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'code' parameter".into())
            })?;
            let state = state.ok_or_else(|| {
                SfaeError::Other("OAuth callback missing 'state' parameter".into())
            })?;

            return Ok((code, state));
        }

        // Ignore other requests (favicon, etc.).
        req.respond(Reply { status: 404, html: "" });
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
fn extract_query_param(lookup: QueryLookup<'_>) -> Option<String> {
    let QueryLookup { path, key } = lookup;
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
fn build_form_page(ctx: FormContext<'_>) -> String {
    let FormContext { label, spec, .. } = ctx;
    let url_section = match spec.help_url.as_deref() {
        Some(u) => format!(
            r#"<p class="url-hint">Obtain your credential here:<br><a href="{}" target="_blank">{}</a></p>"#,
            html_escape(u),
            html_escape(u),
        ),
        None => String::new(),
    };

    let common_fields = collect_common_fields(spec);
    let has_common = !common_fields.is_empty();
    let fields_html = FieldsRender {
        fields: &common_fields,
        autofocus_first: true,
        index_offset: 0,
    }
    .render();
    let groups = spec.groups.as_deref().unwrap_or(&[]);
    let groups_html = GroupsRender {
        groups,
        autofocus_first_group: !has_common,
        field_index_offset: common_fields.len(),
    }
    .render();

    // Hide the submit button when the only content is OAuth (no input fields).
    let has_any_input_fields = has_common
        || groups
            .iter()
            .any(|g| g.fields.as_ref().is_some_and(|f| !f.is_empty()));
    let submit_button = if has_any_input_fields {
        r#"<button type="button" onclick="sfaeSubmit()">Submit</button>"#
    } else {
        ""
    };

    apply_template(Template {
        source: include_str!("form.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{LABEL}}", &html_escape(label)),
            ("{{URL_SECTION}}", &url_section),
            ("{{FIELDS}}", &fields_html),
            ("{{GROUPS}}", &groups_html),
            ("{{SUBMIT_BUTTON}}", submit_button),
        ],
    })
}

/// Parameters for rendering a list of form fields as HTML.
#[cfg(feature = "cli")]
struct FieldsRender<'a> {
    fields: &'a [FieldSpec],
    autofocus_first: bool,
    index_offset: usize,
}

#[cfg(feature = "cli")]
impl<'a> FieldsRender<'a> {
    /// Generate HTML for a list of field specs.
    fn render(&self) -> String {
        let FieldsRender {
            fields,
            autofocus_first,
            index_offset,
        } = *self;
        let mut html = String::new();
        for (i, field) in fields.iter().enumerate() {
            // All field identifiers are opaque to defeat Safari/macOS Passwords
            // heuristics. Names like "PASSWORD" or "ACCESS_TOKEN" trigger the
            // "Save Password?" dialog. We use `_f0`, `_f1`, … and the server
            // maps them back by index.
            let idx = index_offset + i;
            let opaque_name = format!("_f{idx}");
            let label = html_escape(&field.display_label());
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
            let data_required = if field.is_optional() {
                ""
            } else {
                r#" data-required="true""#
            };
            let optional_hint = if field.is_optional() {
                r#" <span class="optional-hint">(optional)</span>"#
            } else {
                ""
            };
            if field.is_secret() {
                html.push_str(&format!(
                    r#"<div class="field"><label>{label}{optional_hint}</label><div style="position:relative"><input type="text" name="{opaque_name}"{value}{autofocus}{data_required} data-m="1"><span class="dots" aria-hidden="true"></span></div></div>"#,
                ));
            } else {
                html.push_str(&format!(
                    r#"<div class="field"><label>{label}{optional_hint}</label><input type="text" name="{opaque_name}"{value}{autofocus}{data_required}></div>"#,
                ));
            }
        }
        html
    }
}

/// Parameters for rendering alternative field groups.
#[cfg(feature = "cli")]
struct GroupsRender<'a> {
    groups: &'a [GroupSpec],
    autofocus_first_group: bool,
    field_index_offset: usize,
}

#[cfg(feature = "cli")]
impl<'a> GroupsRender<'a> {
    /// Generate HTML for alternative field groups with tab selector and toggle script.
    fn render(&self) -> String {
        let GroupsRender {
            groups,
            autofocus_first_group,
            field_index_offset,
        } = *self;
        if groups.is_empty() {
            return String::new();
        }

        let mut html = String::from(r#"<div class="groups">"#);

        // Only show the tab bar when there are multiple groups to choose between.
        if groups.len() > 1 {
            html.push_str(r#"<div class="group-tabs">"#);
            for (i, group) in groups.iter().enumerate() {
                let checked = if i == 0 { " checked" } else { "" };
                let label = html_escape(&group.label);
                html.push_str(&format!(
                    r#"<label class="group-tab"><input type="radio" name="_group" value="{i}"{checked}><span>{label}</span></label>"#,
                ));
            }
            html.push_str("</div>");
        } else {
            // Single group: emit a hidden input so the server still knows which group.
            html.push_str(r#"<input type="hidden" name="_group" value="0">"#);
        }

        for (i, group) in groups.iter().enumerate() {
            let hidden = if i == 0 {
                ""
            } else {
                r#" style="display:none""#
            };
            html.push_str(&format!(
                r#"<div class="group-panel" data-group="{i}"{hidden}>"#,
            ));
            if let Some(oauth) = &group.oauth {
                html.push_str(
                    &OAuthPanel {
                        oauth,
                        group_idx: i,
                    }
                    .render(),
                );
            } else if let Some(fields) = &group.fields {
                html.push_str(
                    &FieldsRender {
                        fields,
                        autofocus_first: autofocus_first_group && i == 0,
                        index_offset: field_index_offset,
                    }
                    .render(),
                );
            }
            html.push_str("</div>");
        }

        html.push_str("</div>");

        // Inline JS for group toggling and OAuth status polling.
        html.push_str(concat!(
            "<script>(function(){",
            // Toggle function: show/hide panels, disable inactive inputs.
            "function u(v){",
            "document.querySelectorAll('.group-panel').forEach(function(p){",
            "var a=p.dataset.group===v;",
            "p.style.display=a?'':'none';",
            "p.querySelectorAll('input:not([name=\"_group\"])').forEach(function(i){i.disabled=!a})",
            "})}",
            "var c=document.querySelector('input[name=\"_group\"]:checked');",
            "if(c)u(c.value);",
            "document.querySelectorAll('input[name=\"_group\"]').forEach(function(r){",
            "r.addEventListener('change',function(){u(r.value)})",
            "});",
            // Poll for OAuth completion when an OAuth group exists.
            "var oa=document.querySelector('.oauth-content');",
            "if(oa){var t=setInterval(function(){",
            "fetch('/oauth-status').then(function(r){return r.json()}).then(function(d){",
            "if(d.authorized){",
            "clearInterval(t);",
            "document.querySelectorAll('.oauth-btn').forEach(function(b){b.style.display='none'});",
            "document.querySelectorAll('.oauth-status').forEach(function(s){s.style.display='flex'});",
            // Auto-submit when there are no input fields to fill (OAuth-only flow).
            "var inputs=document.querySelectorAll('input[type=\"text\"]:not(:disabled)');",
            "if(!inputs.length){sfaeSubmit()}",
            "}",
            "}).catch(function(){})",
            "},1500)}",
            "})()</script>",
        ));

        html
    }
}

/// Parameters for rendering a single OAuth group panel.
#[cfg(feature = "cli")]
struct OAuthPanel<'a> {
    oauth: &'a OAuthSpec,
    group_idx: usize,
}

#[cfg(feature = "cli")]
impl<'a> OAuthPanel<'a> {
    /// Generate HTML for an OAuth group panel: scope display + "Authorize" button.
    fn render(&self) -> String {
        let scope = html_escape(&self.oauth.scope);
        let group_idx = self.group_idx;
        let mut html = String::new();
        html.push_str(r#"<div class="oauth-content">"#);
        html.push_str(&format!(
            r#"<p class="oauth-scope">Scope: <code>{scope}</code></p>"#,
        ));
        html.push_str(&format!(
            r#"<a href="/auth?group={group_idx}" target="_blank" class="oauth-btn" id="oauth-btn-{group_idx}">Authorize</a>"#,
        ));
        html.push_str(&format!(
            r#"<div class="oauth-status" id="oauth-status-{group_idx}" style="display:none">&#10003; Authorized</div>"#,
        ));
        html.push_str("</div>");
        html
    }
}

/// A template source plus substitution pairs used to fill `{{VARS}}`.
struct Template<'a> {
    source: &'a str,
    vars: &'a [(&'a str, &'a str)],
}

/// Apply a sequence of `{{KEY}} → value` substitutions to a template string.
fn apply_template(tpl: Template<'_>) -> String {
    let mut out = tpl.source.to_string();
    for (key, value) in tpl.vars {
        out = out.replace(key, value);
    }
    out
}

/// Build the page shown in the OAuth popup after authorization completes.
fn build_oauth_done_page() -> String {
    apply_template(Template {
        source: include_str!("done.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{TITLE}}", "sfae \u{2014} authorized"),
            ("{{HEADING}}", "Authorized"),
        ],
    })
}

/// Build the confirmation page shown after the secret is submitted or OAuth completes.
fn build_done_page() -> String {
    apply_template(Template {
        source: include_str!("done.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{TITLE}}", "sfae \u{2014} done"),
            ("{{HEADING}}", "Credential saved"),
        ],
    })
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

