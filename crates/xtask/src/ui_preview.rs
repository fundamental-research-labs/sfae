//! Local server for visually reviewing SFAE browser credential collection UI states.
//!
//! The preview serves synthetic pages rendered through the production templates
//! and never calls credential storage, hosted OAuth brokers, or external APIs.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, ExitCode};
use std::time::Duration;

use sfae_core::browser::FormContext;
use sfae_core::code::{CodeFormat, CodeRequest};
use sfae_core::preview::{
    CodePreview, render_code_cancelled_page, render_code_done_page, render_code_page,
    render_credential_done_page, render_form_page,
};
use sfae_core::{FieldSpec, GroupSpec, OAuthSpec, PromptSpec};

const DEFAULT_PORT: u16 = 0;
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REQUEST_BYTES: usize = 64 * 1024;

const FIXTURES: &[Fixture] = &[
    Fixture {
        path: "/prompt/simple-token",
        title: "Simple token prompt",
        description: "Single secret field with a help link.",
    },
    Fixture {
        path: "/prompt/multi-field",
        title: "Multi-field prompt",
        description: "Public, secret, defaulted, and optional fields.",
    },
    Fixture {
        path: "/prompt/groups",
        title: "Grouped credential prompt",
        description: "Common URL plus Basic Auth and API key choices.",
    },
    Fixture {
        path: "/prompt/oauth-pending",
        title: "OAuth pending",
        description: "Hosted OAuth group before authorization is complete.",
    },
    Fixture {
        path: "/prompt/oauth-authorized",
        title: "OAuth authorized",
        description: "Hosted OAuth group after a successful authorization.",
    },
    Fixture {
        path: "/prompt/oauth-error",
        title: "OAuth error",
        description: "Hosted OAuth group with an authorization failure.",
    },
    Fixture {
        path: "/code/digits",
        title: "Verification code",
        description: "Digits-only one-time-code request.",
    },
    Fixture {
        path: "/code/error",
        title: "Verification code error",
        description: "One-time-code request with validation feedback.",
    },
    Fixture {
        path: "/code/done",
        title: "Verification code done",
        description: "Completion page after submitting a code.",
    },
    Fixture {
        path: "/code/cancelled",
        title: "Verification code cancelled",
        description: "Completion page after cancelling a code request.",
    },
    Fixture {
        path: "/done/credential",
        title: "Credential saved",
        description: "Completion page after submitting credential fields.",
    },
];

struct Fixture {
    path: &'static str,
    title: &'static str,
    description: &'static str,
}

struct Config {
    port: u16,
    open: bool,
}

enum ParsedConfig {
    Run(Config),
    Help,
}

impl Config {
    fn parse(args: &[String]) -> Result<ParsedConfig, String> {
        let mut port = DEFAULT_PORT;
        let mut open = false;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if arg == "--open" {
                open = true;
                continue;
            }
            if arg == "--help" || arg == "-h" {
                return Ok(ParsedConfig::Help);
            }
            if let Some(raw) = arg.strip_prefix("--port=") {
                port = parse_port(raw)?;
                continue;
            }
            if arg == "--port" {
                let Some(raw) = iter.next() else {
                    return Err("--port requires a value".into());
                };
                port = parse_port(raw)?;
                continue;
            }
            return Err(format!("unknown ui-preview option: {arg}\n\n{}", usage()));
        }
        Ok(ParsedConfig::Run(Self { port, open }))
    }
}

pub fn run(args: &[String]) -> ExitCode {
    let config = match Config::parse(args) {
        Ok(ParsedConfig::Run(config)) => config,
        Ok(ParsedConfig::Help) => {
            eprintln!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let server = match PreviewServer::bind(config.port) {
        Ok(server) => server,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let url = format!("http://127.0.0.1:{}/", server.port());
    eprintln!("SFAE UI preview: {url}");
    eprintln!("No credentials are requested, printed, stored, or sent.");
    if config.open
        && let Err(message) = open_url(&url)
    {
        eprintln!("{message}");
    }
    server.serve()
}

fn usage() -> String {
    "usage: cargo xtask ui-preview [--port <port>] [--open]".into()
}

fn parse_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|e| format!("invalid --port value {raw:?}: {e}"))
}

fn open_url(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url).status();
    #[cfg(target_os = "windows")]
    let status = Command::new("cmd").args(["/C", "start", "", url]).status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(url).status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "failed to open browser: exit {}",
            status.code().unwrap_or(-1)
        )),
        Err(e) => Err(format!("failed to open browser: {e}")),
    }
}

struct PreviewServer {
    listener: TcpListener,
}

impl PreviewServer {
    fn bind(port: u16) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("failed to bind preview server: {e}"))?;
        Ok(Self { listener })
    }

    fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(DEFAULT_PORT)
    }

    fn serve(&self) -> ExitCode {
        for incoming in self.listener.incoming() {
            match incoming {
                Ok(stream) => {
                    if let Err(message) = self.handle_stream(stream) {
                        eprintln!("{message}");
                    }
                }
                Err(e) => {
                    eprintln!("failed to accept preview request: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        ExitCode::SUCCESS
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<(), String> {
        let request = read_request(&mut stream)?;
        response_for(&request).write_to(&mut stream)
    }
}

struct Request {
    method: String,
    target: String,
    body: String,
}

impl Request {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("/")
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("failed to configure preview socket: {e}"))?;

    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buf).map_err(read_error)?;
        if n == 0 {
            return Err("empty preview request".into());
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("preview request is too large".into());
        }
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
    };

    let header_text = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let content_len = content_length(&header_text);
    let body_start = header_end + 4;
    while bytes.len() < body_start + content_len {
        let n = stream.read(&mut buf).map_err(read_error)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("preview request is too large".into());
        }
    }

    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default();
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    let method = parts.first().copied().unwrap_or_default().to_string();
    let target = parts.get(1).copied().unwrap_or("/").to_string();
    let body_end = (body_start + content_len).min(bytes.len());
    let body = String::from_utf8_lossy(&bytes[body_start..body_end]).into_owned();
    Ok(Request {
        method,
        target,
        body,
    })
}

fn read_error(e: std::io::Error) -> String {
    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
        return "timed out reading preview request".into();
    }
    format!("failed to read preview request: {e}")
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_length(header_text: &str) -> usize {
    header_text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length:"))
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

struct Header {
    name: &'static str,
    value: String,
}

struct Response {
    status: u16,
    content_type: &'static str,
    headers: Vec<Header>,
    body: String,
}

impl Response {
    fn html(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            headers: Vec::new(),
            body,
        }
    }

    fn json(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            headers: Vec::new(),
            body,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            content_type: "text/plain; charset=utf-8",
            headers: vec![Header {
                name: "Location",
                value: location.to_string(),
            }],
            body: String::new(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: "not found".into(),
        }
    }

    fn status_text(&self) -> &'static str {
        match self.status {
            200 => "OK",
            302 => "Found",
            404 => "Not Found",
            _ => "OK",
        }
    }

    fn write_to(self, stream: &mut TcpStream) -> Result<(), String> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.status_text(),
            self.content_type,
            self.body.len()
        );
        for header in self.headers {
            response.push_str(header.name);
            response.push_str(": ");
            response.push_str(&header.value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(&self.body);
        stream
            .write_all(response.as_bytes())
            .and_then(|_| stream.flush())
            .map_err(|e| format!("failed to write preview response: {e}"))
    }
}

fn response_for(request: &Request) -> Response {
    match (request.method.as_str(), request.path()) {
        ("GET", "/") => Response::html(index_page()),
        ("GET", "/prompt/simple-token") => Response::html(simple_token_prompt()),
        ("GET", "/prompt/multi-field") => Response::html(multi_field_prompt()),
        ("GET", "/prompt/groups") => Response::html(grouped_prompt()),
        ("GET", "/prompt/oauth-pending") => Response::html(oauth_prompt(OAuthState::Pending)),
        ("GET", "/prompt/oauth-authorized") => Response::html(oauth_prompt(OAuthState::Authorized)),
        ("GET", "/prompt/oauth-error") => Response::html(oauth_prompt(OAuthState::Error)),
        ("GET", "/code/digits") => Response::html(code_page(None)),
        ("GET", "/code/error") => {
            Response::html(code_page(Some("code must contain only ASCII digits")))
        }
        ("GET", "/code/done") => Response::html(render_code_done_page()),
        ("GET", "/code/cancelled") => Response::html(render_code_cancelled_page()),
        ("GET", "/done/credential") => Response::html(render_credential_done_page()),
        ("GET", "/auth") => Response::redirect("/prompt/oauth-authorized"),
        ("GET", "/oauth-status") => Response::json(oauth_status_json()),
        ("POST", "/") => Response::html(post_submit_page(request)),
        ("POST", "/cancel") => Response::html(render_code_cancelled_page()),
        _ => Response::not_found(),
    }
}

fn oauth_status_json() -> String {
    r#"{"authorized":false,"error":false}"#.into()
}

fn post_submit_page(request: &Request) -> String {
    if request.body.contains("_code=") {
        return render_code_done_page();
    }
    render_credential_done_page()
}

fn index_page() -> String {
    let mut links = String::new();
    for fixture in FIXTURES {
        links.push_str(&format!(
            r#"<li><a href="{path}">{title}</a><p>{description}</p></li>"#,
            path = fixture.path,
            title = fixture.title,
            description = fixture.description
        ));
    }
    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sfae UI preview</title>
<style>
  :root {{
    --bg: #fafafa;
    --surface: #ffffff;
    --border: #e2e2e2;
    --text: #1a1a1a;
    --muted: #666666;
    --link: #1a73e8;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    line-height: 1.5;
    padding: 32px 16px;
  }}
  main {{
    width: min(920px, 100%);
    margin: 0 auto;
  }}
  h1 {{
    font-size: 1.35rem;
    margin: 0 0 8px;
  }}
  .intro {{
    margin: 0 0 24px;
    color: var(--muted);
  }}
  ul {{
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 12px;
  }}
  li {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
  }}
  a {{
    color: var(--link);
    font-weight: 650;
    text-decoration: none;
  }}
  a:hover {{ text-decoration: underline; }}
  p {{
    margin: 6px 0 0;
    color: var(--muted);
    font-size: 0.9rem;
  }}
</style>
</head>
<body>
<main>
  <h1>sfae UI preview</h1>
  <p class="intro">Synthetic credential collection states. This server never requests, prints, stores, or sends credentials.</p>
  <ul>{links}</ul>
</main>
</body>
</html>"#
    )
}

fn simple_token_prompt() -> String {
    let spec = PromptSpec {
        help_url: Some("https://github.com/settings/tokens".into()),
        fields: Some(vec![FieldSpec {
            name: "ACCESS_TOKEN".into(),
            label: Some("Personal access token".into()),
            default: None,
            secret: None,
            optional: None,
        }]),
        groups: None,
    };
    render_prompt(PromptFixture {
        domain: "github.com",
        label: "Credentials for github.com",
        spec,
        oauth_state: OAuthState::None,
    })
}

fn multi_field_prompt() -> String {
    let spec = PromptSpec {
        help_url: Some("https://example.com/account/api-keys".into()),
        fields: Some(vec![
            FieldSpec {
                name: "HOST".into(),
                label: Some("Server URL".into()),
                default: Some("https://api.example.com/v2".into()),
                secret: Some(false),
                optional: None,
            },
            FieldSpec {
                name: "USERNAME".into(),
                label: None,
                default: Some("preview-user@example.com".into()),
                secret: None,
                optional: None,
            },
            FieldSpec {
                name: "PASSWORD".into(),
                label: None,
                default: None,
                secret: None,
                optional: None,
            },
            FieldSpec {
                name: "ACCOUNT_ID".into(),
                label: Some("Account ID".into()),
                default: None,
                secret: Some(false),
                optional: Some(true),
            },
        ]),
        groups: None,
    };
    render_prompt(PromptFixture {
        domain: "api.example.com",
        label: "Credentials for preview-user@api.example.com",
        spec,
        oauth_state: OAuthState::None,
    })
}

fn grouped_prompt() -> String {
    let spec = PromptSpec {
        help_url: Some("https://api.example.com/developers/authentication".into()),
        fields: Some(vec![FieldSpec {
            name: "URL".into(),
            label: Some("API endpoint".into()),
            default: Some("https://api.example.com/v2".into()),
            secret: Some(false),
            optional: None,
        }]),
        groups: Some(vec![
            GroupSpec {
                label: "Basic Auth".into(),
                fields: Some(vec![
                    FieldSpec {
                        name: "USERNAME".into(),
                        label: None,
                        default: None,
                        secret: None,
                        optional: None,
                    },
                    FieldSpec {
                        name: "PASSWORD".into(),
                        label: None,
                        default: None,
                        secret: None,
                        optional: None,
                    },
                ]),
                oauth: None,
            },
            GroupSpec {
                label: "API Key".into(),
                fields: Some(vec![FieldSpec {
                    name: "API_KEY".into(),
                    label: None,
                    default: None,
                    secret: None,
                    optional: None,
                }]),
                oauth: None,
            },
        ]),
    };
    render_prompt(PromptFixture {
        domain: "api.example.com",
        label: "Credentials for api.example.com",
        spec,
        oauth_state: OAuthState::None,
    })
}

fn oauth_prompt(state: OAuthState) -> String {
    let spec = PromptSpec {
        help_url: None,
        fields: None,
        groups: Some(vec![GroupSpec {
            label: "OAuth".into(),
            fields: None,
            oauth: Some(OAuthSpec {
                provider: Some("github".into()),
                scope: Some("read:user user:email".into()),
                scopes: Vec::new(),
            }),
        }]),
    };
    render_prompt(PromptFixture {
        domain: "github.com",
        label: "Credentials for github.com",
        spec,
        oauth_state: state,
    })
}

struct PromptFixture {
    domain: &'static str,
    label: &'static str,
    spec: PromptSpec,
    oauth_state: OAuthState,
}

fn render_prompt(fixture: PromptFixture) -> String {
    let html = render_form_page(FormContext {
        domain: fixture.domain,
        label: fixture.label,
        credential_label: None,
        spec: &fixture.spec,
    });
    fixture.oauth_state.apply(html)
}

#[derive(Clone, Copy)]
enum OAuthState {
    None,
    Pending,
    Authorized,
    Error,
}

impl OAuthState {
    fn apply(self, html: String) -> String {
        match self {
            Self::None | Self::Pending => html,
            Self::Authorized => html
                .replace(
                    r#"class="oauth-btn" id="oauth-btn-0""#,
                    r#"class="oauth-btn" id="oauth-btn-0" style="display:none""#,
                )
                .replace(
                    r#"<div class="oauth-status" id="oauth-status-0" style="display:none">&#10003; Authorized</div>"#,
                    r#"<div class="oauth-status" id="oauth-status-0" style="display:flex">&#10003; Authorized</div>"#,
                ),
            Self::Error => html
                .replace(
                    r#"class="oauth-btn" id="oauth-btn-0""#,
                    r#"class="oauth-btn" id="oauth-btn-0" style="display:none""#,
                )
                .replace(
                    r#"<div class="oauth-status" id="oauth-status-0" style="display:none">&#10003; Authorized</div>"#,
                    r#"<div class="oauth-status" id="oauth-status-0" style="display:flex">Authorization failed</div>"#,
                ),
        }
    }
}

fn code_page(error: Option<&str>) -> String {
    let request = CodeRequest {
        domain: "github.com".into(),
        label: Some("Work account".into()),
        message: Some("Enter the 6-digit code shown by the service.".into()),
        help_url: Some("https://github.com/sessions/two-factor".into()),
        format: CodeFormat::Digits,
        min_length: 6,
        max_length: 6,
        timeout: Duration::from_secs(300),
    };
    render_code_page(CodePreview {
        request: &request,
        csrf_token: "preview-csrf-token",
        error,
        timeout_secs: 300,
    })
}
