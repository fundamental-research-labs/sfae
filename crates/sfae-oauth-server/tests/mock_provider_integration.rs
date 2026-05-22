//! Secret-free broker integration test against a local OAuth-provider double.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use url::Url;

const INTERNAL_AUTH: &str = "mock-provider-test-internal";

#[tokio::test(flavor = "multi_thread")]
async fn broker_callback_completes_against_mock_oauth_provider() {
    let Some(database_url) = std::env::var("SFAE_OAUTH_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping mock provider integration test: SFAE_OAUTH_TEST_DATABASE_URL is unset");
        return;
    };

    let provider = MockProvider::start();
    let broker = BrokerProcess::start(BrokerStart {
        database_url,
        provider_base_url: provider.base_url.clone(),
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    wait_for_health(HealthProbe {
        http: &http,
        base_url: &broker.base_url,
    })
    .await;

    let session = create_session(CreateSession {
        http: &http,
        base_url: &broker.base_url,
    })
    .await;
    assert!(
        session
            .authorization_url
            .starts_with(&format!("{}/authorize?", provider.base_url))
    );

    let state = oauth_state_from_authorization_url(&session.authorization_url);
    let callback = format!(
        "{}/v1/callback/discord?code=mock-code&state={state}",
        broker.base_url
    );
    let callback_resp = http.get(callback).send().await.unwrap();
    assert_eq!(callback_resp.status(), StatusCode::SEE_OTHER);
    let location = callback_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("status=success"));
    assert!(location.contains(&format!("session_id={}", session.session_id)));

    let status = session_status(SessionStatus {
        http: &http,
        base_url: &broker.base_url,
        session_id: &session.session_id,
    })
    .await;
    assert_eq!(status.status, "success");
    assert_eq!(status.provider_subject.as_deref(), Some("mock-user-123"));
    assert!(status.credential_id.is_some());

    let provider_requests = provider.finish();
    assert_eq!(provider_requests.len(), 2);
    let token_body = parse_urlencoded(&provider_requests[0].body);
    assert_eq!(provider_requests[0].method, "POST");
    assert_eq!(provider_requests[0].target, "/token");
    assert_eq!(token_body["grant_type"], "authorization_code");
    assert_eq!(token_body["code"], "mock-code");
    assert_eq!(
        token_body["redirect_uri"],
        format!("{}/v1/callback/discord", broker.base_url)
    );
    assert_eq!(token_body["client_id"], "mock-client-id");
    assert_eq!(token_body["client_secret"], "mock-client-secret");
    assert_eq!(provider_requests[1].method, "GET");
    assert_eq!(provider_requests[1].target, "/userinfo");
    assert_eq!(
        provider_requests[1].header("authorization"),
        Some("Bearer mock-access-token")
    );
}

#[derive(Deserialize)]
struct CreatedSession {
    session_id: String,
    authorization_url: String,
}

#[derive(Deserialize)]
struct SessionState {
    status: String,
    provider_subject: Option<String>,
    credential_id: Option<String>,
}

struct CreateSession<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
}

async fn create_session(args: CreateSession<'_>) -> CreatedSession {
    args.http
        .post(format!("{}/internal/oauth/sessions", args.base_url))
        .header("x-internal-auth", INTERNAL_AUTH)
        .json(&json!({
            "provider": "discord",
            "user_id": "mock-provider-integration",
            "domain": "discord.com",
            "label": "mock-provider",
            "scopes": ["scope.read", "scope.write"]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

struct SessionStatus<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    session_id: &'a str,
}

async fn session_status(args: SessionStatus<'_>) -> SessionState {
    args.http
        .get(format!(
            "{}/internal/oauth/sessions/{}",
            args.base_url, args.session_id
        ))
        .header("x-internal-auth", INTERNAL_AUTH)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

struct HealthProbe<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
}

async fn wait_for_health(args: HealthProbe<'_>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let response = args
            .http
            .get(format!("{}/health", args.base_url))
            .send()
            .await;
        if response.is_ok_and(|response| response.status().is_success()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "OAuth broker did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn oauth_state_from_authorization_url(raw: &str) -> String {
    Url::parse(raw)
        .unwrap()
        .query_pairs()
        .find_map(|pair| (pair.0 == "state").then(|| pair.1.into_owned()))
        .unwrap()
}

struct BrokerStart {
    database_url: String,
    provider_base_url: String,
}

struct BrokerProcess {
    base_url: String,
    child: Child,
}

impl BrokerProcess {
    fn start(args: BrokerStart) -> Self {
        let port = unused_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let key = STANDARD.encode([8u8; 32]);
        let child = Command::new(env!("CARGO_BIN_EXE_sfae-oauth-server"))
            .env("DATABASE_URL", args.database_url)
            .env("SFAE_INTERNAL_AUTH_SECRET", INTERNAL_AUTH)
            .env("SFAE_OAUTH_TOKEN_ENCRYPTION_KEY", key)
            .env("DISCORD_CLIENT_ID", "mock-client-id")
            .env("DISCORD_CLIENT_SECRET", "mock-client-secret")
            .env("BASE_URL", &base_url)
            .env("SFAE_SERVER_PORT", port.to_string())
            .env("SFAE_OAUTH_ALLOW_TEST_PROVIDER_URLS", "1")
            .env(
                "DISCORD_AUTHORIZE_URL",
                format!("{}/authorize", args.provider_base_url),
            )
            .env(
                "DISCORD_TOKEN_URL",
                format!("{}/token", args.provider_base_url),
            )
            .env(
                "DISCORD_TOKEN_REVOKE_URL",
                format!("{}/revoke", args.provider_base_url),
            )
            .env(
                "DISCORD_USERINFO_URL",
                format!("{}/userinfo", args.provider_base_url),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self { base_url, child }
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct MockProvider {
    base_url: String,
    handle: thread::JoinHandle<Vec<ProviderRequest>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || collect_provider_requests(listener));
        Self { base_url, handle }
    }

    fn finish(self) -> Vec<ProviderRequest> {
        self.handle.join().unwrap()
    }
}

fn collect_provider_requests(listener: TcpListener) -> Vec<ProviderRequest> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut requests = Vec::new();
    while requests.len() < 2 && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let request = read_http_request(&mut stream);
                respond_to_provider_request(ProviderResponse {
                    stream: &mut stream,
                    target: &request.target,
                });
                requests.push(request);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("mock provider accept failed: {e}"),
        }
    }
    requests
}

struct ProviderRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: String,
}

impl ProviderRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

fn read_http_request(stream: &mut TcpStream) -> ProviderRequest {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf).unwrap();
        assert!(read > 0, "mock provider connection closed before headers");
        raw.extend_from_slice(&buf[..read]);
        if let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let content_length = content_length_from_headers(&header_text);
    while raw.len() < header_end + content_length {
        let read = stream.read(&mut buf).unwrap();
        assert!(read > 0, "mock provider connection closed before body");
        raw.extend_from_slice(&buf[..read]);
    }

    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let target = request_parts.next().unwrap_or_default().to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let body = String::from_utf8_lossy(&raw[header_end..header_end + content_length]).to_string();

    ProviderRequest {
        method,
        target,
        headers,
        body,
    }
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0)
}

struct ProviderResponse<'a> {
    stream: &'a mut TcpStream,
    target: &'a str,
}

fn respond_to_provider_request(args: ProviderResponse<'_>) {
    match args.target {
        "/token" => write_json_response(ResponseBody {
            stream: args.stream,
            body: r#"{"access_token":"mock-access-token","refresh_token":"mock-refresh-token","token_type":"Bearer","scope":"identify scope.read scope.write","expires_in":3600}"#,
        }),
        "/userinfo" => write_json_response(ResponseBody {
            stream: args.stream,
            body: r#"{"id":"mock-user-123","username":"mockuser","global_name":"Mock User","email":"mock@example.test"}"#,
        }),
        _ => write_not_found(args.stream),
    }
}

struct ResponseBody<'a> {
    stream: &'a mut TcpStream,
    body: &'a str,
}

fn write_json_response(args: ResponseBody<'_>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        args.body.len(),
        args.body
    );
    args.stream.write_all(response.as_bytes()).unwrap();
    args.stream.flush().unwrap();
}

fn write_not_found(stream: &mut TcpStream) {
    let body = "not found";
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).unwrap();
}

fn parse_urlencoded(raw: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect()
}
