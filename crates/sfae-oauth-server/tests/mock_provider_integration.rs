//! Secret-free broker integration test against a local OAuth-provider double.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

const INTERNAL_AUTH: &str = "mock-provider-test-internal";

#[tokio::test(flavor = "multi_thread")]
async fn broker_callback_completes_against_mock_oauth_provider() {
    let Some(database_url) = std::env::var("SFAE_OAUTH_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping mock provider integration test: SFAE_OAUTH_TEST_DATABASE_URL is unset");
        return;
    };

    let provider = MockProvider::start(2);
    let mut broker = BrokerProcess::start(BrokerStart {
        database_url,
        provider_base_url: provider.base_url.clone(),
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    wait_for_health(HealthProbe {
        http: &http,
        broker: &mut broker,
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
        "{}/oauth/callback?code=mock-code&state={state}",
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
        format!("{}/oauth/callback", broker.base_url)
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

#[tokio::test(flavor = "multi_thread")]
async fn google_local_handoff_refresh_and_revoke_use_generic_callback() {
    let Some(database_url) = std::env::var("SFAE_OAUTH_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping mock provider integration test: SFAE_OAUTH_TEST_DATABASE_URL is unset");
        return;
    };

    let provider = MockProvider::start(4);
    let mut broker = BrokerProcess::start(BrokerStart {
        database_url: database_url.clone(),
        provider_base_url: provider.base_url.clone(),
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    wait_for_health(HealthProbe {
        http: &http,
        broker: &mut broker,
    })
    .await;

    let redeem_verifier = "redeem-verifier-with-enough-entropy-for-test";
    let local = create_google_local_session(CreateLocalSession {
        http: &http,
        base_url: &broker.base_url,
        redeem_challenge: &redeem_challenge(redeem_verifier),
    })
    .await;
    let authorize_url = Url::parse(&local.authorization_url).unwrap();
    let authorize_pairs: HashMap<_, _> = authorize_url.query_pairs().into_owned().collect();
    assert_eq!(
        authorize_pairs["redirect_uri"],
        format!("{}/oauth/callback", broker.base_url)
    );
    assert_eq!(authorize_pairs["access_type"], "offline");
    assert_eq!(authorize_pairs["include_granted_scopes"], "true");
    assert!(authorize_pairs["scope"].contains("openid"));
    assert!(authorize_pairs["scope"].contains("email"));
    assert!(authorize_pairs["scope"].contains("profile"));
    assert!(
        authorize_pairs["scope"]
            .contains("https://www.googleapis.com/auth/drive.metadata.readonly")
    );

    let state = oauth_state_from_authorization_url(&local.authorization_url);
    let callback = format!(
        "{}/oauth/callback?code=google-code&state={state}&provider=discord",
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
    let completion_verifier = query_value(location, "completion_verifier");

    let redeemed = redeem_local_session(RedeemLocalSession {
        http: &http,
        base_url: &broker.base_url,
        session_id: &local.session_id,
        redeem_verifier,
        completion_verifier: &completion_verifier,
    })
    .await;
    assert_eq!(
        redeemed.values["OAUTH_ACCESS_TOKEN"],
        "mock-google-access-token"
    );
    assert!(!redeemed.values.contains_key("OAUTH_REFRESH_TOKEN"));
    assert_eq!(
        redeemed.internal["OAUTH_REFRESH_TOKEN"],
        "mock-google-refresh-token"
    );
    assert!(
        redeemed
            .internal
            .contains_key("OAUTH_BROKER_CREDENTIAL_SECRET")
    );
    assert_eq!(redeemed.metadata["OAUTH_PROVIDER"], "google");
    assert_eq!(
        redeemed.metadata["OAUTH_PROVIDER_SUBJECT"],
        "mock-google-sub"
    );
    assert_eq!(redeemed.metadata["OAUTH_DISPLAY_NAME"], "Mock Google User");

    let refreshed = refresh_google_local_credential(RefreshLocalCredential {
        http: &http,
        base_url: &broker.base_url,
        credential_id: &redeemed.metadata["OAUTH_BROKER_CREDENTIAL_ID"],
        credential_secret: &redeemed.internal["OAUTH_BROKER_CREDENTIAL_SECRET"],
        refresh_token: &redeemed.internal["OAUTH_REFRESH_TOKEN"],
    })
    .await;
    assert_eq!(
        refreshed.values["OAUTH_ACCESS_TOKEN"],
        "mock-google-refreshed-access-token"
    );
    assert!(!refreshed.internal.contains_key("OAUTH_REFRESH_TOKEN"));
    assert_eq!(refreshed.metadata["OAUTH_PROVIDER"], "google");
    assert!(!refreshed.metadata.contains_key("OAUTH_SCOPES"));

    revoke_google_local_credential(RevokeLocalCredential {
        http: &http,
        base_url: &broker.base_url,
        credential_id: &redeemed.metadata["OAUTH_BROKER_CREDENTIAL_ID"],
        credential_secret: &redeemed.internal["OAUTH_BROKER_CREDENTIAL_SECRET"],
        refresh_token: &redeemed.internal["OAUTH_REFRESH_TOKEN"],
    })
    .await;

    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let (grant_provider, grant_status) = sqlx::query_as::<_, (String, String)>(
        "SELECT provider, status FROM local_oauth_grants WHERE id = $1::uuid",
    )
    .bind(&redeemed.metadata["OAUTH_BROKER_CREDENTIAL_ID"])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(grant_provider, "google");
    assert_eq!(grant_status, "revoked");

    let provider_requests = provider.finish();
    assert_eq!(provider_requests.len(), 4);
    let token_body = parse_urlencoded(&provider_requests[0].body);
    assert_eq!(provider_requests[0].method, "POST");
    assert_eq!(provider_requests[0].target, "/token");
    assert_eq!(token_body["grant_type"], "authorization_code");
    assert_eq!(token_body["code"], "google-code");
    assert_eq!(
        token_body["redirect_uri"],
        format!("{}/oauth/callback", broker.base_url)
    );
    assert_eq!(token_body["client_id"], "mock-google-client-id");
    assert_eq!(token_body["client_secret"], "mock-google-client-secret");
    assert_eq!(provider_requests[1].method, "GET");
    assert_eq!(provider_requests[1].target, "/userinfo");
    assert_eq!(
        provider_requests[1].header("authorization"),
        Some("Bearer mock-google-access-token")
    );

    let refresh_body = parse_urlencoded(&provider_requests[2].body);
    assert_eq!(provider_requests[2].target, "/token");
    assert_eq!(refresh_body["grant_type"], "refresh_token");
    assert_eq!(refresh_body["refresh_token"], "mock-google-refresh-token");
    assert_eq!(refresh_body["client_id"], "mock-google-client-id");
    assert_eq!(refresh_body["client_secret"], "mock-google-client-secret");

    let revoke_body = parse_urlencoded(&provider_requests[3].body);
    assert_eq!(provider_requests[3].target, "/revoke");
    assert_eq!(revoke_body["token"], "mock-google-refresh-token");
    assert!(!revoke_body.contains_key("token_type_hint"));
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

#[derive(Deserialize)]
struct CreatedLocalSession {
    session_id: String,
    authorization_url: String,
}

#[derive(Deserialize)]
struct RedeemedCredential {
    values: HashMap<String, String>,
    internal: HashMap<String, String>,
    metadata: HashMap<String, String>,
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

struct CreateLocalSession<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    redeem_challenge: &'a str,
}

async fn create_google_local_session(args: CreateLocalSession<'_>) -> CreatedLocalSession {
    args.http
        .post(format!("{}/v1/local/oauth/sessions", args.base_url))
        .json(&json!({
            "provider": "google",
            "domain": "googleapis.com",
            "label": "mock-google",
            "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"],
            "redeem_challenge": args.redeem_challenge,
            "redeem_challenge_method": "S256",
            "return_url": format!("{}/oauth-complete", args.base_url)
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

struct RedeemLocalSession<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    session_id: &'a str,
    redeem_verifier: &'a str,
    completion_verifier: &'a str,
}

async fn redeem_local_session(args: RedeemLocalSession<'_>) -> RedeemedCredential {
    args.http
        .post(format!(
            "{}/v1/local/oauth/sessions/{}/redeem",
            args.base_url, args.session_id
        ))
        .json(&json!({
            "redeem_verifier": args.redeem_verifier,
            "completion_verifier": args.completion_verifier
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

struct RefreshLocalCredential<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    credential_id: &'a str,
    credential_secret: &'a str,
    refresh_token: &'a str,
}

async fn refresh_google_local_credential(args: RefreshLocalCredential<'_>) -> RedeemedCredential {
    args.http
        .post(format!("{}/v1/local/oauth/refresh", args.base_url))
        .json(&json!({
            "provider": "google",
            "broker_credential_id": args.credential_id,
            "broker_credential_secret": args.credential_secret,
            "refresh_token": args.refresh_token
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

struct RevokeLocalCredential<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    credential_id: &'a str,
    credential_secret: &'a str,
    refresh_token: &'a str,
}

async fn revoke_google_local_credential(args: RevokeLocalCredential<'_>) {
    let response = args
        .http
        .post(format!("{}/v1/local/oauth/revoke", args.base_url))
        .json(&json!({
            "provider": "google",
            "broker_credential_id": args.credential_id,
            "broker_credential_secret": args.credential_secret,
            "refresh_token": args.refresh_token
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
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
    broker: &'a mut BrokerProcess,
}

async fn wait_for_health(args: HealthProbe<'_>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let HealthProbe { http, broker } = args;
    loop {
        if let Some(status) = broker.child.try_wait().unwrap() {
            panic!("OAuth broker exited before becoming healthy: {status}");
        }
        let response = http.get(format!("{}/health", broker.base_url)).send().await;
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

// xtask: allow-multi-param - test helper pairs URL with query key
fn query_value(raw: &str, key: &str) -> String {
    Url::parse(raw)
        .unwrap()
        .query_pairs()
        .find_map(|pair| (pair.0 == key).then(|| pair.1.into_owned()))
        .unwrap()
}

fn redeem_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
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
            .env("GOOGLE_CLIENT_ID", "mock-google-client-id")
            .env("GOOGLE_CLIENT_SECRET", "mock-google-client-secret")
            .env("GITHUB_CLIENT_ID", "mock-github-client-id")
            .env("GITHUB_CLIENT_SECRET", "mock-github-client-secret")
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
            .env(
                "GOOGLE_AUTHORIZE_URL",
                format!("{}/authorize", args.provider_base_url),
            )
            .env(
                "GOOGLE_TOKEN_URL",
                format!("{}/token", args.provider_base_url),
            )
            .env(
                "GOOGLE_REVOKE_URL",
                format!("{}/revoke", args.provider_base_url),
            )
            .env(
                "GOOGLE_USERINFO_URL",
                format!("{}/userinfo", args.provider_base_url),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
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
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || collect_provider_requests(listener, expected_requests));
        Self { base_url, handle }
    }

    fn finish(self) -> Vec<ProviderRequest> {
        self.handle.join().unwrap()
    }
}

// xtask: allow-multi-param - test helper pairs listener with expected request count
fn collect_provider_requests(
    listener: TcpListener,
    expected_requests: usize,
) -> Vec<ProviderRequest> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut requests = Vec::new();
    while requests.len() < expected_requests && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let request = read_http_request(&mut stream);
                respond_to_provider_request(ProviderResponse {
                    stream: &mut stream,
                    target: &request.target,
                    body: &request.body,
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
    body: &'a str,
}

fn respond_to_provider_request(args: ProviderResponse<'_>) {
    match args.target {
        "/token" => {
            let body = parse_urlencoded(args.body);
            let response = if body.get("grant_type").map(String::as_str) == Some("refresh_token") {
                r#"{"access_token":"mock-google-refreshed-access-token","token_type":"Bearer","expires_in":1800}"#
            } else if body.get("client_id").map(String::as_str) == Some("mock-google-client-id") {
                r#"{"access_token":"mock-google-access-token","refresh_token":"mock-google-refresh-token","token_type":"Bearer","scope":"email profile https://www.googleapis.com/auth/drive.metadata.readonly","expires_in":3600}"#
            } else {
                r#"{"access_token":"mock-access-token","refresh_token":"mock-refresh-token","token_type":"Bearer","scope":"identify scope.read scope.write","expires_in":3600}"#
            };
            write_json_response(ResponseBody {
                stream: args.stream,
                body: response,
            });
        }
        "/userinfo" => write_json_response(ResponseBody {
            stream: args.stream,
            body: r#"{"id":"mock-user-123","username":"mockuser","global_name":"Mock User","sub":"mock-google-sub","name":"Mock Google User","email":"mock@example.test"}"#,
        }),
        "/revoke" => write_json_response(ResponseBody {
            stream: args.stream,
            body: r#"{}"#,
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
