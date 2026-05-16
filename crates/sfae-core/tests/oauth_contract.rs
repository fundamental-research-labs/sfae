//! Contract tests for hosted OAuth broker adapters and local credential materialization.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use sfae_core::oauth::{
    BackendProxyConfig, BackendProxyHostedOAuthBroker, DirectHostedOAuthBroker, HostedOAuthBroker,
    HostedOAuthCredential, HostedOAuthRefresh, HostedOAuthRevoke, HostedOAuthStart,
    HostedOAuthStatus, OAuthCredentialManager, StartedHostedOAuthSession,
};
use sfae_core::proxy::CredentialLookup;
use sfae_core::store::{InMemoryStore, SecretStore, StructuredCredentialSetInput};

struct MockResponse {
    status: u16,
    body: String,
    content_type: &'static str,
}

struct CapturedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct MockHttpServer {
    base_url: String,
    requests: mpsc::Receiver<CapturedRequest>,
    handle: thread::JoinHandle<()>,
}

impl MockHttpServer {
    fn start(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                tx.send(request).unwrap();
                write_response(ResponseWrite {
                    stream: &mut stream,
                    response,
                });
            }
        });
        Self {
            base_url,
            requests: rx,
            handle,
        }
    }

    fn finish(self) -> Vec<CapturedRequest> {
        self.handle.join().unwrap();
        self.requests.try_iter().collect()
    }
}

struct ResponseWrite<'a> {
    stream: &'a mut TcpStream,
    response: MockResponse,
}

fn write_response(args: ResponseWrite<'_>) {
    let ResponseWrite { stream, response } = args;
    let status = response.status;
    let body = response.body;
    let headers = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        response.content_type,
        body.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed before headers");
        raw.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_header_end(&raw) {
            break pos;
        }
    };
    let headers_raw = String::from_utf8(raw[..header_end].to_vec()).unwrap();
    let mut lines = headers_raw.split("\r\n");
    let request_line = lines.next().unwrap();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap().to_string();
    let target = request_parts.next().unwrap().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let content_length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while raw.len() < body_start + content_length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed before body");
        raw.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8(raw[body_start..body_start + content_length].to_vec()).unwrap();

    CapturedRequest {
        method,
        target,
        headers,
        body,
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn json_response(body: serde_json::Value) -> MockResponse {
    MockResponse {
        status: 200,
        body: body.to_string(),
        content_type: "application/json",
    }
}

fn no_content_response() -> MockResponse {
    MockResponse {
        status: 204,
        body: String::new(),
        content_type: "text/plain",
    }
}

fn sensitive_error_response() -> MockResponse {
    MockResponse {
        status: 500,
        body: r#"{"access_token":"access-secret","refresh_token":"refresh-secret","code":"provider-code"}"#.to_string(),
        content_type: "application/json",
    }
}

fn session_start_response() -> MockResponse {
    json_response(serde_json::json!({
        "session_id": "session-1",
        "authorization_url": "https://discord.com/oauth2/authorize?state=broker-state",
        "expires_at": "2026-01-01T00:00:00Z"
    }))
}

fn provider_registry_response() -> MockResponse {
    json_response(serde_json::json!({
        "providers": [{"provider": "discord", "domains": ["discord.com"]}]
    }))
}

fn session_status_response() -> MockResponse {
    json_response(serde_json::json!({
        "session_id": "session-1",
        "provider": "discord",
        "domain": "discord.com",
        "label": "primary",
        "scopes": ["identify"],
        "status": "success",
        "provider_subject": "discord-user",
        "credential_id": null,
        "expires_at": "2026-01-01T00:00:00Z"
    }))
}

fn credential_response() -> MockResponse {
    json_response(serde_json::json!({
        "values": {"OAUTH_ACCESS_TOKEN": "access-token"},
        "internal": {
            "OAUTH_REFRESH_TOKEN": "refresh-token",
            "OAUTH_BROKER_CREDENTIAL_SECRET": "broker-secret"
        },
        "metadata": {
            "OAUTH_PROVIDER": "discord",
            "OAUTH_BROKER_URL": "https://oauth.sfae.io",
            "OAUTH_BROKER_CREDENTIAL_ID": "grant-id"
        }
    }))
}

fn refreshed_credential_response() -> MockResponse {
    json_response(serde_json::json!({
        "values": {"OAUTH_ACCESS_TOKEN": "new-access-token"},
        "internal": {"OAUTH_REFRESH_TOKEN": "new-refresh-token"},
        "metadata": {
            "OAUTH_PROVIDER": "discord",
            "OAUTH_EXPIRES_AT": "2026-01-01T00:00:00Z"
        }
    }))
}

fn assert_start_status_contract(broker: &dyn HostedOAuthBroker) {
    let session = broker
        .start_session(HostedOAuthStart {
            provider: "discord",
            domain: "discord.com",
            label: Some("primary"),
            scopes: vec!["identify".to_string()],
            return_url: Some("http://127.0.0.1:49152/oauth-complete"),
        })
        .unwrap();
    assert_eq!(session.session_id, "session-1");
    assert!(
        session
            .authorization_url
            .contains("discord.com/oauth2/authorize")
    );

    let status = broker.session_status(&session.session_id).unwrap();
    assert!(status.is_success());
    assert_eq!(status.provider, "discord");
    assert_eq!(status.domain, "discord.com");
    assert_eq!(status.provider_subject.as_deref(), Some("discord-user"));
}

struct InProcessBroker {
    calls: RefCell<Vec<String>>,
}

impl InProcessBroker {
    fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl HostedOAuthBroker for InProcessBroker {
    fn start_session(
        &self,
        input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, sfae_core::SfaeError> {
        self.calls
            .borrow_mut()
            .push(format!("start:{}:{}", input.provider, input.domain));
        Ok(StartedHostedOAuthSession {
            session_id: "session-1".to_string(),
            authorization_url: "https://discord.com/oauth2/authorize".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            redeem_verifier: Some("redeem-verifier".to_string()),
        })
    }

    fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, sfae_core::SfaeError> {
        self.calls.borrow_mut().push(format!("status:{session_id}"));
        Ok(HostedOAuthStatus {
            session_id: session_id.to_string(),
            provider: "discord".to_string(),
            domain: "discord.com".to_string(),
            label: Some("primary".to_string()),
            scopes: vec!["identify".to_string()],
            status: "success".to_string(),
            error_code: None,
            provider_subject: Some("discord-user".to_string()),
            credential_id: None,
            expires_at: "2026-01-01T00:00:00Z".to_string(),
        })
    }

    // xtask: allow-multi-param - trait implementation mirrors verifier handoff contract
    fn redeem_session(
        &self,
        session_id: &str,
        redeem_verifier: &str,
        completion_verifier: &str,
    ) -> Result<HostedOAuthCredential, sfae_core::SfaeError> {
        self.calls.borrow_mut().push(format!(
            "redeem:{session_id}:{redeem_verifier}:{completion_verifier}"
        ));
        Ok(test_credential())
    }

    fn refresh_credential(
        &self,
        input: HostedOAuthRefresh<'_>,
    ) -> Result<HostedOAuthCredential, sfae_core::SfaeError> {
        self.calls.borrow_mut().push(format!(
            "refresh:{}:{}",
            input.broker_credential_id, input.refresh_token
        ));
        Ok(test_credential())
    }

    fn revoke_credential(&self, input: HostedOAuthRevoke<'_>) -> Result<(), sfae_core::SfaeError> {
        self.calls.borrow_mut().push(format!(
            "revoke:{}:{}",
            input.broker_credential_id,
            input.refresh_token.unwrap_or("-")
        ));
        Ok(())
    }
}

fn test_credential() -> HostedOAuthCredential {
    let mut values = HashMap::new();
    values.insert("OAUTH_ACCESS_TOKEN".to_string(), "access-token".to_string());
    let mut internal = HashMap::new();
    internal.insert(
        "OAUTH_REFRESH_TOKEN".to_string(),
        "refresh-token".to_string(),
    );
    internal.insert(
        "OAUTH_BROKER_CREDENTIAL_SECRET".to_string(),
        "broker-secret".to_string(),
    );
    let mut metadata = HashMap::new();
    metadata.insert("OAUTH_PROVIDER".to_string(), "discord".to_string());
    metadata.insert(
        "OAUTH_BROKER_URL".to_string(),
        "https://oauth.sfae.io".to_string(),
    );
    metadata.insert(
        "OAUTH_BROKER_CREDENTIAL_ID".to_string(),
        "grant-id".to_string(),
    );
    HostedOAuthCredential {
        values,
        internal,
        metadata,
    }
}

#[test]
fn direct_broker_fetches_provider_registry_from_broker() {
    let server = MockHttpServer::start(vec![provider_registry_response()]);
    let broker = DirectHostedOAuthBroker::new(&server.base_url).unwrap();

    let registry = broker.provider_registry().unwrap();
    let requests = server.finish();

    assert_eq!(registry.providers[0].provider, "discord");
    assert_eq!(
        registry.providers[0].domains,
        vec!["discord.com".to_string()]
    );
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].target, "/v1/oauth/providers");
}

#[test]
fn direct_broker_uses_local_handoff_contract_without_sending_verifier() {
    let server = MockHttpServer::start(vec![session_start_response(), session_status_response()]);
    let broker = DirectHostedOAuthBroker::new(&server.base_url).unwrap();

    assert_start_status_contract(&broker);
    let requests = server.finish();

    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/v1/local/oauth/sessions");
    assert!(requests[0].body.contains(r#""provider":"discord""#));
    assert!(
        requests[0]
            .body
            .contains(r#""return_url":"http://127.0.0.1:49152/oauth-complete""#)
    );
    assert!(requests[0].body.contains(r#""redeem_challenge""#));
    assert!(!requests[0].body.contains("redeem_verifier"));
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].target, "/v1/local/oauth/sessions/session-1");
}

#[test]
fn backend_proxy_fetches_provider_registry_from_backend() {
    let server = MockHttpServer::start(vec![provider_registry_response()]);
    let broker = BackendProxyHostedOAuthBroker::new(BackendProxyConfig {
        base_url: &server.base_url,
        token: "store-token",
    })
    .unwrap();

    let registry = broker.provider_registry().unwrap();
    let requests = server.finish();

    assert_eq!(registry.providers[0].provider, "discord");
    assert_eq!(
        registry.providers[0].domains,
        vec!["discord.com".to_string()]
    );
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].target, "/oauth/providers");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer store-token")
    );
}

#[test]
fn backend_proxy_contract_uses_backend_routes_and_bearer_auth() {
    let server = MockHttpServer::start(vec![session_start_response(), session_status_response()]);
    let broker = BackendProxyHostedOAuthBroker::new(BackendProxyConfig {
        base_url: &server.base_url,
        token: "store-token",
    })
    .unwrap();

    assert_start_status_contract(&broker);
    let requests = server.finish();

    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/oauth/sessions");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer store-token")
    );
    assert!(requests[0].body.contains(r#""provider":"discord""#));
    assert!(!requests[0].body.contains("return_url"));
    assert!(!requests[0].body.contains("redeem_challenge"));
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].target, "/oauth/sessions/session-1");
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer store-token")
    );
}

#[test]
fn in_process_broker_contract_covers_full_token_lifecycle() {
    let broker = InProcessBroker::new();
    let manager = OAuthCredentialManager::new(&broker);

    assert_start_status_contract(&broker);
    let credential = manager
        .redeem_session("session-1", Some("redeem-verifier"), Some("completion"))
        .unwrap()
        .unwrap();
    assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "access-token");
    manager
        .refresh_credential(HostedOAuthRefresh {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "broker-secret",
            refresh_token: "refresh-token",
        })
        .unwrap();
    manager
        .revoke_credential(HostedOAuthRevoke {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "broker-secret",
            access_token: Some("access-token"),
            refresh_token: Some("refresh-token"),
        })
        .unwrap();

    assert_eq!(
        broker.calls.borrow().as_slice(),
        [
            "start:discord:discord.com",
            "status:session-1",
            "redeem:session-1:redeem-verifier:completion",
            "refresh:grant-id:refresh-token",
            "revoke:grant-id:refresh-token"
        ]
    );
}

#[test]
fn direct_broker_redeem_refresh_and_revoke_requests_are_compartmentalized() {
    let server = MockHttpServer::start(vec![
        credential_response(),
        refreshed_credential_response(),
        no_content_response(),
    ]);
    let broker = DirectHostedOAuthBroker::new(&server.base_url).unwrap();
    let manager = OAuthCredentialManager::new(&broker);

    let credential = manager
        .redeem_session("session-1", Some("redeem-verifier"), Some("completion"))
        .unwrap()
        .unwrap();
    assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "access-token");
    assert_eq!(credential.internal["OAUTH_REFRESH_TOKEN"], "refresh-token");
    let refreshed = manager
        .refresh_credential(HostedOAuthRefresh {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "broker-secret",
            refresh_token: "refresh-token",
        })
        .unwrap();
    assert_eq!(refreshed.values["OAUTH_ACCESS_TOKEN"], "new-access-token");
    manager
        .revoke_credential(HostedOAuthRevoke {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "broker-secret",
            access_token: Some("access-token"),
            refresh_token: Some("refresh-token"),
        })
        .unwrap();
    let requests = server.finish();

    assert_eq!(
        requests[0].target,
        "/v1/local/oauth/sessions/session-1/redeem"
    );
    assert!(requests[0].body.contains("redeem-verifier"));
    assert!(requests[0].body.contains("completion"));
    assert_eq!(requests[1].target, "/v1/local/oauth/refresh");
    assert!(requests[1].body.contains("refresh-token"));
    assert_eq!(requests[2].target, "/v1/local/oauth/revoke");
    assert!(requests[2].body.contains("refresh-token"));
    assert!(!requests[2].body.contains("access-token"));
}

#[test]
fn local_redeemed_credential_materializes_and_resolves_only_injectable_values() {
    let mut store = InMemoryStore::new();
    let credential = test_credential();
    let id = store
        .store_structured_credential_set(StructuredCredentialSetInput {
            domain: "discord.com",
            label: Some("primary"),
            values: &credential.values,
            internal: Some(&credential.internal),
            metadata: Some(&credential.metadata),
        })
        .unwrap();
    let sets = store.list_credential_sets(Some("discord.com")).unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].id, id);
    assert_eq!(sets[0].keys, vec!["OAUTH_ACCESS_TOKEN"]);

    let lookup = CredentialLookup {
        store: &store,
        domain: "discord.com",
        username: Some("primary"),
        cred_id: None,
    };
    assert_eq!(
        lookup
            .resolve("https://discord.com/api/v10/users/@me?token={OAUTH_ACCESS_TOKEN}")
            .unwrap(),
        "https://discord.com/api/v10/users/@me?token=access-token"
    );
    assert_eq!(
        lookup
            .resolve("Authorization: Bearer {OAUTH_ACCESS_TOKEN}")
            .unwrap(),
        "Authorization: Bearer access-token"
    );
    assert_eq!(
        lookup
            .resolve(r#"{"token":"{OAUTH_ACCESS_TOKEN}"}"#)
            .unwrap(),
        r#"{"token":"access-token"}"#
    );
    assert!(lookup.resolve("{OAUTH_REFRESH_TOKEN}").is_err());
    assert!(lookup.resolve("{OAUTH_BROKER_CREDENTIAL_SECRET}").is_err());
    assert!(lookup.resolve("{OAUTH_PROVIDER}").is_err());
}

#[test]
fn broker_error_messages_do_not_include_sensitive_response_bodies() {
    let server = MockHttpServer::start(vec![sensitive_error_response()]);
    let broker = DirectHostedOAuthBroker::new(&server.base_url).unwrap();

    let err = broker.session_status("session-1").unwrap_err().to_string();
    let _ = server.finish();

    assert!(err.contains("OAuth broker returned 500"));
    assert!(!err.contains("access-secret"));
    assert!(!err.contains("refresh-secret"));
    assert!(!err.contains("provider-code"));
    assert!(!err.contains("access_token"));
    assert!(!err.contains("refresh_token"));
}
