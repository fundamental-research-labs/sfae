//! Hosted OAuth broker boundaries and client adapters.
//!
//! SFAE clients do not implement provider OAuth locally. They ask a hosted
//! broker to create and poll browser sessions. Local CLI mode redeems completed
//! token material once and stores it in the OS credential store; backend mode
//! keeps the existing SFAE-server proxy path.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SfaeError;

const DEFAULT_OAUTH_BROKER_URL: &str = "https://oauth.sfae.io";

/// Typed hosted OAuth broker capability used by browser and CLI code.
pub trait HostedOAuthBroker {
    /// Start a hosted OAuth browser session.
    fn start_session(
        &self,
        input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, SfaeError>;

    /// Poll sanitized session status. This must never return token material.
    fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError>;

    /// Redeem token material once for trusted local storage.
    // xtask: allow-multi-param - trait method pairs session id with verifier
    fn redeem_session(
        &self,
        _session_id: &str,
        _redeem_verifier: &str,
        _completion_verifier: &str,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        Err(SfaeError::Other(
            "this OAuth broker adapter does not support local redemption".into(),
        ))
    }

    /// Refresh a locally stored OAuth credential through the hosted broker.
    fn refresh_credential(
        &self,
        _input: HostedOAuthRefresh<'_>,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        Err(SfaeError::Other(
            "this OAuth broker adapter does not support local refresh".into(),
        ))
    }

    /// Revoke locally stored OAuth token material through the hosted broker.
    fn revoke_credential(&self, _input: HostedOAuthRevoke<'_>) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "this OAuth broker adapter does not support local revoke".into(),
        ))
    }
}

/// High-level OAuth credential orchestration over a broker implementation.
pub struct OAuthCredentialManager<'a> {
    broker: &'a dyn HostedOAuthBroker,
}

impl<'a> OAuthCredentialManager<'a> {
    pub fn new(broker: &'a dyn HostedOAuthBroker) -> Self {
        Self { broker }
    }

    pub fn start_session(
        &self,
        input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, SfaeError> {
        self.broker.start_session(input)
    }

    pub fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
        self.broker.session_status(session_id)
    }

    // xtask: allow-multi-param - manager forwards session id plus optional verifier
    pub fn redeem_session(
        &self,
        session_id: &str,
        redeem_verifier: Option<&str>,
        completion_verifier: Option<&str>,
    ) -> Result<Option<HostedOAuthCredential>, SfaeError> {
        let (Some(redeem_verifier), Some(completion_verifier)) =
            (redeem_verifier, completion_verifier)
        else {
            return Ok(None);
        };
        self.broker
            .redeem_session(session_id, redeem_verifier, completion_verifier)
            .map(Some)
    }

    pub fn refresh_credential(
        &self,
        input: HostedOAuthRefresh<'_>,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        self.broker.refresh_credential(input)
    }

    pub fn revoke_credential(&self, input: HostedOAuthRevoke<'_>) -> Result<(), SfaeError> {
        self.broker.revoke_credential(input)
    }
}

/// Inputs for starting a hosted OAuth session.
pub struct HostedOAuthStart<'a> {
    pub provider: &'a str,
    pub domain: &'a str,
    pub label: Option<&'a str>,
    pub scopes: Vec<String>,
    pub return_url: Option<&'a str>,
}

/// Inputs for broker-mediated local OAuth refresh.
pub struct HostedOAuthRefresh<'a> {
    pub provider: &'a str,
    pub broker_credential_id: &'a str,
    pub broker_credential_secret: &'a str,
    pub refresh_token: &'a str,
}

/// Inputs for broker-mediated local OAuth revoke.
pub struct HostedOAuthRevoke<'a> {
    pub provider: &'a str,
    pub broker_credential_id: &'a str,
    pub broker_credential_secret: &'a str,
    pub access_token: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
}

/// Sanitized session-start response returned to browser/UI code.
#[derive(Debug, Clone)]
pub struct StartedHostedOAuthSession {
    pub session_id: String,
    pub authorization_url: String,
    pub expires_at: String,
    pub redeem_verifier: Option<String>,
}

/// Backward-compatible request body for starting a hosted OAuth session.
#[derive(Serialize)]
pub struct HostedOAuthSessionInput<'a> {
    pub provider: &'a str,
    pub domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Backward-compatible session-start response type.
pub type HostedOAuthSession = StartedHostedOAuthSession;

/// Sanitized hosted OAuth session status returned to browser/UI code.
#[derive(Debug, Clone, Deserialize)]
pub struct HostedOAuthStatus {
    pub session_id: String,
    pub provider: String,
    pub domain: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub status: String,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub provider_subject: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    pub expires_at: String,
}

impl HostedOAuthStatus {
    pub fn is_success(&self) -> bool {
        self.status == "success"
    }

    pub fn is_error(&self) -> bool {
        self.status == "error"
    }
}

/// Broker-redeemed OAuth material split by credential compartment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostedOAuthCredential {
    #[serde(default)]
    pub values: HashMap<String, String>,
    #[serde(default)]
    pub internal: HashMap<String, String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Direct client for `oauth.sfae.io` local-CLI handoff endpoints.
pub struct DirectHostedOAuthBroker {
    base_url: String,
    agent: ureq::Agent,
}

impl DirectHostedOAuthBroker {
    /// Create a direct broker client from `SFAE_OAUTH_BROKER_URL`, defaulting to production.
    pub fn from_env() -> Result<Self, SfaeError> {
        let base_url = std::env::var("SFAE_OAUTH_BROKER_URL")
            .unwrap_or_else(|_| DEFAULT_OAUTH_BROKER_URL.to_string());
        Self::new(&base_url)
    }

    pub fn new(base_url: &str) -> Result<Self, SfaeError> {
        if base_url.trim().is_empty() {
            return Err(SfaeError::ConfigError(
                "SFAE_OAUTH_BROKER_URL cannot be empty".into(),
            ));
        }
        validate_broker_url(base_url)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent: crate::http::make_agent(),
        })
    }

    fn send(&self, req: ureq::http::Request<impl ureq::AsSendBody>) -> Result<String, SfaeError> {
        send_request(SendRequest {
            agent: &self.agent,
            request: req,
            target: &self.base_url,
            service: "OAuth broker",
        })
    }
}

impl HostedOAuthBroker for DirectHostedOAuthBroker {
    fn start_session(
        &self,
        input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, SfaeError> {
        let verifier = generate_redeem_verifier();
        let challenge = redeem_challenge(&verifier);
        let url = format!("{}/v1/local/oauth/sessions", self.base_url);
        let body = serde_json::to_string(&LocalSessionReq {
            provider: input.provider,
            domain: input.domain,
            label: input.label,
            scopes: input.scopes,
            redeem_challenge: &challenge,
            redeem_challenge_method: "S256",
            return_url: input.return_url,
        })
        .map_err(|e| SfaeError::StoreError(format!("failed to serialize OAuth request: {e}")))?;
        let req = json_request("POST", &url, body)?;
        let body = self.send(req)?;
        let parsed: LocalSessionResp = serde_json::from_str(&body)
            .map_err(|e| SfaeError::StoreError(format!("failed to parse OAuth response: {e}")))?;
        Ok(StartedHostedOAuthSession {
            session_id: parsed.session_id,
            authorization_url: parsed.authorization_url,
            expires_at: parsed.expires_at,
            redeem_verifier: Some(verifier),
        })
    }

    fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
        let url = format!("{}/v1/local/oauth/sessions/{session_id}", self.base_url);
        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .body(())
            .map_err(|e| {
                SfaeError::StoreError(format!("failed to build OAuth status request: {e}"))
            })?;
        let body = self.send(req)?;
        serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth status response: {e}"))
        })
    }

    // xtask: allow-multi-param - broker endpoint requires session id and verifier
    fn redeem_session(
        &self,
        session_id: &str,
        redeem_verifier: &str,
        completion_verifier: &str,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        let url = format!(
            "{}/v1/local/oauth/sessions/{session_id}/redeem",
            self.base_url
        );
        let body = serde_json::to_string(&RedeemReq {
            redeem_verifier,
            completion_verifier,
        })
        .map_err(|e| SfaeError::StoreError(format!("failed to serialize redeem request: {e}")))?;
        let req = json_request("POST", &url, body)?;
        let body = self.send(req)?;
        serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth credential response: {e}"))
        })
    }

    fn refresh_credential(
        &self,
        input: HostedOAuthRefresh<'_>,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        let url = format!("{}/v1/local/oauth/refresh", self.base_url);
        let body = serde_json::to_string(&RefreshReq {
            provider: input.provider,
            broker_credential_id: input.broker_credential_id,
            broker_credential_secret: input.broker_credential_secret,
            refresh_token: input.refresh_token,
        })
        .map_err(|e| SfaeError::StoreError(format!("failed to serialize refresh request: {e}")))?;
        let req = json_request("POST", &url, body)?;
        let body = self.send(req)?;
        serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth refresh response: {e}"))
        })
    }

    fn revoke_credential(&self, input: HostedOAuthRevoke<'_>) -> Result<(), SfaeError> {
        let url = format!("{}/v1/local/oauth/revoke", self.base_url);
        let (access_token, refresh_token) = match input.refresh_token {
            Some(refresh_token) => (None, Some(refresh_token)),
            None => (input.access_token, None),
        };
        let body = serde_json::to_string(&RevokeReq {
            provider: input.provider,
            broker_credential_id: input.broker_credential_id,
            broker_credential_secret: input.broker_credential_secret,
            access_token,
            refresh_token,
        })
        .map_err(|e| SfaeError::StoreError(format!("failed to serialize revoke request: {e}")))?;
        let req = json_request("POST", &url, body)?;
        self.send(req)?;
        Ok(())
    }
}

/// Client for SFAE backend endpoints that proxy hosted OAuth broker sessions.
pub struct BackendProxyHostedOAuthBroker {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

/// Backward-compatible name for the backend-proxy OAuth client.
pub type HostedOAuthClient = BackendProxyHostedOAuthBroker;

impl BackendProxyHostedOAuthBroker {
    /// Create a backend-proxy client from `SFAE_STORE_URL` and `SFAE_STORE_TOKEN`.
    pub fn from_env() -> Result<Self, SfaeError> {
        let base_url = std::env::var("SFAE_STORE_URL").map_err(|_| {
            SfaeError::ConfigError("hosted OAuth backend proxy requires SFAE_STORE_URL".into())
        })?;
        let token = std::env::var("SFAE_STORE_TOKEN").map_err(|_| {
            SfaeError::ConfigError("hosted OAuth backend proxy requires SFAE_STORE_TOKEN".into())
        })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            agent: crate::http::make_agent(),
        })
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn send(&self, req: ureq::http::Request<impl ureq::AsSendBody>) -> Result<String, SfaeError> {
        send_request(SendRequest {
            agent: &self.agent,
            request: req,
            target: &self.base_url,
            service: "SFAE backend",
        })
    }

    /// Ask the SFAE backend to start a hosted OAuth browser session.
    pub fn create_session(
        &self,
        input: HostedOAuthSessionInput<'_>,
    ) -> Result<HostedOAuthSession, SfaeError> {
        HostedOAuthBroker::start_session(
            self,
            HostedOAuthStart {
                provider: input.provider,
                domain: input.domain,
                label: input.label,
                scopes: input.scopes,
                return_url: None,
            },
        )
    }

    /// Poll hosted OAuth session status through the SFAE backend.
    pub fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
        HostedOAuthBroker::session_status(self, session_id)
    }
}

impl HostedOAuthBroker for BackendProxyHostedOAuthBroker {
    fn start_session(
        &self,
        input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, SfaeError> {
        let url = format!("{}/oauth/sessions", self.base_url);
        let body = serde_json::to_string(&BackendSessionReq {
            provider: input.provider,
            domain: input.domain,
            label: input.label,
            scopes: input.scopes,
        })
        .map_err(|e| SfaeError::StoreError(format!("failed to serialize OAuth request: {e}")))?;
        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| SfaeError::StoreError(format!("failed to build OAuth request: {e}")))?;
        let body = self.send(req)?;
        let parsed: BackendSessionResp = serde_json::from_str(&body)
            .map_err(|e| SfaeError::StoreError(format!("failed to parse OAuth response: {e}")))?;
        Ok(StartedHostedOAuthSession {
            session_id: parsed.session_id,
            authorization_url: parsed.authorization_url,
            expires_at: parsed.expires_at,
            redeem_verifier: None,
        })
    }

    fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
        let url = format!("{}/oauth/sessions/{session_id}", self.base_url);
        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .body(())
            .map_err(|e| {
                SfaeError::StoreError(format!("failed to build OAuth status request: {e}"))
            })?;
        let body = self.send(req)?;
        serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth status response: {e}"))
        })
    }
}

#[derive(Serialize)]
struct LocalSessionReq<'a> {
    provider: &'a str,
    domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    redeem_challenge: &'a str,
    redeem_challenge_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_url: Option<&'a str>,
}

#[derive(Deserialize)]
struct LocalSessionResp {
    session_id: String,
    authorization_url: String,
    expires_at: String,
}

#[derive(Serialize)]
struct RedeemReq<'a> {
    redeem_verifier: &'a str,
    completion_verifier: &'a str,
}

#[derive(Serialize)]
struct RefreshReq<'a> {
    provider: &'a str,
    broker_credential_id: &'a str,
    broker_credential_secret: &'a str,
    refresh_token: &'a str,
}

#[derive(Serialize)]
struct RevokeReq<'a> {
    provider: &'a str,
    broker_credential_id: &'a str,
    broker_credential_secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
}

#[derive(Serialize)]
struct BackendSessionReq<'a> {
    provider: &'a str,
    domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct BackendSessionResp {
    session_id: String,
    authorization_url: String,
    expires_at: String,
}

struct SendRequest<'a, B: ureq::AsSendBody> {
    agent: &'a ureq::Agent,
    request: ureq::http::Request<B>,
    target: &'a str,
    service: &'a str,
}

fn send_request<B: ureq::AsSendBody>(args: SendRequest<'_, B>) -> Result<String, SfaeError> {
    let SendRequest {
        agent,
        request,
        target,
        service,
    } = args;
    let mut response = agent.run(request).map_err(|e| {
        SfaeError::StoreError(format!("failed to contact {service} at {target}: {e}"))
    })?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| SfaeError::StoreError(format!("failed to read OAuth response: {e}")))?;
    if status == 401 || status == 403 {
        return Err(SfaeError::StoreError(format!(
            "{service} rejected OAuth request: {status}"
        )));
    }
    if status >= 400 {
        return Err(SfaeError::StoreError(format!(
            "{service} returned {status}"
        )));
    }
    Ok(body)
}

// xtask: allow-multi-param - small HTTP request builder helper
fn json_request(
    method: &str,
    url: &str,
    body: String,
) -> Result<ureq::http::Request<String>, SfaeError> {
    ureq::http::Request::builder()
        .method(method)
        .uri(url)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| SfaeError::StoreError(format!("failed to build OAuth request: {e}")))
}

/// Generate the high-entropy verifier kept only in the trusted CLI process.
pub fn generate_redeem_verifier() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Compute the local broker redeem challenge for a verifier.
pub fn redeem_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Resolve the hosted provider name for an OAuth spec/domain pair.
pub fn resolve_hosted_provider(input: HostedProviderResolve<'_>) -> Result<String, SfaeError> {
    let HostedProviderResolve {
        domain,
        requested_provider,
    } = input;
    if let Some(provider) = requested_provider {
        if provider == "discord" {
            return Ok(provider.to_string());
        }
        return Err(SfaeError::ConfigError(format!(
            "unsupported hosted OAuth provider \"{provider}\""
        )));
    }

    for candidate in parent_domains(domain) {
        if candidate == "discord.com" {
            return Ok("discord".to_string());
        }
    }

    Err(SfaeError::ConfigError(format!(
        "hosted OAuth provider is required for \"{domain}\"; only provider \"discord\" is enabled"
    )))
}

/// Inputs for resolving a hosted provider.
pub struct HostedProviderResolve<'a> {
    pub domain: &'a str,
    pub requested_provider: Option<&'a str>,
}

fn parent_domains(domain: &str) -> Vec<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    let mut domains = Vec::new();
    for start in 0..parts.len() {
        let candidate = parts[start..].join(".");
        if candidate.matches('.').count() < 1 {
            break;
        }
        domains.push(candidate);
    }
    domains
}

fn validate_broker_url(raw: &str) -> Result<(), SfaeError> {
    let trimmed = raw.trim_end_matches('/');
    let uri: ureq::http::Uri = trimmed.parse().map_err(|e| {
        SfaeError::ConfigError(format!("SFAE_OAUTH_BROKER_URL must be a valid URL: {e}"))
    })?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let host = uri.host().unwrap_or_default();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if loopback && matches!(scheme, "http" | "https") {
        return Ok(());
    }
    if scheme == "https" && host == "oauth.sfae.io" {
        return Ok(());
    }
    Err(SfaeError::ConfigError(
        "SFAE_OAUTH_BROKER_URL must be https://oauth.sfae.io or a local loopback URL".into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct MockHostedOAuthBroker {
        credential: HostedOAuthCredential,
        redeemed: RefCell<Vec<String>>,
        refreshed: RefCell<Vec<String>>,
        revoked: RefCell<Vec<String>>,
    }

    impl HostedOAuthBroker for MockHostedOAuthBroker {
        fn start_session(
            &self,
            _input: HostedOAuthStart<'_>,
        ) -> Result<StartedHostedOAuthSession, SfaeError> {
            Ok(StartedHostedOAuthSession {
                session_id: "session-1".to_string(),
                authorization_url: "https://oauth.example/authorize".to_string(),
                expires_at: "2026-01-01T00:00:00Z".to_string(),
                redeem_verifier: Some("verifier".to_string()),
            })
        }

        fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
            Ok(HostedOAuthStatus {
                session_id: session_id.to_string(),
                provider: "discord".to_string(),
                domain: "discord.com".to_string(),
                label: None,
                scopes: vec!["identify".to_string()],
                status: "success".to_string(),
                error_code: None,
                provider_subject: Some("123".to_string()),
                credential_id: None,
                expires_at: "2026-01-01T00:00:00Z".to_string(),
            })
        }

        // xtask: allow-multi-param - mock records session id and verifier
        fn redeem_session(
            &self,
            session_id: &str,
            redeem_verifier: &str,
            completion_verifier: &str,
        ) -> Result<HostedOAuthCredential, SfaeError> {
            self.redeemed.borrow_mut().push(format!(
                "{session_id}:{redeem_verifier}:{completion_verifier}"
            ));
            Ok(self.credential.clone())
        }

        fn refresh_credential(
            &self,
            input: HostedOAuthRefresh<'_>,
        ) -> Result<HostedOAuthCredential, SfaeError> {
            self.refreshed.borrow_mut().push(format!(
                "{}:{}:{}:{}",
                input.provider,
                input.broker_credential_id,
                input.broker_credential_secret,
                input.refresh_token
            ));
            Ok(self.credential.clone())
        }

        fn revoke_credential(&self, input: HostedOAuthRevoke<'_>) -> Result<(), SfaeError> {
            self.revoked.borrow_mut().push(format!(
                "{}:{}:{}:{}:{}",
                input.provider,
                input.broker_credential_id,
                input.broker_credential_secret,
                input.access_token.unwrap_or("-"),
                input.refresh_token.unwrap_or("-")
            ));
            Ok(())
        }
    }

    #[test]
    fn manager_redeems_through_broker() {
        let mut values = HashMap::new();
        values.insert("OAUTH_ACCESS_TOKEN".to_string(), "access".to_string());
        let broker = MockHostedOAuthBroker {
            credential: HostedOAuthCredential {
                values,
                internal: HashMap::new(),
                metadata: HashMap::new(),
            },
            redeemed: RefCell::new(vec![]),
            refreshed: RefCell::new(vec![]),
            revoked: RefCell::new(vec![]),
        };
        let manager = OAuthCredentialManager::new(&broker);
        let credential = manager
            .redeem_session("session-1", Some("verifier"), Some("completion"))
            .unwrap()
            .unwrap();
        assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "access");
        assert_eq!(
            broker.redeemed.borrow().as_slice(),
            ["session-1:verifier:completion"]
        );
    }

    #[test]
    fn manager_skips_redeem_when_session_has_no_verifier() {
        let broker = MockHostedOAuthBroker {
            credential: HostedOAuthCredential {
                values: HashMap::new(),
                internal: HashMap::new(),
                metadata: HashMap::new(),
            },
            redeemed: RefCell::new(vec![]),
            refreshed: RefCell::new(vec![]),
            revoked: RefCell::new(vec![]),
        };
        let manager = OAuthCredentialManager::new(&broker);
        assert!(
            manager
                .redeem_session("session-1", None, Some("completion"))
                .unwrap()
                .is_none()
        );
        assert!(broker.redeemed.borrow().is_empty());
    }

    #[test]
    fn manager_refreshes_and_revokes_through_broker() {
        let mut values = HashMap::new();
        values.insert("OAUTH_ACCESS_TOKEN".to_string(), "new-access".to_string());
        let broker = MockHostedOAuthBroker {
            credential: HostedOAuthCredential {
                values,
                internal: HashMap::new(),
                metadata: HashMap::new(),
            },
            redeemed: RefCell::new(vec![]),
            refreshed: RefCell::new(vec![]),
            revoked: RefCell::new(vec![]),
        };
        let manager = OAuthCredentialManager::new(&broker);

        let credential = manager
            .refresh_credential(HostedOAuthRefresh {
                provider: "discord",
                broker_credential_id: "grant-id",
                broker_credential_secret: "grant-secret",
                refresh_token: "refresh",
            })
            .unwrap();
        assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "new-access");
        manager
            .revoke_credential(HostedOAuthRevoke {
                provider: "discord",
                broker_credential_id: "grant-id",
                broker_credential_secret: "grant-secret",
                access_token: Some("access"),
                refresh_token: Some("refresh"),
            })
            .unwrap();

        assert_eq!(
            broker.refreshed.borrow().as_slice(),
            ["discord:grant-id:grant-secret:refresh"]
        );
        assert_eq!(
            broker.revoked.borrow().as_slice(),
            ["discord:grant-id:grant-secret:access:refresh"]
        );
    }

    #[test]
    fn redeem_challenge_is_stable_and_not_plaintext() {
        let challenge = redeem_challenge("verifier");
        assert_eq!(challenge, redeem_challenge("verifier"));
        assert_ne!(challenge, "verifier");
        assert!(!challenge.contains('='));
    }

    #[test]
    fn resolves_explicit_discord_provider() {
        let provider = resolve_hosted_provider(HostedProviderResolve {
            domain: "example.com",
            requested_provider: Some("discord"),
        })
        .unwrap();
        assert_eq!(provider, "discord");
    }

    #[test]
    fn resolves_discord_from_domain() {
        let provider = resolve_hosted_provider(HostedProviderResolve {
            domain: "discord.com",
            requested_provider: None,
        })
        .unwrap();
        assert_eq!(provider, "discord");
    }

    #[test]
    fn resolves_discord_from_subdomain() {
        let provider = resolve_hosted_provider(HostedProviderResolve {
            domain: "api.discord.com",
            requested_provider: None,
        })
        .unwrap();
        assert_eq!(provider, "discord");
    }

    #[test]
    fn rejects_unknown_provider() {
        let err = resolve_hosted_provider(HostedProviderResolve {
            domain: "example.com",
            requested_provider: Some("google"),
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported hosted OAuth provider")
        );
    }

    #[test]
    fn rejects_unknown_domain_without_provider() {
        let err = resolve_hosted_provider(HostedProviderResolve {
            domain: "example.com",
            requested_provider: None,
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only provider \"discord\" is enabled")
        );
    }

    #[test]
    fn direct_broker_allows_production_and_loopback_urls() {
        assert!(DirectHostedOAuthBroker::new("https://oauth.sfae.io").is_ok());
        assert!(DirectHostedOAuthBroker::new("http://127.0.0.1:3100").is_ok());
        assert!(DirectHostedOAuthBroker::new("http://localhost:3100").is_ok());
    }

    #[test]
    fn direct_broker_rejects_unknown_urls() {
        assert!(DirectHostedOAuthBroker::new("http://oauth.sfae.io").is_err());
        assert!(DirectHostedOAuthBroker::new("https://evil.example").is_err());
    }
}
