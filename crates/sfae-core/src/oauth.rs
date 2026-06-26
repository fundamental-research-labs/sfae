//! Hosted OAuth broker boundaries and client adapters.
//!
//! SFAE clients do not implement provider OAuth locally. They ask a hosted
//! broker to create and poll browser sessions. Local CLI mode redeems completed
//! token material once and stores it in the OS credential store; backend mode
//! keeps the existing SFAE-server proxy path.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SfaeError;

const DEFAULT_OAUTH_BROKER_URL: &str = "https://oauth.sfae.io";
const PROVIDER_REGISTRY_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Typed hosted OAuth broker capability used by browser and CLI code.
pub trait HostedOAuthBroker {
    /// Fetch supported provider metadata from the broker.
    fn provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        Err(SfaeError::Other(
            "this OAuth broker adapter does not expose provider metadata".into(),
        ))
    }

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

    pub fn provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        self.broker.provider_registry()
    }

    // xtask: allow-multi-param - resolves using the request domain and optional provider name
    pub fn resolve_provider(
        &self,
        domain: &str,
        requested_provider: Option<&str>,
    ) -> Result<String, SfaeError> {
        let registry = self.provider_registry()?;
        resolve_hosted_provider(HostedProviderResolve {
            domain,
            requested_provider,
            registry: &registry,
        })
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

/// Broker-advertised hosted OAuth provider metadata.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostedOAuthProvider {
    pub provider: String,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Broker-advertised hosted OAuth provider registry.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct HostedOAuthProviderRegistry {
    #[serde(default)]
    pub providers: Vec<HostedOAuthProvider>,
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
    provider_cache: RefCell<Option<CachedProviderRegistry>>,
}

#[derive(Clone)]
struct CachedProviderRegistry {
    registry: HostedOAuthProviderRegistry,
    expires_at: Instant,
}

#[derive(Deserialize, Serialize)]
struct ProviderRegistryCacheFile {
    fetched_at_epoch_seconds: u64,
    registry: HostedOAuthProviderRegistry,
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
            agent: crate::http::make_agent_for_url(base_url),
            provider_cache: RefCell::new(None),
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

    fn cached_provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        if let Some(cache) = self.provider_cache.borrow().as_ref()
            && Instant::now() < cache.expires_at
        {
            return Ok(cache.registry.clone());
        }
        if let Some((registry, remaining_ttl)) = read_provider_registry_cache(&self.base_url) {
            *self.provider_cache.borrow_mut() = Some(CachedProviderRegistry {
                registry: registry.clone(),
                expires_at: Instant::now() + remaining_ttl,
            });
            return Ok(registry);
        }

        let url = format!("{}/v1/oauth/providers", self.base_url);
        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .body(())
            .map_err(|e| {
                SfaeError::StoreError(format!("failed to build OAuth providers request: {e}"))
            })?;
        let body = self.send(req)?;
        let registry: HostedOAuthProviderRegistry = serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth providers response: {e}"))
        })?;
        if provider_registry_disk_cache_enabled(&self.base_url) {
            let _ = write_provider_registry_cache(&self.base_url, &registry);
        }
        *self.provider_cache.borrow_mut() = Some(CachedProviderRegistry {
            registry: registry.clone(),
            expires_at: Instant::now() + PROVIDER_REGISTRY_REFRESH_INTERVAL,
        });
        Ok(registry)
    }
}

impl HostedOAuthBroker for DirectHostedOAuthBroker {
    fn provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        self.cached_provider_registry()
    }

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
        let body = serde_json::to_string(&RevokeReq {
            provider: input.provider,
            broker_credential_id: input.broker_credential_id,
            broker_credential_secret: input.broker_credential_secret,
            access_token: input.access_token,
            refresh_token: input.refresh_token,
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
    provider_cache: RefCell<Option<CachedProviderRegistry>>,
}

/// Construction parameters for the SFAE-backend OAuth proxy adapter.
pub struct BackendProxyConfig<'a> {
    pub base_url: &'a str,
    pub token: &'a str,
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
        Self::new(BackendProxyConfig {
            base_url: &base_url,
            token: &token,
        })
    }

    /// Create a backend-proxy client from explicit connection settings.
    pub fn new(config: BackendProxyConfig<'_>) -> Result<Self, SfaeError> {
        if config.base_url.trim().is_empty() {
            return Err(SfaeError::ConfigError(
                "SFAE backend OAuth proxy URL cannot be empty".into(),
            ));
        }
        if config.token.trim().is_empty() {
            return Err(SfaeError::ConfigError(
                "SFAE backend OAuth proxy token cannot be empty".into(),
            ));
        }
        Ok(Self {
            base_url: config.base_url.trim_end_matches('/').to_string(),
            token: config.token.to_string(),
            agent: crate::http::make_agent_for_url(config.base_url),
            provider_cache: RefCell::new(None),
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

    fn cached_provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        if let Some(cache) = self.provider_cache.borrow().as_ref()
            && Instant::now() < cache.expires_at
        {
            return Ok(cache.registry.clone());
        }
        if let Some((registry, remaining_ttl)) = read_provider_registry_cache(&self.base_url) {
            *self.provider_cache.borrow_mut() = Some(CachedProviderRegistry {
                registry: registry.clone(),
                expires_at: Instant::now() + remaining_ttl,
            });
            return Ok(registry);
        }

        let url = format!("{}/oauth/providers", self.base_url);
        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .body(())
            .map_err(|e| {
                SfaeError::StoreError(format!("failed to build OAuth providers request: {e}"))
            })?;
        let body = self.send(req)?;
        let registry: HostedOAuthProviderRegistry = serde_json::from_str(&body).map_err(|e| {
            SfaeError::StoreError(format!("failed to parse OAuth providers response: {e}"))
        })?;
        if provider_registry_disk_cache_enabled(&self.base_url) {
            let _ = write_provider_registry_cache(&self.base_url, &registry);
        }
        *self.provider_cache.borrow_mut() = Some(CachedProviderRegistry {
            registry: registry.clone(),
            expires_at: Instant::now() + PROVIDER_REGISTRY_REFRESH_INTERVAL,
        });
        Ok(registry)
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
    fn provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        self.cached_provider_registry()
    }

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
        registry,
    } = input;
    if let Some(provider) = requested_provider {
        if registry
            .providers
            .iter()
            .any(|candidate| candidate.provider == provider)
        {
            return Ok(provider.to_string());
        }
        return Err(SfaeError::ConfigError(format!(
            "unsupported hosted OAuth provider \"{provider}\"{}",
            supported_provider_hint(registry)
        )));
    }

    for candidate in parent_domains(domain) {
        if let Some(provider) = registry.providers.iter().find(|provider| {
            provider
                .domains
                .iter()
                .any(|supported_domain| supported_domain == &candidate)
        }) {
            return Ok(provider.provider.clone());
        }
    }

    Err(SfaeError::ConfigError(format!(
        "hosted OAuth provider is required for \"{domain}\"{}",
        supported_provider_hint(registry)
    )))
}

/// Inputs for resolving a hosted provider.
pub struct HostedProviderResolve<'a> {
    pub domain: &'a str,
    pub requested_provider: Option<&'a str>,
    pub registry: &'a HostedOAuthProviderRegistry,
}

fn supported_provider_hint(registry: &HostedOAuthProviderRegistry) -> String {
    if registry.providers.is_empty() {
        return "; the broker did not report any hosted OAuth providers".to_string();
    }
    let mut providers: Vec<&str> = registry
        .providers
        .iter()
        .map(|provider| provider.provider.as_str())
        .collect();
    providers.sort();
    providers.dedup();
    format!("; supported providers: {}", providers.join(", "))
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

fn read_provider_registry_cache(base_url: &str) -> Option<(HostedOAuthProviderRegistry, Duration)> {
    if !provider_registry_disk_cache_enabled(base_url) {
        return None;
    }
    let raw = fs::read_to_string(provider_registry_cache_path(base_url)).ok()?;
    let cache: ProviderRegistryCacheFile = serde_json::from_str(&raw).ok()?;
    let now = current_epoch_seconds()?;
    let max_age = PROVIDER_REGISTRY_REFRESH_INTERVAL.as_secs();
    let age = now.checked_sub(cache.fetched_at_epoch_seconds)?;
    if age >= max_age {
        return None;
    }
    Some((
        cache.registry,
        Duration::from_secs(max_age.saturating_sub(age)),
    ))
}

// xtask: allow-multi-param - cache key pairs broker URL with fetched registry
fn write_provider_registry_cache(
    base_url: &str,
    registry: &HostedOAuthProviderRegistry,
) -> Result<(), SfaeError> {
    let path = provider_registry_cache_path(base_url);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cache = ProviderRegistryCacheFile {
        fetched_at_epoch_seconds: current_epoch_seconds()
            .ok_or_else(|| SfaeError::Other("system clock is before unix epoch".into()))?,
        registry: registry.clone(),
    };
    let raw = serde_json::to_string(&cache)?;
    fs::write(path, raw)?;
    Ok(())
}

fn provider_registry_cache_path(base_url: &str) -> PathBuf {
    let digest = Sha256::digest(base_url.as_bytes());
    let key = URL_SAFE_NO_PAD.encode(digest);
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("sfae");
    cache_dir.join(format!("oauth-providers-{key}.json"))
}

fn provider_registry_disk_cache_enabled(base_url: &str) -> bool {
    !broker_url_is_loopback(base_url)
}

fn current_epoch_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn broker_url_is_loopback(raw: &str) -> bool {
    let Ok(uri) = raw.parse::<ureq::http::Uri>() else {
        return false;
    };
    matches!(uri.host(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn validate_broker_url(raw: &str) -> Result<(), SfaeError> {
    let trimmed = raw.trim_end_matches('/');
    let uri: ureq::http::Uri = trimmed.parse().map_err(|e| {
        SfaeError::ConfigError(format!("SFAE_OAUTH_BROKER_URL must be a valid URL: {e}"))
    })?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let host = uri.host().unwrap_or_default();
    let loopback = broker_url_is_loopback(trimmed);
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
