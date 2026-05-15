//! Hosted OAuth handoff helpers.
//!
//! SFAE clients do not implement provider OAuth locally. They ask the SFAE
//! backend to create and poll hosted broker sessions, then the hosted broker
//! owns provider callbacks, token exchange, token storage, refresh, and revoke.

use serde::{Deserialize, Serialize};

use crate::error::SfaeError;

/// Client for SFAE backend endpoints that proxy hosted OAuth broker sessions.
pub struct HostedOAuthClient {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

impl HostedOAuthClient {
    /// Create a client from `SFAE_STORE_URL` and `SFAE_STORE_TOKEN`.
    pub fn from_env() -> Result<Self, SfaeError> {
        let base_url = std::env::var("SFAE_STORE_URL").map_err(|_| {
            SfaeError::ConfigError(
                "hosted OAuth requires SFAE_STORE_URL to point at the SFAE backend".into(),
            )
        })?;
        let token = std::env::var("SFAE_STORE_TOKEN").map_err(|_| {
            SfaeError::ConfigError(
                "hosted OAuth requires SFAE_STORE_TOKEN for the current SFAE user".into(),
            )
        })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            agent: crate::http::make_agent(),
        })
    }

    /// Ask the SFAE backend to start a hosted OAuth browser session.
    pub fn create_session(
        &self,
        input: HostedOAuthSessionInput<'_>,
    ) -> Result<HostedOAuthSession, SfaeError> {
        let url = format!("{}/oauth/sessions", self.base_url);
        let body = serde_json::to_string(&input).map_err(|e| {
            SfaeError::StoreError(format!("failed to serialize OAuth request: {e}"))
        })?;
        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| SfaeError::StoreError(format!("failed to build OAuth request: {e}")))?;

        let body = self.send(req)?;
        serde_json::from_str(&body)
            .map_err(|e| SfaeError::StoreError(format!("failed to parse OAuth response: {e}")))
    }

    /// Poll hosted OAuth session status through the SFAE backend.
    pub fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
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

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn send(&self, req: ureq::http::Request<impl ureq::AsSendBody>) -> Result<String, SfaeError> {
        let mut response = self.agent.run(req).map_err(|e| {
            SfaeError::StoreError(format!(
                "failed to contact SFAE backend at {}: {e}",
                self.base_url
            ))
        })?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| SfaeError::StoreError(format!("failed to read backend response: {e}")))?;
        if status == 401 || status == 403 {
            return Err(SfaeError::StoreError(format!(
                "SFAE backend rejected OAuth request: {status}"
            )));
        }
        if status >= 400 {
            return Err(SfaeError::StoreError(format!(
                "SFAE backend returned {status}: {}",
                trim_for_error(&body)
            )));
        }
        Ok(body)
    }
}

/// Request body for starting a hosted OAuth session through the SFAE backend.
#[derive(Serialize)]
pub struct HostedOAuthSessionInput<'a> {
    pub provider: &'a str,
    pub domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Sanitized session-start response returned to browser/UI code.
#[derive(Debug, Clone, Deserialize)]
pub struct HostedOAuthSession {
    pub session_id: String,
    pub authorization_url: String,
    pub expires_at: String,
}

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

fn trim_for_error(body: &str) -> String {
    const MAX_LEN: usize = 180;
    let one_line = body.replace(['\n', '\r'], " ");
    if one_line.len() > MAX_LEN {
        format!("{}...", &one_line[..MAX_LEN])
    } else {
        one_line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
