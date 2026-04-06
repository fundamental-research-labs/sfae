use crate::error::SfaeError;
use crate::store::SecretStore;

/// SecretStore backed by the SFAE HTTP API.
///
/// Used when the CLI runs in client mode against a remote sfae-server (no OS keychain).
/// Configured via environment variables:
/// - `SFAE_STORE_URL`: base URL of the SFAE HTTP API (e.g., "http://sfae-api:3100")
/// - `SFAE_STORE_TOKEN`: JWT bearer token (contains user_id in `sub` claim)
pub struct ApiStore {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

impl ApiStore {
    /// Create from environment variables. Returns None if SFAE_STORE_URL is not set.
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("SFAE_STORE_URL").ok()?;
        let token = std::env::var("SFAE_STORE_TOKEN").ok()?;
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        Some(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            agent: ureq::Agent::new_with_config(config),
        })
    }
}

#[derive(serde::Deserialize)]
struct ResolveResponse {
    values: std::collections::HashMap<String, Option<String>>,
}

#[derive(serde::Deserialize)]
struct CredentialEntry {
    domain: String,
    cred_type: String,
}

#[derive(serde::Deserialize)]
struct ListResponse {
    credentials: Vec<CredentialEntry>,
}

impl ApiStore {
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn run_request(
        &self,
        req: ureq::http::Request<impl ureq::AsSendBody>,
    ) -> Result<ureq::http::Response<ureq::Body>, SfaeError> {
        let response = self.agent.run(req).map_err(|e| match e {
            ureq::Error::StatusCode(_) => {
                unreachable!("http_status_as_error is false")
            }
            other => SfaeError::StoreError(format!(
                "Failed to connect to credential store at {}: {other}. \
                 The SFAE server may be down.",
                self.base_url
            )),
        })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(SfaeError::StoreError(format!(
                "Authentication failed with credential store: {status}. \
                 The JWT may be expired or invalid."
            )));
        }
        if status >= 400 {
            return Err(SfaeError::StoreError(format!(
                "Credential store returned {status}"
            )));
        }

        Ok(response)
    }
}

impl SecretStore for ApiStore {
    fn set(&mut self, _key: &str, _value: &str) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "Write not supported in API store mode".to_string(),
        ))
    }

    fn get(&self, key: &str) -> Result<String, SfaeError> {
        let url = format!("{}/credentials/resolve", self.base_url);
        let body = serde_json::json!({ "keys": [key] }).to_string();

        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

        let mut response = self.run_request(req)?;
        let body_str = response
            .body_mut()
            .read_to_string()
            .map_err(|e| SfaeError::StoreError(format!("Failed to read response: {e}")))?;
        let parsed: ResolveResponse = serde_json::from_str(&body_str)
            .map_err(|e| SfaeError::StoreError(format!("Failed to parse response: {e}")))?;

        match parsed.values.get(key) {
            Some(Some(value)) => Ok(value.clone()),
            _ => Err(SfaeError::CredentialNotFound(key.to_string())),
        }
    }

    fn delete(&mut self, _key: &str) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "Delete not supported in API store mode".to_string(),
        ))
    }

    fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
        let url = format!("{}/credentials", self.base_url);

        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .body(())
            .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

        let mut response = self.run_request(req)?;
        let body_str = response
            .body_mut()
            .read_to_string()
            .map_err(|e| SfaeError::StoreError(format!("Failed to read response: {e}")))?;
        let parsed: ListResponse = serde_json::from_str(&body_str)
            .map_err(|e| SfaeError::StoreError(format!("Failed to parse response: {e}")))?;

        let mut keys: Vec<String> = parsed
            .credentials
            .into_iter()
            .map(|c| format!("{}_{}", c.domain, c.cred_type))
            .collect();
        keys.sort();
        Ok(keys)
    }
}
