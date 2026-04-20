use std::collections::HashMap;

use crate::error::SfaeError;
use crate::store::{CredentialSetInfo, CredentialSetInput, SecretStore, StoreEntry};

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
    ///
    /// Panics if SFAE_STORE_URL is set but SFAE_STORE_TOKEN is missing.
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("SFAE_STORE_URL").ok()?;
        let token = std::env::var("SFAE_STORE_TOKEN").unwrap_or_else(|_| {
            panic!(
                "SFAE_STORE_URL is set but SFAE_STORE_TOKEN is missing. \
                 Both environment variables are required for API store mode."
            )
        });
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

// -- Response types for the resolve/list endpoints ----------------------------

#[derive(serde::Deserialize)]
struct ResolveResponse {
    values: HashMap<String, Option<String>>,
}

#[derive(serde::Deserialize)]
struct LegacyCredentialEntry {
    domain: String,
    cred_type: String,
}

#[derive(serde::Deserialize)]
struct LegacyListResponse {
    credentials: Vec<LegacyCredentialEntry>,
}

// -- Response types for the new credential set endpoints (Phase 3) ------------

#[derive(serde::Deserialize)]
struct CredentialSetEntry {
    id: String,
    domain: String,
    #[serde(default)]
    label: Option<String>,
    keys: Vec<String>,
}

#[derive(serde::Deserialize)]
struct CredentialSetListResponse {
    credentials: Vec<CredentialSetEntry>,
}

#[derive(serde::Deserialize)]
struct StoreCredentialResponse {
    id: String,
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
        if status == 404 {
            return Err(SfaeError::CredentialNotFound("not found".into()));
        }
        if status >= 400 {
            return Err(SfaeError::StoreError(format!(
                "Credential store returned {status}"
            )));
        }

        Ok(response)
    }

    fn read_response_body(
        response: &mut ureq::http::Response<ureq::Body>,
    ) -> Result<String, SfaeError> {
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| SfaeError::StoreError(format!("Failed to read response: {e}")))
    }
}

impl SecretStore for ApiStore {
    fn set(&mut self, _entry: StoreEntry<'_>) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "Write not supported in API store mode".to_string(),
        ))
    }

    fn get(&self, key: &str) -> Result<String, SfaeError> {
        // If key looks like a UUID, use the blob endpoint (new credential sets).
        if uuid::Uuid::parse_str(key).is_ok() {
            let url = format!("{}/credentials/{}/blob", self.base_url, key);
            let req = ureq::http::Request::builder()
                .method("GET")
                .uri(&url)
                .header("Authorization", self.auth_header())
                .body(())
                .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

            let mut response = self.run_request(req).map_err(|e| match e {
                SfaeError::CredentialNotFound(_) => SfaeError::CredentialNotFound(key.into()),
                other => other,
            })?;
            return Self::read_response_body(&mut response);
        }

        // Legacy: resolve endpoint for flat domain_TYPE keys.
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
        let body_str = Self::read_response_body(&mut response)?;
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
        let body_str = Self::read_response_body(&mut response)?;

        // Try new format first (returns credential set IDs)
        if let Ok(parsed) = serde_json::from_str::<CredentialSetListResponse>(&body_str)
            && parsed.credentials.iter().all(|c| !c.id.is_empty())
        {
            return Ok(parsed.credentials.into_iter().map(|c| c.id).collect());
        }

        // Legacy format: domain_cred_type strings
        let parsed: LegacyListResponse = serde_json::from_str(&body_str)
            .map_err(|e| SfaeError::StoreError(format!("Failed to parse response: {e}")))?;

        let mut keys: Vec<String> = parsed
            .credentials
            .into_iter()
            .map(|c| format!("{}_{}", c.domain, c.cred_type))
            .collect();
        keys.sort();
        Ok(keys)
    }

    // -- Credential set operations (active once server supports Phase 3 API) --

    fn supports_credential_sets(&self) -> bool {
        true
    }

    fn store_credential_set(
        &mut self,
        input: CredentialSetInput<'_>,
    ) -> Result<String, SfaeError> {
        let CredentialSetInput {
            domain,
            label,
            values,
        } = input;
        let url = format!("{}/credentials", self.base_url);
        let body = serde_json::json!({
            "domain": domain,
            "label": label,
            "values": values,
        })
        .to_string();

        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

        let mut response = self.run_request(req)?;
        let body_str = Self::read_response_body(&mut response)?;
        let parsed: StoreCredentialResponse = serde_json::from_str(&body_str)
            .map_err(|e| SfaeError::StoreError(format!("Failed to parse response: {e}")))?;

        Ok(parsed.id)
    }

    fn list_credential_sets(
        &self,
        domain: Option<&str>,
    ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
        let url = match domain {
            Some(d) => format!("{}/credentials/{}", self.base_url, d),
            None => format!("{}/credentials", self.base_url),
        };

        let req = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .body(())
            .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

        let mut response = match self.run_request(req) {
            Ok(r) => r,
            Err(SfaeError::CredentialNotFound(_)) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let body_str = Self::read_response_body(&mut response)?;

        // Try new format
        let parsed: CredentialSetListResponse = match serde_json::from_str(&body_str) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]), // Server returns old format — no sets
        };

        Ok(parsed
            .credentials
            .into_iter()
            .map(|c| CredentialSetInfo {
                id: c.id,
                domain: c.domain,
                label: c.label,
                keys: c.keys,
            })
            .collect())
    }

    fn delete_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
        let url = format!("{}/credentials/{}", self.base_url, id);

        let req = ureq::http::Request::builder()
            .method("DELETE")
            .uri(&url)
            .header("Authorization", self.auth_header())
            .body(())
            .map_err(|e| SfaeError::StoreError(format!("Failed to build request: {e}")))?;

        self.run_request(req).map_err(|e| match e {
            SfaeError::CredentialNotFound(_) => SfaeError::CredentialNotFound(id.into()),
            other => other,
        })?;
        Ok(())
    }
}
