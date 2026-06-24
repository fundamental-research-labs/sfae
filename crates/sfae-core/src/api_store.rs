//! HTTP-backed `SecretStore` implementation for talking to a remote sfae-server.
//!
//! Used by client builds that talk to a remote SFAE store.

use std::collections::HashMap;

use crate::error::SfaeError;
use crate::store::{CredentialSetInfo, CredentialSetInput, SecretStore, StoreEntry};

/// SecretStore backed by the SFAE HTTP API.
///
/// Used when the CLI talks to a remote sfae-server.
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
                 Both environment variables are required for the remote credential store."
            )
        });
        Some(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            agent: crate::http::make_agent(),
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
    #[serde(default)]
    metadata: HashMap<String, String>,
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
            "Write not supported by the remote credential store".to_string(),
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

    fn delete(&mut self, key: &str) -> Result<(), SfaeError> {
        if uuid::Uuid::parse_str(key).is_ok() {
            return self.delete_credential_set(key);
        }
        Err(SfaeError::Other(
            "Delete not supported by the remote credential store".to_string(),
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

    fn store_credential_set(&mut self, input: CredentialSetInput<'_>) -> Result<String, SfaeError> {
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
                metadata: c.metadata,
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::proxy::CredentialLookup;

    use super::*;

    struct ExpectedRequest {
        method: &'static str,
        path: String,
        response: MockResponse,
    }

    struct MockResponse {
        status: u16,
        content_type: &'static str,
        body: String,
    }

    struct JsonExpected {
        path: String,
        body: serde_json::Value,
    }

    struct TextExpected {
        path: String,
        body: String,
    }

    struct MockStore {
        base_url: String,
        handle: thread::JoinHandle<()>,
    }

    struct ParsedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
    }

    struct SendResponse<'a> {
        stream: &'a mut TcpStream,
        response: &'a MockResponse,
    }

    impl ExpectedRequest {
        fn json(args: JsonExpected) -> Self {
            Self {
                method: "GET",
                path: args.path,
                response: MockResponse {
                    status: 200,
                    content_type: "application/json",
                    body: args.body.to_string(),
                },
            }
        }

        fn text(args: TextExpected) -> Self {
            Self {
                method: "GET",
                path: args.path,
                response: MockResponse {
                    status: 200,
                    content_type: "text/plain",
                    body: args.body,
                },
            }
        }
    }

    impl MockStore {
        fn api_store(&self) -> ApiStore {
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build();
            ApiStore {
                base_url: self.base_url.clone(),
                token: "test-token".to_string(),
                agent: ureq::Agent::new_with_config(config),
            }
        }

        fn finish(self) {
            self.handle.join().unwrap();
        }
    }

    fn spawn_mock_store(requests: Vec<ExpectedRequest>) -> MockStore {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for expected in requests {
                let (mut stream, _) = listener.accept().unwrap();
                let actual = read_request(&mut stream);
                assert_eq!(actual.method, expected.method);
                assert_eq!(actual.path, expected.path);
                assert_eq!(
                    actual.headers.get("authorization").map(String::as_str),
                    Some("Bearer test-token")
                );
                send_response(SendResponse {
                    stream: &mut stream,
                    response: &expected.response,
                });
            }
        });

        MockStore {
            base_url: format!("http://{addr}"),
            handle,
        }
    }

    fn read_request(stream: &mut TcpStream) -> ParsedRequest {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();

        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let key = name.to_ascii_lowercase();
                let value = value.trim().to_string();
                if key == "content-length" {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.insert(key, value);
            }
        }

        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
        }

        ParsedRequest {
            method,
            path,
            headers,
        }
    }

    fn send_response(args: SendResponse<'_>) {
        let SendResponse { stream, response } = args;
        let status_text = if response.status == 200 {
            "OK"
        } else {
            "Error"
        };
        let http = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status,
            status_text,
            response.content_type,
            response.body.len(),
            response.body
        );
        stream.write_all(http.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn remote_store_resolves_materialized_discord_oauth_credential() {
        let credential_id = "00000000-0000-4000-8000-000000000001";
        let account_id = "00000000-0000-4000-8000-000000000002";
        let blob = serde_json::json!({
            "OAUTH_ACCESS_TOKEN": "discord-access-token",
            "OAUTH_ACCOUNT_ID": account_id,
            "OAUTH_PROVIDER": "discord"
        })
        .to_string();

        let mock = spawn_mock_store(vec![
            ExpectedRequest::json(JsonExpected {
                path: "/credentials/api.discord.com".to_string(),
                body: serde_json::json!({ "credentials": [] }),
            }),
            ExpectedRequest::json(JsonExpected {
                path: "/credentials/discord.com".to_string(),
                body: serde_json::json!({
                    "credentials": [{
                        "id": credential_id,
                        "domain": "discord.com",
                        "label": null,
                        "keys": [
                            "OAUTH_ACCESS_TOKEN",
                            "OAUTH_ACCOUNT_ID",
                            "OAUTH_PROVIDER"
                        ]
                    }]
                }),
            }),
            ExpectedRequest::text(TextExpected {
                path: format!("/credentials/{credential_id}/blob"),
                body: blob,
            }),
        ]);
        let store = mock.api_store();

        let resolved = CredentialLookup {
            store: &store,
            domain: "api.discord.com",
            username: None,
            cred_id: None,
        }
        .resolve("Bearer {OAUTH_ACCESS_TOKEN}")
        .unwrap();

        assert_eq!(resolved, "Bearer discord-access-token");
        mock.finish();
    }

    #[test]
    fn remote_store_resolves_materialized_discord_oauth_credential_by_id() {
        let credential_id = "00000000-0000-4000-8000-000000000003";
        let blob = serde_json::json!({
            "OAUTH_ACCESS_TOKEN": "direct-token",
            "OAUTH_ACCOUNT_ID": "00000000-0000-4000-8000-000000000004",
            "OAUTH_PROVIDER": "discord"
        })
        .to_string();

        let mock = spawn_mock_store(vec![ExpectedRequest::text(TextExpected {
            path: format!("/credentials/{credential_id}/blob"),
            body: blob,
        })]);
        let store = mock.api_store();

        let resolved = CredentialLookup {
            store: &store,
            domain: "wrong.example",
            username: None,
            cred_id: Some(credential_id),
        }
        .resolve("{OAUTH_ACCESS_TOKEN}")
        .unwrap();

        assert_eq!(resolved, "direct-token");
        mock.finish();
    }
}
