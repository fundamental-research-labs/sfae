use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SfaeError;

/// OAuth2 token response from the token endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// Non-secret OAuth metadata needed to refresh tokens for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthMetadata {
    pub token_url: String,
    pub client_id: String,
    #[serde(default)]
    pub revocation_url: Option<String>,
}

/// Returns the path to `~/.sfae/oauth.json`.
pub fn oauth_metadata_path() -> Result<PathBuf, SfaeError> {
    let home = dirs::home_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine home directory".into()))?;
    Ok(home.join(".sfae").join("oauth.json"))
}

// -- Metadata key + file access ---------------------------------------------

/// The domain + optional username used to address a row in `oauth.json`.
pub struct MetadataKey<'a> {
    pub domain: &'a str,
    pub username: Option<&'a str>,
}

impl<'a> MetadataKey<'a> {
    /// The flat string key used in `oauth.json`: `domain` or `domain:username`.
    pub fn as_key(&self) -> String {
        match self.username {
            Some(user) => format!("{}:{}", self.domain, user),
            None => self.domain.to_string(),
        }
    }

    /// Save/insert OAuth metadata for this key.
    pub fn save(&self, metadata: OAuthMetadata) -> Result<(), SfaeError> {
        let path = oauth_metadata_path()?;
        let file = MetadataFile { path: &path };
        let mut map = file.read()?;
        map.insert(self.as_key(), metadata);
        file.write(&map)
    }

    /// Look up OAuth metadata for this key with parent-domain fallback.
    pub fn get(&self) -> Result<Option<OAuthMetadata>, SfaeError> {
        let map = read_all_oauth_metadata()?;
        Ok(self.lookup_in(&map))
    }

    /// Remove OAuth metadata for this key.
    pub fn remove(&self) -> Result<(), SfaeError> {
        let path = oauth_metadata_path()?;
        let file = MetadataFile { path: &path };
        let mut map = file.read()?;
        map.remove(&self.as_key());
        file.write(&map)
    }

    /// Look up this key (+ parent-domain fallback) inside an already-loaded map.
    pub fn lookup_in(&self, map: &HashMap<String, OAuthMetadata>) -> Option<OAuthMetadata> {
        if let Some(m) = map.get(&self.as_key()) {
            return Some(m.clone());
        }

        let parts: Vec<&str> = self.domain.split('.').collect();
        for i in 1..parts.len() {
            let parent: Vec<&str> = parts[i..].to_vec();
            if parent.len() < 2 {
                break;
            }
            let parent_domain = parent.join(".");
            let key = MetadataKey {
                domain: &parent_domain,
                username: self.username,
            }
            .as_key();
            if let Some(m) = map.get(&key) {
                return Some(m.clone());
            }
        }

        None
    }
}

/// A view over an on-disk OAuth metadata JSON file (for read/write helpers).
pub struct MetadataFile<'a> {
    pub path: &'a Path,
}

impl<'a> MetadataFile<'a> {
    pub fn read(&self) -> Result<HashMap<String, OAuthMetadata>, SfaeError> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }
        let data = fs::read_to_string(self.path)?;
        let map: HashMap<String, OAuthMetadata> = serde_json::from_str(&data)?;
        Ok(map)
    }

    pub fn write(&self, map: &HashMap<String, OAuthMetadata>) -> Result<(), SfaeError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(map)?;
        fs::write(self.path, data)?;
        Ok(())
    }
}

/// Read all OAuth metadata from disk. Returns an empty map if the file is missing.
pub fn read_all_oauth_metadata() -> Result<HashMap<String, OAuthMetadata>, SfaeError> {
    MetadataFile {
        path: &oauth_metadata_path()?,
    }
    .read()
}

/// Write all OAuth metadata to disk.
pub fn write_all_oauth_metadata(map: &HashMap<String, OAuthMetadata>) -> Result<(), SfaeError> {
    MetadataFile {
        path: &oauth_metadata_path()?,
    }
    .write(map)
}

/// Delete the entire `oauth.json` file.
pub fn delete_all_oauth_metadata() -> Result<(), SfaeError> {
    let path = oauth_metadata_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

// -- PKCE helpers -----------------------------------------------------------

/// Generate a random PKCE code verifier (128 chars from unreserved charset).
pub fn generate_code_verifier() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::rng();
    (0..128)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Compute the PKCE code challenge: BASE64URL_NO_PAD(SHA256(verifier)).
pub fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random state string for CSRF protection.
pub fn generate_state() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

// -- Authorization URL ------------------------------------------------------

/// Parameters for constructing an OAuth2 authorization URL.
pub struct AuthorizationUrl<'a> {
    pub auth_url: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub scope: Option<&'a str>,
    pub state: &'a str,
}

impl<'a> AuthorizationUrl<'a> {
    /// Build the full OAuth2 authorization URL with query parameters.
    pub fn build(&self) -> String {
        let sep = if self.auth_url.contains('?') { "&" } else { "?" };
        let mut url = format!(
            "{}{}client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256&state={}&prompt=consent&access_type=offline",
            self.auth_url,
            sep,
            url_encode(self.client_id),
            url_encode(self.redirect_uri),
            url_encode(self.code_challenge),
            url_encode(self.state),
        );
        if let Some(scope) = self.scope {
            url.push_str(&format!("&scope={}", url_encode(scope)));
        }
        url
    }
}

// -- Token request ----------------------------------------------------------

/// Which OAuth2 grant flow a `TokenRequest` uses.
pub enum Grant<'a> {
    AuthorizationCode {
        code: &'a str,
        redirect_uri: &'a str,
        code_verifier: &'a str,
    },
    RefreshToken {
        refresh_token: &'a str,
    },
}

/// Parameters shared by every POST to an OAuth2 token endpoint.
pub struct TokenRequest<'a> {
    pub token_url: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub grant: Grant<'a>,
}

impl<'a> TokenRequest<'a> {
    /// Serialize the form body for this grant.
    fn body(&self) -> String {
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        match &self.grant {
            Grant::AuthorizationCode {
                code,
                redirect_uri,
                code_verifier,
            } => {
                pairs.push(("grant_type", "authorization_code"));
                pairs.push(("code", code));
                pairs.push(("redirect_uri", redirect_uri));
                pairs.push(("client_id", self.client_id));
                pairs.push(("code_verifier", code_verifier));
            }
            Grant::RefreshToken { refresh_token } => {
                pairs.push(("grant_type", "refresh_token"));
                pairs.push(("refresh_token", refresh_token));
                pairs.push(("client_id", self.client_id));
            }
        }
        if let Some(secret) = self.client_secret {
            pairs.push(("client_secret", secret));
        }
        build_form_body(&pairs)
    }

    /// POST to the token endpoint and parse the JSON response.
    ///
    /// Used for both authorization-code exchange and refresh-token flows.
    /// Some providers rotate refresh tokens — if a new one is returned, it
    /// will be in `TokenResponse::refresh_token`.
    pub fn send(&self) -> Result<TokenResponse, SfaeError> {
        let body = self.body();

        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(self.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .map_err(|e| SfaeError::HttpError(format!("failed to build token request: {e}")))?;

        let agent = ureq::Agent::new_with_defaults();
        let mut response = agent
            .run(req)
            .map_err(|e| SfaeError::HttpError(format!("token request failed: {e}")))?;

        let body_str = response
            .body_mut()
            .read_to_string()
            .map_err(|e| SfaeError::HttpError(format!("failed to read token response: {e}")))?;

        let json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|e| SfaeError::HttpError(format!("failed to parse token response: {e}")))?;

        let access_token = json["access_token"]
            .as_str()
            .ok_or_else(|| SfaeError::HttpError("token response missing access_token".into()))?
            .to_string();

        let refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());

        Ok(TokenResponse {
            access_token,
            refresh_token,
        })
    }
}

// -- Revocation -------------------------------------------------------------

/// An OAuth2 token revocation request (RFC 7009).
pub struct Revocation<'a> {
    pub revocation_url: &'a str,
    pub token: &'a str,
}

impl<'a> Revocation<'a> {
    fn body(&self) -> String {
        build_form_body(&[("token", self.token)])
    }

    /// POST to the provider's revocation endpoint.
    ///
    /// The provider may return success even if the token is already invalid —
    /// that is fine. Callers should treat errors as non-fatal.
    pub fn send(&self) -> Result<(), SfaeError> {
        let body = self.body();

        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(self.revocation_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .map_err(|e| {
                SfaeError::HttpError(format!("failed to build revocation request: {e}"))
            })?;

        let agent = ureq::Agent::new_with_defaults();
        agent
            .run(req)
            .map_err(|e| SfaeError::HttpError(format!("token revocation request failed: {e}")))?;

        Ok(())
    }
}

// -- Helpers ----------------------------------------------------------------

/// Serialize URL-encoded form pairs as `k1=v1&k2=v2...`.
fn build_form_body(pairs: &[(&str, &str)]) -> String {
    let mut body = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            body.push('&');
        }
        body.push_str(k);
        body.push('=');
        body.push_str(&url_encode(v));
    }
    body
}

/// Minimal percent-encoding for URL query parameter values.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    result
}

// -- Provider presets -------------------------------------------------------

/// Built-in OAuth configuration for a known provider.
pub struct ProviderPreset {
    pub client_id: &'static str,
    pub client_secret: Option<&'static str>,
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub revocation_url: Option<&'static str>,
}

/// Look up a built-in OAuth provider preset by domain.
///
/// Uses parent-domain walk-up so `gmail.googleapis.com` matches the
/// `googleapis.com` preset.
pub fn get_provider_preset(domain: &str) -> Option<ProviderPreset> {
    let parts: Vec<&str> = domain.split('.').collect();
    for start in 0..parts.len() {
        let candidate: String = parts[start..].join(".");
        if candidate.matches('.').count() < 1 {
            break;
        }
        if let Some(preset) = match_preset(&candidate) {
            return Some(preset);
        }
    }
    None
}

// Cross-reference: these preset URLs are duplicated in the API server at
// api/server-v1/src/routes/sfae-oauth.ts (resolveProviderPreset function).
// If you change a URL here, update the TS side too.
fn match_preset(domain: &str) -> Option<ProviderPreset> {
    match domain {
        "googleapis.com" => Some(ProviderPreset {
            client_id: option_env!("SFAE_OAUTH_GOOGLE_CLIENT_ID").unwrap_or(
                "648921945993-7bgg2l4k5qqir28pgdve4kgfv7udfs95.apps.googleusercontent.com",
            ),
            client_secret: option_env!("SFAE_OAUTH_GOOGLE_CLIENT_SECRET"),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            revocation_url: Some("https://oauth2.googleapis.com/revoke"),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_verifier_length_and_charset() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 128);
        for ch in verifier.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_' || ch == '~',
                "invalid char in verifier: {ch}"
            );
        }
    }

    #[test]
    fn code_challenge_is_base64url() {
        let verifier = "test_verifier_string";
        let challenge = compute_code_challenge(verifier);
        // Should be valid base64url with no padding.
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.is_empty());
    }

    #[test]
    fn code_challenge_known_value() {
        // RFC 7636 Appendix B: verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // expected challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn authorization_url_construction() {
        let url = AuthorizationUrl {
            auth_url: "https://example.com/auth",
            client_id: "my_client",
            redirect_uri: "http://127.0.0.1:8080/callback",
            code_challenge: "challenge123",
            scope: Some("read write"),
            state: "state456",
        }
        .build();
        assert!(url.starts_with("https://example.com/auth?"));
        assert!(url.contains("client_id=my_client"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback"));
        assert!(url.contains("code_challenge=challenge123"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state456"));
        assert!(url.contains("scope=read%20write"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn authorization_url_no_scope() {
        let url = AuthorizationUrl {
            auth_url: "https://example.com/auth",
            client_id: "my_client",
            redirect_uri: "http://127.0.0.1:8080/callback",
            code_challenge: "challenge123",
            scope: None,
            state: "state456",
        }
        .build();
        assert!(!url.contains("scope="));
    }

    #[test]
    fn state_is_nonempty() {
        let state = generate_state();
        assert!(!state.is_empty());
        // 32 random bytes base64url-encoded = 43 chars.
        assert_eq!(state.len(), 43);
    }

    #[test]
    fn url_encode_preserves_unreserved() {
        assert_eq!(url_encode("hello-world_2.0~test"), "hello-world_2.0~test");
    }

    #[test]
    fn url_encode_encodes_special() {
        assert_eq!(url_encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    // --- OAuthMetadata tests ---

    fn sample_metadata() -> OAuthMetadata {
        OAuthMetadata {
            token_url: "https://oauth2.example.com/token".into(),
            client_id: "my-client-id".into(),
            revocation_url: None,
        }
    }

    #[test]
    fn metadata_key_without_username() {
        assert_eq!(
            MetadataKey {
                domain: "example.com",
                username: None
            }
            .as_key(),
            "example.com"
        );
    }

    #[test]
    fn metadata_key_with_username() {
        assert_eq!(
            MetadataKey {
                domain: "example.com",
                username: Some("alice")
            }
            .as_key(),
            "example.com:alice"
        );
    }

    #[test]
    fn metadata_serialization_roundtrip() {
        let m = sample_metadata();
        let json = serde_json::to_string(&m).unwrap();
        let m2: OAuthMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m.token_url, m2.token_url);
        assert_eq!(m.client_id, m2.client_id);
        assert_eq!(m.revocation_url, m2.revocation_url);
    }

    #[test]
    fn metadata_deserializes_without_revocation_url() {
        let json = r#"{"token_url":"https://example.com/token","client_id":"old-client"}"#;
        let m: OAuthMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(m.token_url, "https://example.com/token");
        assert_eq!(m.client_id, "old-client");
        assert_eq!(m.revocation_url, None);
    }

    #[test]
    fn metadata_serialization_with_revocation_url() {
        let m = OAuthMetadata {
            token_url: "https://example.com/token".into(),
            client_id: "my-client".into(),
            revocation_url: Some("https://example.com/revoke".into()),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: OAuthMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.revocation_url, Some("https://example.com/revoke".into()));
    }

    #[test]
    fn read_missing_file_returns_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let map = MetadataFile { path: &path }.read().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        MetadataFile { path: &path }.write(&map).unwrap();

        let loaded = MetadataFile { path: &path }.read().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["example.com"].client_id, "my-client-id");
    }

    #[test]
    fn save_and_get_via_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        // Save
        let mut map = HashMap::new();
        map.insert(
            MetadataKey {
                domain: "google.com",
                username: None,
            }
            .as_key(),
            OAuthMetadata {
                token_url: "https://oauth2.googleapis.com/token".into(),
                client_id: "goog-123".into(),
                revocation_url: None,
            },
        );
        MetadataFile { path: &path }.write(&map).unwrap();

        // Read back
        let loaded = MetadataFile { path: &path }.read().unwrap();
        let m = loaded.get("google.com").unwrap();
        assert_eq!(m.token_url, "https://oauth2.googleapis.com/token");
        assert_eq!(m.client_id, "goog-123");
    }

    #[test]
    fn save_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        let mut map = HashMap::new();
        map.insert("d.com".to_string(), sample_metadata());
        MetadataFile { path: &path }.write(&map).unwrap();

        // Overwrite with new metadata
        let mut map = MetadataFile { path: &path }.read().unwrap();
        map.insert(
            "d.com".to_string(),
            OAuthMetadata {
                token_url: "https://new.example.com/token".into(),
                client_id: "new-id".into(),
                revocation_url: None,
            },
        );
        MetadataFile { path: &path }.write(&map).unwrap();

        let loaded = MetadataFile { path: &path }.read().unwrap();
        assert_eq!(loaded["d.com"].client_id, "new-id");
    }

    #[test]
    fn lookup_exact_match() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = MetadataKey {
            domain: "example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, "my-client-id");
    }

    #[test]
    fn lookup_parent_domain_fallback() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = MetadataKey {
            domain: "api.example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, "my-client-id");
    }

    #[test]
    fn lookup_deep_subdomain_fallback() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = MetadataKey {
            domain: "a.b.example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_some());
    }

    #[test]
    fn lookup_stops_at_two_labels() {
        let mut map = HashMap::new();
        map.insert("com".to_string(), sample_metadata());
        let found = MetadataKey {
            domain: "api.example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_none());
    }

    #[test]
    fn lookup_not_found() {
        let map = HashMap::new();
        let found = MetadataKey {
            domain: "example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_none());
    }

    #[test]
    fn lookup_with_username() {
        let mut map = HashMap::new();
        map.insert("example.com:alice".to_string(), sample_metadata());

        // With matching username
        let found = MetadataKey {
            domain: "example.com",
            username: Some("alice"),
        }
        .lookup_in(&map);
        assert!(found.is_some());

        // Without username — should not match
        let found = MetadataKey {
            domain: "example.com",
            username: None,
        }
        .lookup_in(&map);
        assert!(found.is_none());
    }

    // --- TokenRequest body tests ---

    #[test]
    fn refresh_body_without_client_secret() {
        let body = TokenRequest {
            token_url: "https://example.com/token",
            client_id: "my-client",
            client_secret: None,
            grant: Grant::RefreshToken {
                refresh_token: "my-refresh-tok",
            },
        }
        .body();
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=my-refresh-tok&client_id=my-client"
        );
    }

    #[test]
    fn refresh_body_with_client_secret() {
        let body = TokenRequest {
            token_url: "https://example.com/token",
            client_id: "my-client",
            client_secret: Some("s3cret"),
            grant: Grant::RefreshToken {
                refresh_token: "my-refresh-tok",
            },
        }
        .body();
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=my-refresh-tok&client_id=my-client&client_secret=s3cret"
        );
    }

    #[test]
    fn refresh_body_encodes_special_chars() {
        let body = TokenRequest {
            token_url: "https://example.com/token",
            client_id: "id with spaces",
            client_secret: Some("sec/ret"),
            grant: Grant::RefreshToken {
                refresh_token: "tok&en=val",
            },
        }
        .body();
        assert!(body.contains("refresh_token=tok%26en%3Dval"));
        assert!(body.contains("client_id=id%20with%20spaces"));
        assert!(body.contains("client_secret=sec%2Fret"));
    }

    #[test]
    fn authorization_code_body() {
        let body = TokenRequest {
            token_url: "https://example.com/token",
            client_id: "my-client",
            client_secret: None,
            grant: Grant::AuthorizationCode {
                code: "auth-code-123",
                redirect_uri: "http://127.0.0.1:8080/callback",
                code_verifier: "verifier-abc",
            },
        }
        .body();
        assert!(body.starts_with("grant_type=authorization_code&"));
        assert!(body.contains("code=auth-code-123"));
        assert!(body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback"));
        assert!(body.contains("client_id=my-client"));
        assert!(body.contains("code_verifier=verifier-abc"));
    }

    // --- Revocation body tests ---

    #[test]
    fn revocation_body_basic() {
        let body = Revocation {
            revocation_url: "https://example.com/revoke",
            token: "ya29.some-access-token",
        }
        .body();
        assert_eq!(body, "token=ya29.some-access-token");
    }

    #[test]
    fn revocation_body_encodes_special_chars() {
        let body = Revocation {
            revocation_url: "https://example.com/revoke",
            token: "tok&en=val ue",
        }
        .body();
        assert_eq!(body, "token=tok%26en%3Dval%20ue");
    }

    // --- ProviderPreset tests ---

    #[test]
    fn preset_known_domain() {
        let preset = get_provider_preset("googleapis.com");
        assert!(preset.is_some());
        let p = preset.unwrap();
        assert!(p.client_id.ends_with(".apps.googleusercontent.com"));
        assert_eq!(p.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(p.token_url, "https://oauth2.googleapis.com/token");
        assert_eq!(
            p.revocation_url,
            Some("https://oauth2.googleapis.com/revoke")
        );
    }

    #[test]
    fn preset_subdomain_walkup() {
        let preset = get_provider_preset("gmail.googleapis.com");
        assert!(preset.is_some());
        let p = preset.unwrap();
        assert!(p.client_id.ends_with(".apps.googleusercontent.com"));
    }

    #[test]
    fn preset_deep_subdomain_walkup() {
        let preset = get_provider_preset("www.mail.googleapis.com");
        assert!(preset.is_some());
    }

    #[test]
    fn preset_unknown_domain() {
        assert!(get_provider_preset("github.com").is_none());
    }

    #[test]
    fn preset_tld_not_matched() {
        assert!(get_provider_preset("com").is_none());
    }

    #[test]
    fn remove_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        let mut map = HashMap::new();
        map.insert("a.com".to_string(), sample_metadata());
        map.insert("b.com".to_string(), sample_metadata());
        MetadataFile { path: &path }.write(&map).unwrap();

        // Remove one
        let mut map = MetadataFile { path: &path }.read().unwrap();
        map.remove("a.com");
        MetadataFile { path: &path }.write(&map).unwrap();

        let loaded = MetadataFile { path: &path }.read().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("b.com"));
        assert!(!loaded.contains_key("a.com"));
    }
}
