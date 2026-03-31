use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

/// Returns the path to `~/.config/sfae/oauth.json`.
pub fn oauth_metadata_path() -> Result<PathBuf, SfaeError> {
    let base = dirs::config_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine config directory".into()))?;
    Ok(base.join("sfae").join("oauth.json"))
}

/// Build the metadata key: `domain` or `domain:username`.
pub fn metadata_key(domain: &str, username: Option<&str>) -> String {
    match username {
        Some(user) => format!("{domain}:{user}"),
        None => domain.to_string(),
    }
}

fn read_all_from(path: &std::path::Path) -> Result<HashMap<String, OAuthMetadata>, SfaeError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let data = fs::read_to_string(path)?;
    let map: HashMap<String, OAuthMetadata> = serde_json::from_str(&data)?;
    Ok(map)
}

fn write_all_to(
    path: &std::path::Path,
    map: &HashMap<String, OAuthMetadata>,
) -> Result<(), SfaeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(map)?;
    fs::write(path, data)?;
    Ok(())
}

fn lookup_in_map(
    map: &HashMap<String, OAuthMetadata>,
    domain: &str,
    username: Option<&str>,
) -> Option<OAuthMetadata> {
    // Exact match.
    let key = metadata_key(domain, username);
    if let Some(m) = map.get(&key) {
        return Some(m.clone());
    }

    // Walk up parent domains.
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent: Vec<&str> = parts[i..].to_vec();
        if parent.len() < 2 {
            break;
        }
        let parent_domain = parent.join(".");
        let key = metadata_key(&parent_domain, username);
        if let Some(m) = map.get(&key) {
            return Some(m.clone());
        }
    }

    None
}

/// Read all OAuth metadata from disk. Returns an empty map if the file is missing.
pub fn read_all_oauth_metadata() -> Result<HashMap<String, OAuthMetadata>, SfaeError> {
    read_all_from(&oauth_metadata_path()?)
}

/// Write all OAuth metadata to disk.
pub fn write_all_oauth_metadata(map: &HashMap<String, OAuthMetadata>) -> Result<(), SfaeError> {
    write_all_to(&oauth_metadata_path()?, map)
}

/// Save or update OAuth metadata for a domain (and optional username).
pub fn save_oauth_metadata(
    domain: &str,
    username: Option<&str>,
    metadata: OAuthMetadata,
) -> Result<(), SfaeError> {
    let path = oauth_metadata_path()?;
    let mut map = read_all_from(&path)?;
    map.insert(metadata_key(domain, username), metadata);
    write_all_to(&path, &map)
}

/// Look up OAuth metadata for a domain, with parent-domain fallback.
///
/// Same walk-up logic as credential lookup: `api.example.com` → `example.com`.
pub fn get_oauth_metadata(
    domain: &str,
    username: Option<&str>,
) -> Result<Option<OAuthMetadata>, SfaeError> {
    let map = read_all_oauth_metadata()?;
    Ok(lookup_in_map(&map, domain, username))
}

/// Remove OAuth metadata for a domain (and optional username).
pub fn remove_oauth_metadata(domain: &str, username: Option<&str>) -> Result<(), SfaeError> {
    let path = oauth_metadata_path()?;
    let mut map = read_all_from(&path)?;
    map.remove(&metadata_key(domain, username));
    write_all_to(&path, &map)
}

/// Delete the entire `oauth.json` file.
pub fn delete_all_oauth_metadata() -> Result<(), SfaeError> {
    let path = oauth_metadata_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

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

/// Build the full OAuth2 authorization URL with query parameters.
pub fn build_authorization_url(
    auth_url: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: Option<&str>,
    state: &str,
) -> String {
    let sep = if auth_url.contains('?') { "&" } else { "?" };
    let mut url = format!(
        "{auth_url}{sep}client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256&state={}&prompt=consent&access_type=offline",
        url_encode(client_id),
        url_encode(redirect_uri),
        url_encode(code_challenge),
        url_encode(state),
    );
    if let Some(scope) = scope {
        url.push_str(&format!("&scope={}", url_encode(scope)));
    }
    url
}

/// Exchange an authorization code for tokens by POSTing to the token endpoint.
pub fn exchange_code(
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code_verifier: &str,
) -> Result<TokenResponse, SfaeError> {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        url_encode(code),
        url_encode(redirect_uri),
        url_encode(client_id),
        url_encode(code_verifier),
    );
    if let Some(secret) = client_secret {
        body.push_str(&format!("&client_secret={}", url_encode(secret)));
    }

    let req = ureq::http::Request::builder()
        .method("POST")
        .uri(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .map_err(|e| SfaeError::HttpError(format!("failed to build token request: {e}")))?;

    let agent = ureq::Agent::new_with_defaults();
    let mut response = agent
        .run(req)
        .map_err(|e| SfaeError::HttpError(format!("token exchange request failed: {e}")))?;

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

/// Build the form body for a token refresh request.
fn build_refresh_body(refresh_token: &str, client_id: &str, client_secret: Option<&str>) -> String {
    let mut body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        url_encode(refresh_token),
        url_encode(client_id),
    );
    if let Some(secret) = client_secret {
        body.push_str(&format!("&client_secret={}", url_encode(secret)));
    }
    body
}

/// Exchange a refresh token for a new access token by POSTing to the token endpoint.
///
/// Some providers rotate refresh tokens — if a new one is returned, it will be in
/// `TokenResponse::refresh_token`.
pub fn refresh_access_token(
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<TokenResponse, SfaeError> {
    let body = build_refresh_body(refresh_token, client_id, client_secret);

    let req = ureq::http::Request::builder()
        .method("POST")
        .uri(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .map_err(|e| SfaeError::HttpError(format!("failed to build refresh request: {e}")))?;

    let agent = ureq::Agent::new_with_defaults();
    let mut response = agent
        .run(req)
        .map_err(|e| SfaeError::HttpError(format!("token refresh request failed: {e}")))?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .map_err(|e| SfaeError::HttpError(format!("failed to read refresh response: {e}")))?;

    let json: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| SfaeError::HttpError(format!("failed to parse refresh response: {e}")))?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| SfaeError::HttpError("refresh response missing access_token".into()))?
        .to_string();

    let new_refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());

    Ok(TokenResponse {
        access_token,
        refresh_token: new_refresh_token,
    })
}

/// Build the form body for a token revocation request.
fn build_revocation_body(token: &str) -> String {
    format!("token={}", url_encode(token))
}

/// Revoke an OAuth2 token by POSTing to the provider's revocation endpoint.
///
/// Follows RFC 7009. The provider may return success even if the token is already
/// invalid — that is fine. Callers should treat errors as non-fatal.
pub fn revoke_token(revocation_url: &str, token: &str) -> Result<(), SfaeError> {
    let body = build_revocation_body(token);

    let req = ureq::http::Request::builder()
        .method("POST")
        .uri(revocation_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .map_err(|e| SfaeError::HttpError(format!("failed to build revocation request: {e}")))?;

    let agent = ureq::Agent::new_with_defaults();
    agent
        .run(req)
        .map_err(|e| SfaeError::HttpError(format!("token revocation request failed: {e}")))?;

    Ok(())
}

/// Generate a random state string for CSRF protection.
pub fn generate_state() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

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

fn match_preset(domain: &str) -> Option<ProviderPreset> {
    match domain {
        "googleapis.com" => Some(ProviderPreset {
            client_id: "648921945993-gfl5j7ksi200dt5t6k3qebid4b7alc4k.apps.googleusercontent.com",
            client_secret: option_env!("SFAE_GOOGLE_CLIENT_SECRET"),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            revocation_url: Some("https://oauth2.googleapis.com/revoke"),
        }),
        _ => None,
    }
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
        let url = build_authorization_url(
            "https://example.com/auth",
            "my_client",
            "http://127.0.0.1:8080/callback",
            "challenge123",
            Some("read write"),
            "state456",
        );
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
        let url = build_authorization_url(
            "https://example.com/auth",
            "my_client",
            "http://127.0.0.1:8080/callback",
            "challenge123",
            None,
            "state456",
        );
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
        assert_eq!(metadata_key("example.com", None), "example.com");
    }

    #[test]
    fn metadata_key_with_username() {
        assert_eq!(
            metadata_key("example.com", Some("alice")),
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
        let map = read_all_from(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        write_all_to(&path, &map).unwrap();

        let loaded = read_all_from(&path).unwrap();
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
            metadata_key("google.com", None),
            OAuthMetadata {
                token_url: "https://oauth2.googleapis.com/token".into(),
                client_id: "goog-123".into(),
                revocation_url: None,
            },
        );
        write_all_to(&path, &map).unwrap();

        // Read back
        let loaded = read_all_from(&path).unwrap();
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
        write_all_to(&path, &map).unwrap();

        // Overwrite with new metadata
        let mut map = read_all_from(&path).unwrap();
        map.insert(
            "d.com".to_string(),
            OAuthMetadata {
                token_url: "https://new.example.com/token".into(),
                client_id: "new-id".into(),
                revocation_url: None,
            },
        );
        write_all_to(&path, &map).unwrap();

        let loaded = read_all_from(&path).unwrap();
        assert_eq!(loaded["d.com"].client_id, "new-id");
    }

    #[test]
    fn lookup_exact_match() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = lookup_in_map(&map, "example.com", None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, "my-client-id");
    }

    #[test]
    fn lookup_parent_domain_fallback() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = lookup_in_map(&map, "api.example.com", None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, "my-client-id");
    }

    #[test]
    fn lookup_deep_subdomain_fallback() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), sample_metadata());
        let found = lookup_in_map(&map, "a.b.example.com", None);
        assert!(found.is_some());
    }

    #[test]
    fn lookup_stops_at_two_labels() {
        let mut map = HashMap::new();
        map.insert("com".to_string(), sample_metadata());
        let found = lookup_in_map(&map, "api.example.com", None);
        assert!(found.is_none());
    }

    #[test]
    fn lookup_not_found() {
        let map = HashMap::new();
        let found = lookup_in_map(&map, "example.com", None);
        assert!(found.is_none());
    }

    #[test]
    fn lookup_with_username() {
        let mut map = HashMap::new();
        map.insert("example.com:alice".to_string(), sample_metadata());

        // With matching username
        let found = lookup_in_map(&map, "example.com", Some("alice"));
        assert!(found.is_some());

        // Without username — should not match
        let found = lookup_in_map(&map, "example.com", None);
        assert!(found.is_none());
    }

    // --- refresh_access_token tests ---

    #[test]
    fn refresh_body_without_client_secret() {
        let body = build_refresh_body("my-refresh-tok", "my-client", None);
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=my-refresh-tok&client_id=my-client"
        );
    }

    #[test]
    fn refresh_body_with_client_secret() {
        let body = build_refresh_body("my-refresh-tok", "my-client", Some("s3cret"));
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=my-refresh-tok&client_id=my-client&client_secret=s3cret"
        );
    }

    #[test]
    fn refresh_body_encodes_special_chars() {
        let body = build_refresh_body("tok&en=val", "id with spaces", Some("sec/ret"));
        assert!(body.contains("refresh_token=tok%26en%3Dval"));
        assert!(body.contains("client_id=id%20with%20spaces"));
        assert!(body.contains("client_secret=sec%2Fret"));
    }

    // --- revoke_token tests ---

    #[test]
    fn revocation_body_basic() {
        let body = build_revocation_body("ya29.some-access-token");
        assert_eq!(body, "token=ya29.some-access-token");
    }

    #[test]
    fn revocation_body_encodes_special_chars() {
        let body = build_revocation_body("tok&en=val ue");
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
        write_all_to(&path, &map).unwrap();

        // Remove one
        let mut map = read_all_from(&path).unwrap();
        map.remove("a.com");
        write_all_to(&path, &map).unwrap();

        let loaded = read_all_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("b.com"));
        assert!(!loaded.contains_key("a.com"));
    }
}
