use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::SfaeError;

/// OAuth2 token response from the token endpoint.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
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
        "{auth_url}{sep}client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256&state={}",
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

/// Generate a random state string for CSRF protection.
pub fn generate_state() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
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
}
