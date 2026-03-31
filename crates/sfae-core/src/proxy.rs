use std::collections::HashMap;

use crate::credential::{CredentialType, credential_key};
use crate::error::SfaeError;
use crate::store::SecretStore;

/// An HTTP request with possible `-TYPE-` placeholders.
#[derive(Debug, Clone)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// The HTTP response returned after proxying.
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Known placeholder patterns mapped to their credential types.
const PLACEHOLDERS: &[(&str, CredentialType)] = &[
    ("-ACCESS_TOKEN-", CredentialType::AccessToken),
    ("-REFRESH_TOKEN-", CredentialType::RefreshToken),
    ("-API_KEY-", CredentialType::ApiKey),
    ("-PASSWORD-", CredentialType::Password),
];

/// Find all credential type placeholders present in a string.
pub fn find_placeholders(text: &str) -> Vec<CredentialType> {
    let mut found = Vec::new();
    for (pattern, cred_type) in PLACEHOLDERS {
        if text.contains(pattern) {
            found.push(*cred_type);
        }
    }
    found
}

/// Look up a credential, falling back to parent domains when not found.
///
/// For example, if `domain` is `api.github.com` and no credential exists for
/// that exact domain, this will try `github.com` before giving up. Stops when
/// the domain has fewer than 2 labels (never tries bare TLDs).
pub fn get_credential_with_fallback(
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
    cred_type: CredentialType,
) -> Result<String, SfaeError> {
    let key = credential_key(domain, username, cred_type);
    match store.get(&key) {
        Ok(value) => return Ok(value),
        Err(SfaeError::CredentialNotFound(_)) => {}
        Err(e) => return Err(e),
    }

    // Walk up parent domains: api.github.com → github.com
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent: Vec<&str> = parts[i..].to_vec();
        if parent.len() < 2 {
            break;
        }
        let parent_domain = parent.join(".");
        let key = credential_key(&parent_domain, username, cred_type);
        match store.get(&key) {
            Ok(value) => return Ok(value),
            Err(SfaeError::CredentialNotFound(_)) => continue,
            Err(e) => return Err(e),
        }
    }

    Err(SfaeError::CredentialNotFound(credential_key(
        domain, username, cred_type,
    )))
}

/// Replace all `-TYPE-` placeholders in `text` with credential values from the store.
pub fn resolve_placeholders(
    text: &str,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<String, SfaeError> {
    let mut result = text.to_string();
    for (pattern, cred_type) in PLACEHOLDERS {
        if result.contains(pattern) {
            let value = get_credential_with_fallback(store, domain, username, *cred_type)?;
            result = result.replace(pattern, &value);
        }
    }
    Ok(result)
}

/// Replace all `-TYPE-` placeholders with `***`, verifying each credential exists.
pub fn resolve_and_mask(
    text: &str,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<String, SfaeError> {
    let mut result = text.to_string();
    for (pattern, cred_type) in PLACEHOLDERS {
        if result.contains(pattern) {
            get_credential_with_fallback(store, domain, username, *cred_type)?;
            result = result.replace(pattern, "***");
        }
    }
    Ok(result)
}

/// Extract the host from a URL string.
///
/// E.g., `"https://api.github.com/repos"` → `"api.github.com"`
pub fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Resolve all placeholders in the request and execute the HTTP call.
pub fn execute(
    request: &ProxyRequest,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<ProxyResponse, SfaeError> {
    let url = resolve_placeholders(&request.url, store, domain, username)?;
    let headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(k, v)| Ok((k.clone(), resolve_placeholders(v, store, domain, username)?)))
        .collect::<Result<_, SfaeError>>()?;
    let body = match &request.body {
        Some(b) => Some(resolve_placeholders(b, store, domain, username)?),
        None => None,
    };

    let mut builder = ureq::http::Request::builder()
        .method(request.method.as_str())
        .uri(&url);
    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = if let Some(body) = body {
        let req = builder
            .body(body)
            .map_err(|e| SfaeError::HttpError(e.to_string()))?;
        agent
            .run(req)
            .map_err(|e| SfaeError::HttpError(e.to_string()))?
    } else {
        let req = builder
            .body(())
            .map_err(|e| SfaeError::HttpError(e.to_string()))?;
        agent
            .run(req)
            .map_err(|e| SfaeError::HttpError(e.to_string()))?
    };

    let status = response.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (name, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(name.to_string(), v.to_string());
        }
    }
    let resp_body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| SfaeError::HttpError(e.to_string()))?;

    Ok(ProxyResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    fn test_store() -> InMemoryStore {
        let mut store = InMemoryStore::new();
        store.set("github.com_API_KEY", "ghk_abc123").unwrap();
        store.set("github.com_ACCESS_TOKEN", "ght_xyz789").unwrap();
        store.set("github.com_user1_PASSWORD", "secret").unwrap();
        store
    }

    #[test]
    fn find_no_placeholders() {
        assert!(find_placeholders("no placeholders here").is_empty());
    }

    #[test]
    fn find_single_placeholder() {
        let found = find_placeholders("Bearer -ACCESS_TOKEN-");
        assert_eq!(found, vec![CredentialType::AccessToken]);
    }

    #[test]
    fn find_multiple_placeholders() {
        let found = find_placeholders("-API_KEY- and -PASSWORD-");
        assert_eq!(
            found,
            vec![CredentialType::ApiKey, CredentialType::Password]
        );
    }

    #[test]
    fn resolve_single() {
        let store = test_store();
        let result = resolve_placeholders("Bearer -API_KEY-", &store, "github.com", None).unwrap();
        assert_eq!(result, "Bearer ghk_abc123");
    }

    #[test]
    fn resolve_with_username() {
        let store = test_store();
        let result =
            resolve_placeholders("pw=-PASSWORD-", &store, "github.com", Some("user1")).unwrap();
        assert_eq!(result, "pw=secret");
    }

    #[test]
    fn resolve_missing_credential_fails() {
        let store = InMemoryStore::new();
        let err = resolve_placeholders("-API_KEY-", &store, "github.com", None).unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    #[test]
    fn resolve_no_placeholders_passes_through() {
        let store = InMemoryStore::new();
        let result = resolve_placeholders("plain text", &store, "github.com", None).unwrap();
        assert_eq!(result, "plain text");
    }

    #[test]
    fn mask_replaces_with_stars() {
        let store = test_store();
        let result = resolve_and_mask("key=-API_KEY-", &store, "github.com", None).unwrap();
        assert_eq!(result, "key=***");
    }

    #[test]
    fn extract_host_https() {
        assert_eq!(
            extract_host("https://api.github.com/repos"),
            Some("api.github.com".to_string())
        );
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("http://localhost:8080/api"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn extract_host_no_scheme() {
        assert_eq!(extract_host("not-a-url"), None);
    }

    #[test]
    fn extract_host_bare_domain() {
        assert_eq!(
            extract_host("https://example.com"),
            Some("example.com".to_string())
        );
    }

    // --- Domain fallback tests ---

    #[test]
    fn fallback_exact_domain_match() {
        let store = test_store();
        let val = get_credential_with_fallback(&store, "github.com", None, CredentialType::ApiKey)
            .unwrap();
        assert_eq!(val, "ghk_abc123");
    }

    #[test]
    fn fallback_subdomain_to_parent() {
        let store = test_store();
        let val = get_credential_with_fallback(
            &store,
            "api.github.com",
            None,
            CredentialType::AccessToken,
        )
        .unwrap();
        assert_eq!(val, "ght_xyz789");
    }

    #[test]
    fn fallback_multi_level_subdomain() {
        let mut store = InMemoryStore::new();
        store.set("example.com_API_KEY", "deep_key").unwrap();
        let val =
            get_credential_with_fallback(&store, "a.b.example.com", None, CredentialType::ApiKey)
                .unwrap();
        assert_eq!(val, "deep_key");
    }

    #[test]
    fn fallback_stops_at_two_labels() {
        // Credential stored under "com" should NOT be found via fallback
        let mut store = InMemoryStore::new();
        store.set("com_API_KEY", "bad").unwrap();
        let err =
            get_credential_with_fallback(&store, "api.github.com", None, CredentialType::ApiKey)
                .unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    #[test]
    fn fallback_not_found_on_any_level() {
        let store = InMemoryStore::new();
        let err = get_credential_with_fallback(
            &store,
            "api.github.com",
            None,
            CredentialType::AccessToken,
        )
        .unwrap_err();
        match err {
            SfaeError::CredentialNotFound(key) => {
                assert_eq!(key, "api.github.com_ACCESS_TOKEN");
            }
            _ => panic!("expected CredentialNotFound"),
        }
    }

    #[test]
    fn fallback_with_username() {
        let store = test_store();
        let val = get_credential_with_fallback(
            &store,
            "api.github.com",
            Some("user1"),
            CredentialType::Password,
        )
        .unwrap();
        assert_eq!(val, "secret");
    }

    #[test]
    fn resolve_subdomain_placeholders() {
        let store = test_store();
        let result =
            resolve_placeholders("Bearer -ACCESS_TOKEN-", &store, "api.github.com", None).unwrap();
        assert_eq!(result, "Bearer ght_xyz789");
    }

    #[test]
    fn mask_subdomain_placeholders() {
        let store = test_store();
        let result = resolve_and_mask("key=-API_KEY-", &store, "api.github.com", None).unwrap();
        assert_eq!(result, "key=***");
    }

    #[test]
    fn fallback_prefers_exact_match() {
        let mut store = InMemoryStore::new();
        store.set("api.github.com_API_KEY", "exact").unwrap();
        store.set("github.com_API_KEY", "parent").unwrap();
        let val =
            get_credential_with_fallback(&store, "api.github.com", None, CredentialType::ApiKey)
                .unwrap();
        assert_eq!(val, "exact");
    }
}
