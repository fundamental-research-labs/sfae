use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::credential::{CredentialType, credential_key};
use crate::error::SfaeError;
use crate::store::{SecretStore, list_credential_types};

/// An HTTP request with possible `{KEY}` placeholders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// The HTTP response returned after proxying.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Regex matching `{KEY}` placeholders where KEY is `[A-Z][A-Z0-9_]*`.
static DYNAMIC_PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([A-Z][A-Z0-9_]*)\}").unwrap());

// -- Legacy placeholder support (used by request.rs until phase 1c) ----------

/// Known placeholder patterns mapped to their credential types (legacy `-TYPE-` syntax).
const PLACEHOLDERS: &[(&str, CredentialType)] = &[
    ("-ACCESS_TOKEN-", CredentialType::AccessToken),
    ("-REFRESH_TOKEN-", CredentialType::RefreshToken),
    ("-API_KEY-", CredentialType::ApiKey),
    ("-PASSWORD-", CredentialType::Password),
    ("-USERNAME-", CredentialType::Username),
];

/// Find all credential type placeholders present in a string (legacy `-TYPE-` syntax).
pub fn find_placeholders(text: &str) -> Vec<CredentialType> {
    let mut found = Vec::new();
    for (pattern, cred_type) in PLACEHOLDERS {
        if text.contains(pattern) {
            found.push(*cred_type);
        }
    }
    found
}

// -- Dynamic `{KEY}` placeholder system --------------------------------------

/// Find all `{KEY}` dynamic placeholders in a string.
///
/// Returns deduplicated field names in order of first appearance.
pub fn find_dynamic_placeholders(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for cap in DYNAMIC_PLACEHOLDER_RE.captures_iter(text) {
        let key = cap[1].to_string();
        if !found.contains(&key) {
            found.push(key);
        }
    }
    found
}

/// Replace all `{KEY}` patterns in `text` with values from the map.
pub fn resolve_placeholders_from_map(
    text: &str,
    values: &HashMap<String, String>,
) -> Result<String, SfaeError> {
    let placeholders = find_dynamic_placeholders(text);
    if placeholders.is_empty() {
        return Ok(text.to_string());
    }
    let mut result = text.to_string();
    for key in &placeholders {
        let value = values
            .get(key.as_str())
            .ok_or_else(|| SfaeError::CredentialNotFound(key.clone()))?;
        result = result.replace(&format!("{{{key}}}"), value);
    }
    Ok(result)
}

/// Replace all `{KEY}` patterns with `***`, verifying each credential exists in the map.
pub fn mask_placeholders_from_map(
    text: &str,
    values: &HashMap<String, String>,
) -> Result<String, SfaeError> {
    let placeholders = find_dynamic_placeholders(text);
    if placeholders.is_empty() {
        return Ok(text.to_string());
    }
    let mut result = text.to_string();
    for key in &placeholders {
        if !values.contains_key(key.as_str()) {
            return Err(SfaeError::CredentialNotFound(key.clone()));
        }
        result = result.replace(&format!("{{{key}}}"), "***");
    }
    Ok(result)
}

/// Fetch all credentials for a domain as a HashMap, with domain fallback.
///
/// Walks up parent domains if no credentials are found at the exact domain.
/// Returns an empty map if no credentials exist anywhere in the domain chain.
pub fn get_credentials_map(
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<HashMap<String, String>, SfaeError> {
    // Try exact domain
    let types = list_credential_types(store, domain, username)?;
    if !types.is_empty() {
        return build_credentials_map(store, domain, username, &types);
    }

    // Walk up parent domains: api.github.com -> github.com
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent: Vec<&str> = parts[i..].to_vec();
        if parent.len() < 2 {
            break;
        }
        let parent_domain = parent.join(".");
        let types = list_credential_types(store, &parent_domain, username)?;
        if !types.is_empty() {
            return build_credentials_map(store, &parent_domain, username, &types);
        }
    }

    Ok(HashMap::new())
}

fn build_credentials_map(
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
    types: &[String],
) -> Result<HashMap<String, String>, SfaeError> {
    let mut map = HashMap::new();
    for type_str in types {
        let key = match username {
            Some(user) => format!("{domain}_{user}_{type_str}"),
            None => format!("{domain}_{type_str}"),
        };
        let value = store.get(&key)?;
        map.insert(type_str.clone(), value);
    }
    Ok(map)
}

// -- Legacy per-field fallback (used by request.rs OAuth refresh) -------------

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

    // Walk up parent domains: api.github.com -> github.com
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

// -- Public resolution API ---------------------------------------------------

/// Replace all `{KEY}` placeholders in `text` with credential values from the store.
pub fn resolve_placeholders(
    text: &str,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<String, SfaeError> {
    let map = get_credentials_map(store, domain, username)?;
    resolve_placeholders_from_map(text, &map)
}

/// Replace all `{KEY}` placeholders with `***`, verifying each credential exists.
pub fn resolve_and_mask(
    text: &str,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<String, SfaeError> {
    let map = get_credentials_map(store, domain, username)?;
    mask_placeholders_from_map(text, &map)
}

/// Extract the host from a URL string.
///
/// E.g., `"https://api.github.com/repos"` -> `"api.github.com"`
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
///
/// Fetches the credential map once and resolves all `{KEY}` patterns across
/// URL, headers, and body from a single map lookup.
pub fn execute(
    request: &ProxyRequest,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<ProxyResponse, SfaeError> {
    let map = get_credentials_map(store, domain, username)?;

    let url = resolve_placeholders_from_map(&request.url, &map)?;
    let headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(k, v)| Ok((k.clone(), resolve_placeholders_from_map(v, &map)?)))
        .collect::<Result<_, SfaeError>>()?;
    let body = match &request.body {
        Some(b) => Some(resolve_placeholders_from_map(b, &map)?),
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

    // -- find_dynamic_placeholders tests --

    #[test]
    fn find_dynamic_no_placeholders() {
        assert!(find_dynamic_placeholders("no placeholders here").is_empty());
    }

    #[test]
    fn find_dynamic_single() {
        let found = find_dynamic_placeholders("Bearer {ACCESS_TOKEN}");
        assert_eq!(found, vec!["ACCESS_TOKEN"]);
    }

    #[test]
    fn find_dynamic_multiple() {
        let found = find_dynamic_placeholders("{API_KEY} and {PASSWORD}");
        assert_eq!(found, vec!["API_KEY", "PASSWORD"]);
    }

    #[test]
    fn find_dynamic_deduplicates() {
        let found = find_dynamic_placeholders("{HOST}...{HOST}");
        assert_eq!(found, vec!["HOST"]);
    }

    #[test]
    fn find_dynamic_ignores_lowercase() {
        // JSON-like braces with lowercase keys should not match
        assert!(find_dynamic_placeholders(r#"{"key": "val"}"#).is_empty());
    }

    #[test]
    fn find_dynamic_ignores_empty_braces() {
        assert!(find_dynamic_placeholders("{}").is_empty());
    }

    #[test]
    fn find_dynamic_mixed_content() {
        let found =
            find_dynamic_placeholders(r#"https://{HOST}:8443/?db={DATABASE}&q={"type":"x"}"#);
        assert_eq!(found, vec!["HOST", "DATABASE"]);
    }

    // -- resolve_placeholders_from_map tests --

    #[test]
    fn resolve_from_map_single() {
        let mut map = HashMap::new();
        map.insert("API_KEY".to_string(), "ghk_abc123".to_string());
        let result = resolve_placeholders_from_map("Bearer {API_KEY}", &map).unwrap();
        assert_eq!(result, "Bearer ghk_abc123");
    }

    #[test]
    fn resolve_from_map_multiple() {
        let mut map = HashMap::new();
        map.insert("HOST".to_string(), "ch.cloud".to_string());
        map.insert("PASSWORD".to_string(), "secret".to_string());
        let result =
            resolve_placeholders_from_map("https://{HOST}/?pw={PASSWORD}", &map).unwrap();
        assert_eq!(result, "https://ch.cloud/?pw=secret");
    }

    #[test]
    fn resolve_from_map_missing_key() {
        let map = HashMap::new();
        let err = resolve_placeholders_from_map("{MISSING}", &map).unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(ref k) if k == "MISSING"));
    }

    #[test]
    fn resolve_from_map_no_placeholders() {
        let map = HashMap::new();
        let result = resolve_placeholders_from_map("plain text", &map).unwrap();
        assert_eq!(result, "plain text");
    }

    // -- mask_placeholders_from_map tests --

    #[test]
    fn mask_from_map_replaces_with_stars() {
        let mut map = HashMap::new();
        map.insert("API_KEY".to_string(), "ghk_abc123".to_string());
        let result = mask_placeholders_from_map("key={API_KEY}", &map).unwrap();
        assert_eq!(result, "key=***");
    }

    #[test]
    fn mask_from_map_missing_key() {
        let map = HashMap::new();
        let err = mask_placeholders_from_map("{MISSING}", &map).unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    // -- get_credentials_map tests --

    #[test]
    fn credentials_map_exact_domain() {
        let store = test_store();
        let map = get_credentials_map(&store, "github.com", None).unwrap();
        assert_eq!(map.get("API_KEY").unwrap(), "ghk_abc123");
        assert_eq!(map.get("ACCESS_TOKEN").unwrap(), "ght_xyz789");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn credentials_map_subdomain_fallback() {
        let store = test_store();
        let map = get_credentials_map(&store, "api.github.com", None).unwrap();
        assert_eq!(map.get("API_KEY").unwrap(), "ghk_abc123");
        assert_eq!(map.get("ACCESS_TOKEN").unwrap(), "ght_xyz789");
    }

    #[test]
    fn credentials_map_with_username() {
        let store = test_store();
        let map = get_credentials_map(&store, "github.com", Some("user1")).unwrap();
        assert_eq!(map.get("PASSWORD").unwrap(), "secret");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn credentials_map_empty_when_not_found() {
        let store = InMemoryStore::new();
        let map = get_credentials_map(&store, "unknown.com", None).unwrap();
        assert!(map.is_empty());
    }

    // -- resolve_placeholders (full stack) tests --

    #[test]
    fn resolve_single() {
        let store = test_store();
        let result =
            resolve_placeholders("Bearer {API_KEY}", &store, "github.com", None).unwrap();
        assert_eq!(result, "Bearer ghk_abc123");
    }

    #[test]
    fn resolve_with_username() {
        let store = test_store();
        let result =
            resolve_placeholders("pw={PASSWORD}", &store, "github.com", Some("user1")).unwrap();
        assert_eq!(result, "pw=secret");
    }

    #[test]
    fn resolve_missing_credential_fails() {
        let store = InMemoryStore::new();
        let err = resolve_placeholders("{API_KEY}", &store, "github.com", None).unwrap_err();
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
        let result = resolve_and_mask("key={API_KEY}", &store, "github.com", None).unwrap();
        assert_eq!(result, "key=***");
    }

    // -- extract_host tests --

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

    // -- Domain fallback tests (legacy + map-based) --

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
            resolve_placeholders("Bearer {ACCESS_TOKEN}", &store, "api.github.com", None).unwrap();
        assert_eq!(result, "Bearer ght_xyz789");
    }

    #[test]
    fn mask_subdomain_placeholders() {
        let store = test_store();
        let result = resolve_and_mask("key={API_KEY}", &store, "api.github.com", None).unwrap();
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

    // -- Custom field types (the whole point of dynamic placeholders) --

    #[test]
    fn resolve_custom_fields() {
        let mut store = InMemoryStore::new();
        store.set("ch.cloud_HOST", "analytics.ch.cloud").unwrap();
        store.set("ch.cloud_PORT", "8443").unwrap();
        store.set("ch.cloud_USERNAME", "admin").unwrap();
        store.set("ch.cloud_PASSWORD", "hunter2").unwrap();
        store.set("ch.cloud_DATABASE", "default").unwrap();

        let result = resolve_placeholders(
            "https://{HOST}:{PORT}/?database={DATABASE}&user={USERNAME}&password={PASSWORD}",
            &store,
            "ch.cloud",
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            "https://analytics.ch.cloud:8443/?database=default&user=admin&password=hunter2"
        );
    }
}
