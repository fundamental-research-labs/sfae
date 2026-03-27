use std::collections::HashMap;

use regex::Regex;

use crate::error::SfaeError;
use crate::secret::SecretHandle;
use crate::store::SecretStore;

/// An HTTP request to be proxied, with possible `{{sfae:name}}` placeholders.
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

/// Regex pattern matching `{{sfae:name}}` placeholders.
const PLACEHOLDER_PATTERN: &str = r"\{\{sfae:([a-zA-Z0-9_-]+)\}\}";

/// Find all `{{sfae:name}}` placeholders in a string.
pub fn find_placeholders(text: &str) -> Vec<SecretHandle> {
    let re = Regex::new(PLACEHOLDER_PATTERN).expect("valid regex");
    re.captures_iter(text)
        .map(|cap| SecretHandle {
            name: cap[1].to_string(),
        })
        .collect()
}

/// Replace all `{{sfae:name}}` placeholders in `text` with credential values
/// from `store`. Fails fast on the first missing credential.
pub fn resolve_placeholders(text: &str, store: &dyn SecretStore) -> Result<String, SfaeError> {
    let re = Regex::new(PLACEHOLDER_PATTERN).expect("valid regex");
    let mut result = text.to_string();
    // Collect matches first to avoid borrow issues during replacement.
    let matches: Vec<(String, String)> = re
        .captures_iter(text)
        .map(|cap| (cap[0].to_string(), cap[1].to_string()))
        .collect();
    for (full_match, name) in matches {
        let credential = store.get(&name)?;
        result = result.replace(&full_match, credential.secret_value());
    }
    Ok(result)
}

/// Resolve all placeholders in the request and execute the HTTP call via ureq.
pub fn execute(request: &ProxyRequest, store: &dyn SecretStore) -> Result<ProxyResponse, SfaeError> {
    // Resolve placeholders in URL, headers, and body.
    let url = resolve_placeholders(&request.url, store)?;
    let headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(k, v)| Ok((k.clone(), resolve_placeholders(v, store)?)))
        .collect::<Result<_, SfaeError>>()?;
    let body = match &request.body {
        Some(b) => Some(resolve_placeholders(b, store)?),
        None => None,
    };

    // Build the HTTP request.
    let mut builder = ureq::http::Request::builder()
        .method(request.method.as_str())
        .uri(&url);
    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let agent = ureq::Agent::new_with_defaults();
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

    // Read response.
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
    use crate::credential::Credential;
    use crate::store::InMemoryStore;

    fn store_with_token(name: &str, value: &str) -> InMemoryStore {
        let mut store = InMemoryStore::new();
        store
            .set(
                name,
                &Credential::AccessToken {
                    token: value.to_string(),
                },
            )
            .unwrap();
        store
    }

    // -- find_placeholders tests --

    #[test]
    fn find_no_placeholders() {
        let handles = find_placeholders("no placeholders here");
        assert!(handles.is_empty());
    }

    #[test]
    fn find_single_placeholder() {
        let handles = find_placeholders("Bearer {{sfae:github_token}}");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].name, "github_token");
    }

    #[test]
    fn find_multiple_placeholders() {
        let text = "{{sfae:a}} and {{sfae:b-c}} and {{sfae:d_1}}";
        let handles = find_placeholders(text);
        assert_eq!(handles.len(), 3);
        assert_eq!(handles[0].name, "a");
        assert_eq!(handles[1].name, "b-c");
        assert_eq!(handles[2].name, "d_1");
    }

    #[test]
    fn find_ignores_malformed_placeholders() {
        let handles = find_placeholders("{{sfae:}} and {{sfae: space}} and {{other:foo}}");
        assert!(handles.is_empty());
    }

    // -- resolve_placeholders tests --

    #[test]
    fn resolve_single() {
        let store = store_with_token("tok", "secret123");
        let result = resolve_placeholders("Bearer {{sfae:tok}}", &store).unwrap();
        assert_eq!(result, "Bearer secret123");
    }

    #[test]
    fn resolve_multiple() {
        let mut store = InMemoryStore::new();
        store
            .set(
                "a",
                &Credential::AccessToken {
                    token: "AAA".to_string(),
                },
            )
            .unwrap();
        store
            .set(
                "b",
                &Credential::AccessToken {
                    token: "BBB".to_string(),
                },
            )
            .unwrap();
        let result = resolve_placeholders("{{sfae:a}}/{{sfae:b}}", &store).unwrap();
        assert_eq!(result, "AAA/BBB");
    }

    #[test]
    fn resolve_missing_credential_fails() {
        let store = InMemoryStore::new();
        let err = resolve_placeholders("{{sfae:missing}}", &store).unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    #[test]
    fn resolve_no_placeholders_passes_through() {
        let store = InMemoryStore::new();
        let result = resolve_placeholders("plain text", &store).unwrap();
        assert_eq!(result, "plain text");
    }
}
