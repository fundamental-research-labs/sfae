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
