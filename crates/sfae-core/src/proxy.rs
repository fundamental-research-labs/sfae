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
