//! Request and response payload types shared across the HTTP handlers.
//!
//! Kept in one module so the wire-format surface is easy to audit at a glance.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct StoreCredentialReq {
    pub(crate) domain: String,
    pub(crate) label: Option<String>,
    pub(crate) values: HashMap<String, String>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateCredentialReq {
    pub(crate) values: HashMap<String, String>,
}

#[derive(Deserialize)]
pub(crate) struct MintTokenReq {
    pub(crate) user_id: String,
}

#[derive(Serialize)]
pub(crate) struct OkResponse {
    pub(crate) ok: bool,
}

#[derive(Serialize)]
pub(crate) struct StoreOkResponse {
    pub(crate) ok: bool,
    pub(crate) id: String,
}

#[derive(Serialize)]
pub(crate) struct CredentialEntry {
    pub(crate) id: String,
    pub(crate) domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    pub(crate) keys: Vec<String>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub(crate) struct ListResponse {
    pub(crate) credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    pub(crate) token: String,
}

#[derive(Serialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: String,
}

#[derive(Deserialize)]
pub(crate) struct HostedOAuthSessionReq {
    pub(crate) provider: String,
    #[serde(default)]
    pub(crate) domain: Option<String>,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct HostedOAuthSessionResp {
    pub(crate) session_id: String,
    pub(crate) authorization_url: String,
    pub(crate) expires_at: String,
}

#[derive(Serialize)]
pub(crate) struct HostedOAuthStatusResp {
    pub(crate) session_id: String,
    pub(crate) provider: String,
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) error_code: Option<String>,
    #[serde(default)]
    pub(crate) provider_subject: Option<String>,
    #[serde(default)]
    pub(crate) credential_id: Option<String>,
    pub(crate) expires_at: String,
}

#[derive(Serialize)]
pub(crate) struct BrokerCreateSessionReq<'a> {
    pub(crate) provider: &'a str,
    pub(crate) user_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) scopes: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct BrokerCreateSessionResp {
    pub(crate) session_id: String,
    pub(crate) authorization_url: String,
    pub(crate) expires_at: String,
}

#[derive(Deserialize)]
pub(crate) struct BrokerSessionStatusResp {
    pub(crate) id: String,
    pub(crate) provider: String,
    pub(crate) user_id: String,
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) error_code: Option<String>,
    #[serde(default)]
    pub(crate) provider_subject: Option<String>,
    #[serde(default)]
    pub(crate) credential_id: Option<String>,
    pub(crate) expires_at: String,
}
