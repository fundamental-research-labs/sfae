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
pub(crate) struct CreatePendingOAuthReq {
    pub(crate) state: String,
    pub(crate) user_id: String,
    pub(crate) verifier: String,
    pub(crate) domain: String,
    pub(crate) token_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) redirect_origin: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct PendingOAuthRow {
    pub(crate) state: String,
    pub(crate) user_id: String,
    pub(crate) verifier: String,
    pub(crate) domain: String,
    pub(crate) token_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) redirect_origin: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RefreshReq {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) domain: Option<String>,
}
