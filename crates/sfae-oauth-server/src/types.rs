//! Request and response payloads exposed by the OAuth service APIs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Internal request to create an OAuth browser session.
#[derive(Deserialize)]
pub(crate) struct CreateSessionReq {
    pub(crate) provider: String,
    pub(crate) user_id: String,
    #[serde(default)]
    pub(crate) domain: Option<String>,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) return_url: Option<String>,
}

/// Response containing the provider URL the browser should visit.
#[derive(Serialize)]
pub(crate) struct CreateSessionResp {
    pub(crate) session_id: Uuid,
    pub(crate) authorization_url: String,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Public health-check response.
#[derive(Serialize)]
pub(crate) struct HealthResp {
    pub(crate) status: &'static str,
}

/// Internal session status response for app polling and smoke tests.
#[derive(Serialize)]
pub(crate) struct SessionStatusResp {
    pub(crate) id: Uuid,
    pub(crate) provider: String,
    pub(crate) user_id: String,
    pub(crate) domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_id: Option<Uuid>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Public local-CLI request to start an OAuth handoff session.
#[derive(Deserialize)]
pub(crate) struct CreateLocalSessionReq {
    pub(crate) provider: String,
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
    pub(crate) redeem_challenge: String,
    pub(crate) redeem_challenge_method: String,
    pub(crate) return_url: String,
}

/// Public local-CLI session start response.
#[derive(Serialize)]
pub(crate) struct CreateLocalSessionResp {
    pub(crate) session_id: Uuid,
    pub(crate) authorization_url: String,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Public local-CLI status response. It intentionally omits user id and token material.
#[derive(Serialize)]
pub(crate) struct LocalSessionStatusResp {
    pub(crate) session_id: Uuid,
    pub(crate) provider: String,
    pub(crate) domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_id: Option<Uuid>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Public local-CLI one-time redeem request.
#[derive(Deserialize)]
pub(crate) struct RedeemLocalSessionReq {
    pub(crate) redeem_verifier: String,
    pub(crate) completion_verifier: String,
}

/// Credential material returned once to the trusted local CLI.
#[derive(Deserialize, Serialize)]
pub(crate) struct RedeemedCredentialResp {
    pub(crate) values: std::collections::HashMap<String, String>,
    pub(crate) internal: std::collections::HashMap<String, String>,
    pub(crate) metadata: std::collections::HashMap<String, String>,
}

/// Public local-CLI request to refresh a locally stored OAuth token.
#[derive(Deserialize)]
pub(crate) struct RefreshLocalCredentialReq {
    pub(crate) provider: String,
    pub(crate) broker_credential_id: Uuid,
    pub(crate) broker_credential_secret: String,
    pub(crate) refresh_token: String,
}

/// Public local-CLI request to revoke locally stored OAuth token material.
#[derive(Deserialize)]
pub(crate) struct RevokeLocalCredentialReq {
    pub(crate) provider: String,
    pub(crate) broker_credential_id: Uuid,
    pub(crate) broker_credential_secret: String,
    #[serde(default)]
    pub(crate) access_token: Option<String>,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
}
