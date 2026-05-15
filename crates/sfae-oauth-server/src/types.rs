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
