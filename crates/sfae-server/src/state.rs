//! Shared application state plus authentication helpers used across handlers.
//!
//! `AppState` carries the database pool, auth secrets, and hosted OAuth broker config.
//! The auth helpers here centralize the bearer/internal extraction pattern
//! that handlers would otherwise repeat for each route.

use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

pub(crate) struct AppState {
    pub(crate) pool: PgPool,
    pub(crate) jwt_secret: String,
    pub(crate) internal_auth_secret: String,
    pub(crate) oauth_broker_url: String,
    pub(crate) http: reqwest::Client,
}

/// The two authentication modes.
pub(crate) enum AuthInfo {
    /// Authenticated via X-Internal-Auth — can read + write + delete.
    Internal { user_id: String },
    /// Authenticated via Bearer JWT — read only.
    Bearer { user_id: String },
}

impl AuthInfo {
    pub(crate) fn user_id(&self) -> &str {
        match self {
            AuthInfo::Internal { user_id } | AuthInfo::Bearer { user_id } => user_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) sub: String,
    pub(crate) exp: usize,
    pub(crate) iat: usize,
}

impl AppState {
    pub(crate) fn extract_auth(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthInfo, (StatusCode, String)> {
        if let Some(val) = headers.get("x-internal-auth") {
            let val = val.to_str().unwrap_or("");
            if val != self.internal_auth_secret {
                return Err((StatusCode::UNAUTHORIZED, "Invalid internal auth".into()));
            }
            let user_id = headers
                .get("x-user-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "X-User-Id header required with internal auth".into(),
                    )
                })?;
            return Ok(AuthInfo::Internal { user_id });
        }

        if let Some(val) = headers.get("authorization") {
            let val = val.to_str().unwrap_or("");
            if let Some(token) = val.strip_prefix("Bearer ") {
                let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
                let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
                validation.set_required_spec_claims(&["sub", "exp"]);
                let data = decode::<Claims>(token, &key, &validation)
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid JWT: {e}")))?;
                return Ok(AuthInfo::Bearer {
                    user_id: data.claims.sub,
                });
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Authentication required".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    #[test]
    fn jwt_roundtrip() {
        let secret = "test-secret-at-least-32-characters-long";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test-user".to_string(),
            iat: now,
            exp: now + 3600,
        };

        let key = EncodingKey::from_secret(secret.as_bytes());
        let token = encode(&Header::default(), &claims, &key).unwrap();

        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp"]);
        let decoded = decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims.sub, "test-user");
    }
}
