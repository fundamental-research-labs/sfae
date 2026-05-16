//! Public local-CLI OAuth handoff endpoints for the hosted broker.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::crypto::{generate_state, redeem_challenge};
use crate::discord::{self, DiscordAuthorize};
use crate::state::AppState;
use crate::types::{
    CreateLocalSessionReq, CreateLocalSessionResp, LocalSessionStatusResp, RedeemLocalSessionReq,
    RedeemedCredentialResp,
};

/// POST /v1/local/oauth/sessions — create a local-CLI one-time handoff session.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn create_local_session(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<CreateLocalSessionReq>,
) -> Response {
    if body.provider != "discord" {
        return (
            StatusCode::BAD_REQUEST,
            "only provider \"discord\" is enabled",
        )
            .into_response();
    }
    if body.redeem_challenge_method != "S256" || body.redeem_challenge.len() < 32 {
        return (StatusCode::BAD_REQUEST, "invalid redeem challenge").into_response();
    }
    if !local_return_url_allowed(&body.return_url) {
        return (StatusCode::BAD_REQUEST, "return_url must be local loopback").into_response();
    }

    let raw_state = generate_state();
    let state_hash = state.state_hasher.hash(&raw_state);
    let discord_session = match discord::build_authorization(DiscordAuthorize {
        config: &state.config,
        state: &raw_state,
        requested_scopes: &body.scopes,
    }) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let expires_at = Utc::now() + Duration::minutes(10);
    let completion_verifier = generate_state();
    let completion_challenge = redeem_challenge(&completion_verifier);
    let completion_ciphertext = match state.cipher.encrypt(&completion_verifier) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!("failed to encrypt local completion verifier: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create OAuth session",
            )
                .into_response();
        }
    };

    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO oauth_sessions \
         (state_hash, provider, user_id, domain, label, scopes, return_url, expires_at, \
          session_mode, redeem_challenge_hash, redeem_challenge_method, \
          completion_challenge_hash, completion_verifier_ciphertext) \
         VALUES ($1, 'discord', 'local-cli', $2, $3, $4, $5, $6, 'local', $7, 'S256', $8, $9) \
         RETURNING id",
    )
    .bind(&state_hash)
    .bind(&body.domain)
    .bind(&body.label)
    .bind(&discord_session.scopes)
    .bind(&body.return_url)
    .bind(expires_at)
    .bind(&body.redeem_challenge)
    .bind(&completion_challenge)
    .bind(&completion_ciphertext)
    .fetch_one(&state.pool)
    .await;

    match row {
        Ok((session_id,)) => axum::Json(CreateLocalSessionResp {
            session_id,
            authorization_url: discord_session.authorization_url,
            expires_at,
        })
        .into_response(),
        Err(e) => {
            tracing::error!("failed to create local OAuth session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create OAuth session",
            )
                .into_response()
        }
    }
}

/// GET /v1/local/oauth/sessions/:id — public sanitized status for local CLI polling.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn get_local_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Response {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            Option<String>,
            Vec<String>,
            String,
            Option<String>,
            Option<String>,
            Option<Uuid>,
            chrono::DateTime<Utc>,
        ),
    >(
        "SELECT id, provider, domain, label, scopes, status, error_code, \
         provider_subject, credential_id, expires_at \
         FROM oauth_sessions WHERE id = $1 AND session_mode = 'local'",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(row)) => axum::Json(LocalSessionStatusResp {
            session_id: row.0,
            provider: row.1,
            domain: row.2,
            label: row.3,
            scopes: row.4,
            status: row.5,
            error_code: row.6,
            provider_subject: row.7,
            credential_id: row.8,
            expires_at: row.9,
        })
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "session not found").into_response(),
        Err(e) => {
            tracing::error!("failed to fetch local OAuth session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch OAuth session",
            )
                .into_response()
        }
    }
}

/// POST /v1/local/oauth/sessions/:id/redeem — one-time token handoff to local CLI.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn redeem_local_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::Json(body): axum::Json<RedeemLocalSessionReq>,
) -> Response {
    let redeem_verifier_challenge = redeem_challenge(&body.redeem_verifier);
    let completion_challenge = redeem_challenge(&body.completion_verifier);
    let row = sqlx::query_as::<_, (String,)>(
        "SELECT local_credential_ciphertext \
         FROM oauth_sessions \
         WHERE id = $1 AND session_mode = 'local' AND status = 'success' \
           AND redeemed_at IS NULL AND expires_at > now() \
           AND redeem_challenge_hash = $2 AND completion_challenge_hash = $3 \
           AND local_credential_ciphertext IS NOT NULL",
    )
    .bind(id)
    .bind(&redeem_verifier_challenge)
    .bind(&completion_challenge)
    .fetch_optional(&state.pool)
    .await;

    let ciphertext = match row {
        Ok(Some((ciphertext,))) => ciphertext,
        Ok(None) => return (StatusCode::BAD_REQUEST, "session cannot be redeemed").into_response(),
        Err(e) => {
            tracing::error!("failed to redeem local OAuth session: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem session",
            )
                .into_response();
        }
    };

    let plaintext = match state.cipher.decrypt(&ciphertext) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!("failed to decrypt local OAuth credential material: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem session",
            )
                .into_response();
        }
    };
    let credential = match serde_json::from_str::<RedeemedCredentialResp>(&plaintext) {
        Ok(credential) => credential,
        Err(e) => {
            tracing::error!("failed to parse local OAuth credential material: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem session",
            )
                .into_response();
        }
    };

    let claimed = sqlx::query_as::<_, (Uuid,)>(
        "UPDATE oauth_sessions \
         SET redeemed_at = now(), local_credential_ciphertext = NULL, \
             completion_verifier_ciphertext = NULL, updated_at = now() \
         WHERE id = $1 AND redeemed_at IS NULL AND local_credential_ciphertext = $2 \
         RETURNING id",
    )
    .bind(id)
    .bind(&ciphertext)
    .fetch_optional(&state.pool)
    .await;

    match claimed {
        Ok(Some(_)) => axum::Json(credential).into_response(),
        Ok(None) => (StatusCode::BAD_REQUEST, "session cannot be redeemed").into_response(),
        Err(e) => {
            tracing::error!("failed to clear redeemed local OAuth session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem session",
            )
                .into_response()
        }
    }
}

fn local_return_url_allowed(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"))
}
