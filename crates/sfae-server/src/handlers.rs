//! HTTP handlers for the credential, OAuth, auth-token, and health routes.
//!
//! Each handler uses `AppState::extract_auth` / `require_internal` for
//! authentication and `helpers::db_error` to convert sqlx errors uniformly.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use jsonwebtoken::{EncodingKey, Header, encode};

use crate::helpers::db_error;
use crate::state::{AppState, Claims};
use crate::types::{
    BrokerCreateSessionReq, BrokerCreateSessionResp, BrokerSessionStatusResp, CredentialEntry,
    HealthResponse, HostedOAuthSessionReq, HostedOAuthSessionResp, HostedOAuthStatusResp,
    ListResponse, MintTokenReq, OAuthProviderListResp, OkResponse, StoreCredentialReq,
    StoreOkResponse, TokenResponse, UpdateCredentialReq,
};

/// POST /credentials — create a new credential set for the authenticated user.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn store_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<StoreCredentialReq>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let mut keys: Vec<String> = body.values.keys().cloned().collect();
    keys.sort();

    let value_json = match serde_json::to_string(&body.values) {
        Ok(j) => j,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid values: {e}")).into_response(),
    };

    let result = sqlx::query_as::<_, (String,)>(
        "INSERT INTO sfae_credentials (user_id, domain, label, keys, value) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id::text",
    )
    .bind(&user_id)
    .bind(&body.domain)
    .bind(&body.label)
    .bind(&keys)
    .bind(&value_json)
    .fetch_one(&state.pool)
    .await;

    match result {
        Ok((id,)) => axum::Json(StoreOkResponse { ok: true, id }).into_response(),
        Err(e) => db_error(e).into_response(),
    }
}

/// PUT /credentials/:id — merge fields into an existing credential set.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn update_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<UpdateCredentialReq>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let current = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2",
    )
    .bind(&id)
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await;

    let current_value = match current {
        Ok(Some((v,))) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "Credential set not found".to_string(),
            )
                .into_response();
        }
        Err(e) => return db_error(e).into_response(),
    };

    let mut values: HashMap<String, String> =
        serde_json::from_str(&current_value).unwrap_or_default();
    for (k, v) in body.values {
        values.insert(k, v);
    }

    let mut keys: Vec<String> = values.keys().cloned().collect();
    keys.sort();

    let value_json = match serde_json::to_string(&values) {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialize error: {e}"),
            )
                .into_response();
        }
    };

    let result = sqlx::query(
        "UPDATE sfae_credentials SET value = $1, keys = $2, updated_at = now() \
         WHERE id = $3::uuid AND user_id = $4",
    )
    .bind(&value_json)
    .bind(&keys)
    .bind(&id)
    .bind(&user_id)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => axum::Json(OkResponse { ok: true }).into_response(),
        Err(e) => db_error(e).into_response(),
    }
}

/// GET /credentials/:id/blob — return the raw JSON blob.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn get_blob(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id();

    let result = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2",
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some((value,))) => (StatusCode::OK, value).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "Credential set not found".to_string(),
        )
            .into_response(),
        Err(e) => db_error(e).into_response(),
    }
}

/// GET /credentials — list all credential sets for the authenticated user.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn list_all_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id();

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Vec<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id::text, domain, label, keys, updated_at FROM sfae_credentials \
         WHERE user_id = $1 ORDER BY domain, label",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let credentials: Vec<CredentialEntry> = rows
                .into_iter()
                .map(|(id, domain, label, keys, updated_at)| CredentialEntry {
                    id,
                    domain,
                    label,
                    keys,
                    updated_at,
                })
                .collect();
            axum::Json(ListResponse { credentials }).into_response()
        }
        Err(e) => db_error(e).into_response(),
    }
}

/// GET /credentials/:domain — list credential sets for a domain.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id();

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Vec<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id::text, domain, label, keys, updated_at FROM sfae_credentials \
         WHERE user_id = $1 AND domain = $2",
    )
    .bind(user_id)
    .bind(&domain)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let credentials: Vec<CredentialEntry> = rows
                .into_iter()
                .map(|(id, domain, label, keys, updated_at)| CredentialEntry {
                    id,
                    domain,
                    label,
                    keys,
                    updated_at,
                })
                .collect();
            axum::Json(ListResponse { credentials }).into_response()
        }
        Err(e) => db_error(e).into_response(),
    }
}

/// DELETE /credentials/:id — delete a credential set by UUID.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let result = sqlx::query("DELETE FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2")
        .bind(&id)
        .bind(&user_id)
        .execute(&state.pool)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    "Credential set not found".to_string(),
                )
                    .into_response()
            } else {
                axum::Json(OkResponse { ok: true }).into_response()
            }
        }
        Err(e) => db_error(e).into_response(),
    }
}

/// POST /auth/token — mint a JWT for a user (internal auth only).
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn mint_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<MintTokenReq>,
) -> impl IntoResponse {
    // For this endpoint, internal auth is required but user_id comes from the
    // body, not from X-User-Id header. We still verify the internal secret.
    let internal_header = headers
        .get("x-internal-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if internal_header != state.internal_auth_secret {
        return (
            StatusCode::UNAUTHORIZED,
            "Internal auth required".to_string(),
        )
            .into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: body.user_id,
        iat: now,
        exp: now + 86400,
    };

    let key = EncodingKey::from_secret(state.jwt_secret.as_bytes());
    match encode(&Header::default(), &claims, &key) {
        Ok(token) => axum::Json(TokenResponse { token }).into_response(),
        Err(e) => {
            tracing::error!("JWT encoding error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("JWT error: {e}")).into_response()
        }
    }
}

/// GET /oauth/providers — proxy hosted OAuth provider metadata for the current user.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn list_hosted_oauth_providers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = state.extract_auth(&headers) {
        return e.into_response();
    }

    let url = format!("{}/v1/oauth/providers", state.oauth_broker_url);
    let response = match state.http.get(&url).send().await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("OAuth broker provider request failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to contact OAuth broker".to_string(),
            )
                .into_response();
        }
    };
    let status = response.status();
    let text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            tracing::error!("OAuth broker provider response read failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to read OAuth broker response".to_string(),
            )
                .into_response();
        }
    };
    if !status.is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            format!("OAuth broker provider request failed: {status}"),
        )
            .into_response();
    }
    let providers: OAuthProviderListResp = match serde_json::from_str(&text) {
        Ok(providers) => providers,
        Err(e) => {
            tracing::error!("OAuth broker provider response parse failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to parse OAuth broker provider response".to_string(),
            )
                .into_response();
        }
    };
    axum::Json(providers).into_response()
}

/// POST /oauth/sessions — start a hosted OAuth broker session for the current user.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn create_hosted_oauth_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<HostedOAuthSessionReq>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(auth) => auth,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let url = format!("{}/internal/oauth/sessions", state.oauth_broker_url);
    let broker_body = BrokerCreateSessionReq {
        provider: &body.provider,
        user_id: &user_id,
        domain: body.domain.as_deref(),
        label: body.label.as_deref(),
        scopes: body.scopes,
    };

    let response = match state
        .http
        .post(&url)
        .header("x-internal-auth", &state.internal_auth_secret)
        .json(&broker_body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("failed to contact hosted OAuth broker: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to contact hosted OAuth broker".to_string(),
            )
                .into_response();
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!("hosted OAuth broker rejected session create: {status} {body}");
        let client_status = if status.is_client_error() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::BAD_GATEWAY
        };
        return (
            client_status,
            format!("hosted OAuth broker rejected session create: {status}"),
        )
            .into_response();
    }

    let broker: BrokerCreateSessionResp = match response.json().await {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("failed to parse hosted OAuth broker response: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "invalid hosted OAuth broker response".to_string(),
            )
                .into_response();
        }
    };

    axum::Json(HostedOAuthSessionResp {
        session_id: broker.session_id,
        authorization_url: broker.authorization_url,
        expires_at: broker.expires_at,
    })
    .into_response()
}

/// GET /oauth/sessions/:id — poll sanitized hosted OAuth broker status.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn get_hosted_oauth_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(auth) => auth,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let url = format!("{}/internal/oauth/sessions/{id}", state.oauth_broker_url);
    let response = match state
        .http
        .get(&url)
        .header("x-internal-auth", &state.internal_auth_secret)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("failed to contact hosted OAuth broker: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to contact hosted OAuth broker".to_string(),
            )
                .into_response();
        }
    };

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return (StatusCode::NOT_FOUND, "session not found".to_string()).into_response();
    }
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("hosted OAuth broker rejected status poll: {status}");
        return (
            StatusCode::BAD_GATEWAY,
            format!("hosted OAuth broker rejected status poll: {status}"),
        )
            .into_response();
    }

    let broker: BrokerSessionStatusResp = match response.json().await {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("failed to parse hosted OAuth broker status: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "invalid hosted OAuth broker response".to_string(),
            )
                .into_response();
        }
    };

    if broker.user_id != user_id {
        return (StatusCode::NOT_FOUND, "session not found".to_string()).into_response();
    }

    axum::Json(HostedOAuthStatusResp {
        session_id: broker.id,
        provider: broker.provider,
        domain: broker.domain,
        label: broker.label,
        scopes: broker.scopes,
        status: broker.status,
        error_code: public_oauth_error_code(broker.error_code.as_deref()),
        provider_subject: broker.provider_subject,
        credential_id: broker.credential_id,
        expires_at: broker.expires_at,
    })
    .into_response()
}

fn public_oauth_error_code(error_code: Option<&str>) -> Option<String> {
    let code = match error_code? {
        "access_denied" => "access_denied",
        "missing_code" => "missing_code",
        code if code.starts_with("discord_token_status_") => "provider_token_exchange_failed",
        code if code.starts_with("discord_user_status_") => "provider_identity_failed",
        code if code.contains("_failed") => "oauth_completion_failed",
        _ => "oauth_failed",
    };
    Some(code.to_string())
}

/// POST /credentials/refresh — OAuth refresh will delegate to the hosted broker in a later phase.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn refresh_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(_body): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Err(e) = state.extract_auth(&headers) {
        return e.into_response();
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        "OAuth refresh delegation is not implemented in this phase".to_string(),
    )
        .into_response()
}

/// GET /health — health check (no auth).
pub(crate) async fn health() -> impl IntoResponse {
    axum::Json(HealthResponse {
        status: "ok".to_string(),
    })
}
