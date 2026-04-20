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

use crate::helpers::{db_error, find_oauth_set_for_domain, resolve_oauth_client_from_state};
use crate::state::{AppState, Claims};
use crate::types::{
    CreatePendingOAuthReq, CredentialEntry, HealthResponse, ListResponse, MintTokenReq, OkResponse,
    PendingOAuthRow, RefreshReq, StoreCredentialReq, StoreOkResponse, TokenResponse,
    UpdateCredentialReq,
};

/// POST /credentials — create a new credential set (internal auth only).
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn store_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<StoreCredentialReq>,
) -> impl IntoResponse {
    let user_id = match state.require_internal(&headers) {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

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
    let user_id = match state.require_internal(&headers) {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

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
    let user_id = match state.require_internal(&headers) {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

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

/// POST /oauth/pending — store a pending OAuth row (internal auth only).
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn create_pending_oauth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreatePendingOAuthReq>,
) -> impl IntoResponse {
    if let Err(resp) = state.require_internal(&headers) {
        return resp;
    }

    let result = sqlx::query(
        "INSERT INTO sfae_pending_oauth \
         (state, user_id, verifier, domain, token_url, client_id, client_secret, redirect_uri, scope, redirect_origin) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&body.state)
    .bind(&body.user_id)
    .bind(&body.verifier)
    .bind(&body.domain)
    .bind(&body.token_url)
    .bind(&body.client_id)
    .bind(&body.client_secret)
    .bind(&body.redirect_uri)
    .bind(&body.scope)
    .bind(&body.redirect_origin)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => axum::Json(OkResponse { ok: true }).into_response(),
        Err(e) => db_error(e).into_response(),
    }
}

/// GET /oauth/pending/:state — atomically consume a pending OAuth row.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn consume_pending_oauth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(oauth_state): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = state.require_internal(&headers) {
        return resp;
    }

    let result = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>, String, Option<String>, Option<String>)>(
        "DELETE FROM sfae_pending_oauth \
         WHERE state = $1 AND expires_at > now() \
         RETURNING state, user_id, verifier, domain, token_url, client_id, client_secret, redirect_uri, scope, redirect_origin",
    )
    .bind(&oauth_state)
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some((
            state_val,
            user_id,
            verifier,
            domain,
            token_url,
            client_id,
            client_secret,
            redirect_uri,
            scope,
            redirect_origin,
        ))) => axum::Json(PendingOAuthRow {
            state: state_val,
            user_id,
            verifier,
            domain,
            token_url,
            client_id,
            client_secret,
            redirect_uri,
            scope,
            redirect_origin,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "Pending OAuth session not found or expired".to_string(),
        )
            .into_response(),
        Err(e) => db_error(e).into_response(),
    }
}

/// POST /credentials/refresh — server-side OAuth token refresh.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn refresh_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RefreshReq>,
) -> impl IntoResponse {
    let auth = match state.extract_auth(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    let (cred_id, domain, blob_str) = if let Some(ref id) = body.id {
        match sqlx::query_as::<_, (String, String)>(
            "SELECT domain, value FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2",
        )
        .bind(id)
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(Some((d, v))) => (id.clone(), d, v),
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "Credential set not found".to_string(),
                )
                    .into_response();
            }
            Err(e) => return db_error(e).into_response(),
        }
    } else if let Some(ref domain) = body.domain {
        match find_oauth_set_for_domain(crate::helpers::OAuthSetQuery {
            pool: &state.pool,
            user_id: &user_id,
            domain,
        })
        .await
        {
            Ok(Some((id, d, v))) => (id, d, v),
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "No OAuth credentials found for this domain".to_string(),
                )
                    .into_response();
            }
            Err(e) => return db_error(e).into_response(),
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            "Either id or domain is required".to_string(),
        )
            .into_response();
    };

    let mut blob: HashMap<String, String> = match serde_json::from_str(&blob_str) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid credential blob: {e}"),
            )
                .into_response();
        }
    };

    let token_url = match blob.get("OAUTH_TOKEN_URL") {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Credential blob missing OAUTH_TOKEN_URL".to_string(),
            )
                .into_response();
        }
    };
    let refresh_token = match blob.get("OAUTH_REFRESH_TOKEN") {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Credential blob missing OAUTH_REFRESH_TOKEN".to_string(),
            )
                .into_response();
        }
    };

    let (client_id, client_secret) = match resolve_oauth_client_from_state(
        crate::helpers::StateDomain {
            state: &state,
            domain: &domain,
        },
    ) {
        Some(pair) => pair,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("No OAuth client config for domain {domain}"),
            )
                .into_response();
        }
    };

    let http = reqwest::Client::new();
    let mut params = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(ref secret) = client_secret {
        params.push(("client_secret", secret.clone()));
    }

    let provider_resp = match http.post(&token_url).form(&params).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Provider token endpoint error: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "Failed to contact token endpoint".to_string(),
            )
                .into_response();
        }
    };

    if !provider_resp.status().is_success() {
        let status = provider_resp.status();
        let body_text = provider_resp.text().await.unwrap_or_default();
        tracing::error!("Provider rejected refresh: {status} {body_text}");
        return (
            StatusCode::BAD_GATEWAY,
            format!("Provider rejected refresh: {status}"),
        )
            .into_response();
    }

    let token_data: serde_json::Value = match provider_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Failed to parse token response: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "Invalid token response from provider".to_string(),
            )
                .into_response();
        }
    };

    let new_access_token = match token_data.get("access_token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "Provider response missing access_token".to_string(),
            )
                .into_response();
        }
    };

    blob.insert("OAUTH_ACCESS_TOKEN".to_string(), new_access_token);
    if let Some(new_refresh) = token_data.get("refresh_token").and_then(|v| v.as_str()) {
        blob.insert("OAUTH_REFRESH_TOKEN".to_string(), new_refresh.to_string());
    }

    let mut keys: Vec<String> = blob.keys().cloned().collect();
    keys.sort();
    let value_json = match serde_json::to_string(&blob) {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialize error: {e}"),
            )
                .into_response();
        }
    };

    let update_result = sqlx::query(
        "UPDATE sfae_credentials SET value = $1, keys = $2, updated_at = now() \
         WHERE id = $3::uuid AND user_id = $4",
    )
    .bind(&value_json)
    .bind(&keys)
    .bind(&cred_id)
    .bind(&user_id)
    .execute(&state.pool)
    .await;

    if let Err(e) = update_result {
        return db_error(e).into_response();
    }

    axum::Json(OkResponse { ok: true }).into_response()
}

/// GET /health — health check (no auth).
pub(crate) async fn health() -> impl IntoResponse {
    axum::Json(HealthResponse {
        status: "ok".to_string(),
    })
}
