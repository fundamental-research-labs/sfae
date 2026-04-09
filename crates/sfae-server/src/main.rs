use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    pool: PgPool,
    jwt_secret: String,
    internal_auth_secret: String,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// The two authentication modes.
enum AuthInfo {
    /// Authenticated via X-Internal-Auth — can read + write + delete.
    Internal { user_id: String },
    /// Authenticated via Bearer JWT — read only.
    Bearer { user_id: String },
}

impl AuthInfo {
    fn user_id(&self) -> &str {
        match self {
            AuthInfo::Internal { user_id } | AuthInfo::Bearer { user_id } => user_id,
        }
    }

    fn is_internal(&self) -> bool {
        matches!(self, AuthInfo::Internal { .. })
    }
}

fn extract_auth(headers: &HeaderMap, state: &AppState) -> Result<AuthInfo, (StatusCode, String)> {
    // 1. Check X-Internal-Auth
    if let Some(val) = headers.get("x-internal-auth") {
        let val = val.to_str().unwrap_or("");
        if val != state.internal_auth_secret {
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

    // 2. Check Authorization: Bearer <token>
    if let Some(val) = headers.get("authorization") {
        let val = val.to_str().unwrap_or("");
        if let Some(token) = val.strip_prefix("Bearer ") {
            let key = DecodingKey::from_secret(state.jwt_secret.as_bytes());
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

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct StoreCredentialReq {
    domain: String,
    label: Option<String>,
    values: HashMap<String, String>,
}

#[derive(Deserialize)]
struct UpdateCredentialReq {
    values: HashMap<String, String>,
}

#[derive(Deserialize)]
struct MintTokenReq {
    user_id: String,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Serialize)]
struct StoreOkResponse {
    ok: bool,
    id: String,
}

#[derive(Serialize)]
struct CredentialEntry {
    id: String,
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    keys: Vec<String>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct ListResponse {
    credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Deserialize)]
struct CreatePendingOAuthReq {
    state: String,
    user_id: String,
    verifier: String,
    domain: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scope: Option<String>,
    redirect_origin: Option<String>,
}

#[derive(Serialize)]
struct PendingOAuthRow {
    state: String,
    user_id: String,
    verifier: String,
    domain: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scope: Option<String>,
    redirect_origin: Option<String>,
}

#[derive(Deserialize)]
struct RefreshReq {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve OAuth client_id and client_secret from env config for a domain.
/// Walks up parent domains (e.g. gmail.googleapis.com -> googleapis.com).
fn resolve_oauth_client(
    google_client_id: Option<&str>,
    google_client_secret: Option<&str>,
    domain: &str,
) -> Option<(String, Option<String>)> {
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 0..parts.len() {
        let candidate = parts[i..].join(".");
        if candidate == "googleapis.com" {
            let client_id = google_client_id?.to_string();
            let client_secret = google_client_secret.map(String::from);
            return Some((client_id, client_secret));
        }
    }
    None
}

/// Find an OAuth credential set for a domain (one containing OAUTH_ACCESS_TOKEN).
/// Walks up parent domains for fallback.
async fn find_oauth_set_for_domain(
    pool: &PgPool,
    user_id: &str,
    domain: &str,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 0..parts.len() {
        if parts.len() - i < 2 {
            break;
        }
        let candidate = parts[i..].join(".");
        let row = sqlx::query_as::<_, (String, String, String)>(
            "SELECT id::text, domain, value FROM sfae_credentials \
             WHERE user_id = $1 AND domain = $2 AND 'OAUTH_ACCESS_TOKEN' = ANY(keys) \
             LIMIT 1",
        )
        .bind(user_id)
        .bind(&candidate)
        .fetch_optional(pool)
        .await?;

        if let Some(row) = row {
            return Ok(Some(row));
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /credentials — create a new credential set (internal auth only)
///
/// Accepts `{domain, label?, values: {KEY: VALUE, ...}}`, inserts a new row
/// with a generated UUID, and returns `{ok: true, id: "<uuid>"}`.
async fn store_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<StoreCredentialReq>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !auth.is_internal() {
        return (
            StatusCode::FORBIDDEN,
            "Write requires internal auth".to_string(),
        )
            .into_response();
    }
    let user_id = auth.user_id();

    let mut keys: Vec<String> = body.values.keys().cloned().collect();
    keys.sort();

    let value_json = match serde_json::to_string(&body.values) {
        Ok(j) => j,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid values: {e}")).into_response()
        }
    };

    let result = sqlx::query_as::<_, (String,)>(
        "INSERT INTO sfae_credentials (user_id, domain, label, keys, value) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id::text",
    )
    .bind(user_id)
    .bind(&body.domain)
    .bind(&body.label)
    .bind(&keys)
    .bind(&value_json)
    .fetch_one(&state.pool)
    .await;

    match result {
        Ok((id,)) => axum::Json(StoreOkResponse { ok: true, id }).into_response(),
        Err(e) => {
            tracing::error!("DB error storing credential set: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// PUT /credentials/:id — merge fields into an existing credential set (internal auth only)
///
/// Reads the current blob, merges new `{values}` into it, and writes back.
async fn update_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<UpdateCredentialReq>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !auth.is_internal() {
        return (
            StatusCode::FORBIDDEN,
            "Write requires internal auth".to_string(),
        )
            .into_response();
    }
    let user_id = auth.user_id();

    // Read current blob
    let current = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2",
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await;

    let current_value = match current {
        Ok(Some((v,))) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "Credential set not found".to_string(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("DB error reading credential set: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
    };

    // Parse and merge
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
                .into_response()
        }
    };

    let result = sqlx::query(
        "UPDATE sfae_credentials SET value = $1, keys = $2, updated_at = now() \
         WHERE id = $3::uuid AND user_id = $4",
    )
    .bind(&value_json)
    .bind(&keys)
    .bind(&id)
    .bind(user_id)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => axum::Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!("DB error updating credential set: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// GET /credentials/:id/blob — return the raw JSON blob for a credential set
///
/// The response body is the JSON string exactly as stored (not wrapped in an
/// envelope). Both Bearer JWT and internal auth accepted.
async fn get_blob(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
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
        Err(e) => {
            tracing::error!("DB error fetching blob: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// GET /credentials — list all credential sets for the authenticated user
async fn list_all_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
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
        Err(e) => {
            tracing::error!("DB error listing all credentials: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// GET /credentials/:domain — list credential sets for a domain
async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
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
        Err(e) => {
            tracing::error!("DB error listing credentials: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// DELETE /credentials/:id — delete a credential set by UUID (internal auth only)
async fn delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !auth.is_internal() {
        return (
            StatusCode::FORBIDDEN,
            "Delete requires internal auth".to_string(),
        )
            .into_response();
    }
    let user_id = auth.user_id();

    let result = sqlx::query(
        "DELETE FROM sfae_credentials WHERE id = $1::uuid AND user_id = $2",
    )
    .bind(&id)
    .bind(user_id)
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
        Err(e) => {
            tracing::error!("DB error deleting credential: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// POST /auth/token — mint a JWT for a user (internal auth only)
async fn mint_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<MintTokenReq>,
) -> impl IntoResponse {
    // For this endpoint, internal auth is required but user_id comes from the body,
    // not from X-User-Id header. We still need to verify internal auth though.
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
        exp: now + 86400, // 24h
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

/// POST /oauth/pending — store a pending OAuth row (internal auth only)
async fn create_pending_oauth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreatePendingOAuthReq>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !auth.is_internal() {
        return (
            StatusCode::FORBIDDEN,
            "Write requires internal auth".to_string(),
        )
            .into_response();
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
        Err(e) => {
            tracing::error!("DB error creating pending OAuth: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// GET /oauth/pending/:state — consume a pending OAuth row (internal auth only)
///
/// Atomically deletes and returns the row. Returns 404 if not found or expired.
async fn consume_pending_oauth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(oauth_state): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !auth.is_internal() {
        return (StatusCode::FORBIDDEN, "Requires internal auth".to_string()).into_response();
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
        Err(e) => {
            tracing::error!("DB error consuming pending OAuth: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// POST /credentials/refresh — server-side OAuth token refresh
///
/// Accepts `{id?, domain?}`. Reads OAuth metadata from the credential blob,
/// fetches a new token from the provider, and updates the blob.
/// Both Bearer JWT and internal auth accepted.
async fn refresh_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RefreshReq>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id().to_string();

    // 1. Find the credential set and its blob
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
                    .into_response()
            }
            Err(e) => {
                tracing::error!("DB error: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                    .into_response();
            }
        }
    } else if let Some(ref domain) = body.domain {
        match find_oauth_set_for_domain(&state.pool, &user_id, domain).await {
            Ok(Some((id, d, v))) => (id, d, v),
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "No OAuth credentials found for this domain".to_string(),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("DB error: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            "Either id or domain is required".to_string(),
        )
            .into_response();
    };

    // 2. Parse blob
    let mut blob: HashMap<String, String> = match serde_json::from_str(&blob_str) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid credential blob: {e}"),
            )
                .into_response()
        }
    };

    let token_url = match blob.get("OAUTH_TOKEN_URL") {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Credential blob missing OAUTH_TOKEN_URL".to_string(),
            )
                .into_response()
        }
    };
    let refresh_token = match blob.get("OAUTH_REFRESH_TOKEN") {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Credential blob missing OAUTH_REFRESH_TOKEN".to_string(),
            )
                .into_response()
        }
    };

    // 3. Resolve client credentials from env config by domain
    let (client_id, client_secret) = match resolve_oauth_client(
        state.google_client_id.as_deref(),
        state.google_client_secret.as_deref(),
        &domain,
    ) {
        Some(pair) => pair,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("No OAuth client config for domain {domain}"),
            )
                .into_response()
        }
    };

    // 4. Call provider token endpoint
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
                .into_response()
        }
    };

    // 5. Update blob with new tokens
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
                .into_response()
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
        tracing::error!("DB error updating credential blob: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
    }

    axum::Json(OkResponse { ok: true }).into_response()
}

/// GET /health — health check (no auth)
async fn health() -> impl IntoResponse {
    axum::Json(HealthResponse {
        status: "ok".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sfae_server=info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = std::env::var("SFAE_JWT_SECRET").expect("SFAE_JWT_SECRET must be set");
    let internal_auth_secret =
        std::env::var("SFAE_INTERNAL_AUTH_SECRET").expect("SFAE_INTERNAL_AUTH_SECRET must be set");
    let port: u16 = std::env::var("SFAE_SERVER_PORT")
        .unwrap_or_else(|_| "3100".into())
        .parse()
        .expect("SFAE_SERVER_PORT must be a valid port number");

    let google_client_id = std::env::var("SFAE_GOOGLE_CLIENT_ID").ok();
    let google_client_secret = std::env::var("SFAE_GOOGLE_CLIENT_SECRET").ok();

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        internal_auth_secret,
        google_client_id,
        google_client_secret,
    });

    let app = Router::new()
        .route(
            "/credentials",
            post(store_credential).get(list_all_credentials),
        )
        .route("/credentials/refresh", post(refresh_credential))
        .route("/credentials/{id}/blob", get(get_blob))
        .route(
            "/credentials/{id_or_domain}",
            get(list_credentials)
                .put(update_credential)
                .delete(delete_credential),
        )
        .route("/oauth/pending", post(create_pending_oauth))
        .route("/oauth/pending/{state}", get(consume_pending_oauth))
        .route("/auth/token", post(mint_token))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("Failed to bind");
    info!("sfae-server listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_oauth_client_google() {
        let (id, secret) =
            resolve_oauth_client(Some("test-client-id"), Some("test-secret"), "googleapis.com")
                .unwrap();
        assert_eq!(id, "test-client-id");
        assert_eq!(secret.unwrap(), "test-secret");
    }

    #[test]
    fn resolve_oauth_client_google_subdomain() {
        let (id, _) = resolve_oauth_client(
            Some("test-client-id"),
            Some("test-secret"),
            "gmail.googleapis.com",
        )
        .unwrap();
        assert_eq!(id, "test-client-id");
    }

    #[test]
    fn resolve_oauth_client_unknown_domain() {
        assert!(
            resolve_oauth_client(Some("test-client-id"), Some("test-secret"), "github.com")
                .is_none()
        );
    }

    #[test]
    fn resolve_oauth_client_no_env_config() {
        assert!(resolve_oauth_client(None, None, "googleapis.com").is_none());
    }

    #[test]
    fn resolve_oauth_client_secret_optional() {
        let (id, secret) =
            resolve_oauth_client(Some("test-client-id"), None, "googleapis.com").unwrap();
        assert_eq!(id, "test-client-id");
        assert!(secret.is_none());
    }

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
