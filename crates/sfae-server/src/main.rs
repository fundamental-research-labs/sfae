use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
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
    cred_type: String,
    value: String,
    metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ResolveReq {
    keys: Vec<String>,
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
struct CredentialEntry {
    domain: String,
    cred_type: String,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct ListResponse {
    credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
struct ResolveResponse {
    values: serde_json::Map<String, serde_json::Value>,
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
    domain: String,
}

// ---------------------------------------------------------------------------
// Credential key parsing
// ---------------------------------------------------------------------------

/// Known credential type suffixes. Order matters — check longer suffixes first
/// to avoid false matches (e.g. `_CLIENT_SECRET` before `_SECRET`).
const CRED_TYPE_SUFFIXES: &[&str] = &[
    "_CLIENT_SECRET",
    "_REFRESH_TOKEN",
    "_ACCESS_TOKEN",
    "_API_KEY",
    "_PASSWORD",
];

/// Parse a key like "github.com_ACCESS_TOKEN" into (domain, cred_type).
fn parse_credential_key(key: &str) -> Option<(String, String)> {
    for suffix in CRED_TYPE_SUFFIXES {
        if let Some(domain) = key.strip_suffix(suffix)
            && !domain.is_empty()
        {
            // Remove leading underscore from suffix to get the cred_type
            return Some((domain.to_string(), suffix[1..].to_string()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /credentials — store or upsert a credential (internal auth only)
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

    let result = sqlx::query(
        "INSERT INTO sfae_credentials (user_id, domain, cred_type, value, metadata, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (user_id, domain, cred_type) \
         DO UPDATE SET value = $4, metadata = $5, updated_at = now()",
    )
    .bind(user_id)
    .bind(&body.domain)
    .bind(&body.cred_type)
    .bind(&body.value)
    .bind(&body.metadata)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => axum::Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!("DB error storing credential: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    }
}

/// GET /credentials — list all credentials for the authenticated user
async fn list_all_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id();

    let rows = sqlx::query_as::<_, (String, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT domain, cred_type, updated_at FROM sfae_credentials \
         WHERE user_id = $1 ORDER BY domain, cred_type",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let credentials: Vec<CredentialEntry> = rows
                .into_iter()
                .map(|(domain, cred_type, updated_at)| CredentialEntry {
                    domain,
                    cred_type,
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

/// GET /credentials/:domain — list credential types for a domain
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

    let rows = sqlx::query_as::<_, (String, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT domain, cred_type, updated_at FROM sfae_credentials \
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
                .map(|(domain, cred_type, updated_at)| CredentialEntry {
                    domain,
                    cred_type,
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

/// POST /credentials/resolve — batch resolve credential values
async fn resolve_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ResolveReq>,
) -> impl IntoResponse {
    let auth = match extract_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = auth.user_id();

    // Parse all keys into (domain, cred_type) pairs
    let parsed: Vec<(String, String, String)> = body
        .keys
        .iter()
        .filter_map(|key| {
            parse_credential_key(key).map(|(domain, cred_type)| (key.clone(), domain, cred_type))
        })
        .collect();

    // Build result map — start with null for all requested keys
    let mut values = serde_json::Map::new();
    for key in &body.keys {
        values.insert(key.clone(), serde_json::Value::Null);
    }

    if !parsed.is_empty() {
        // Build a dynamic query for batch lookup
        // SELECT domain, cred_type, value FROM sfae_credentials
        // WHERE user_id = $1 AND (domain, cred_type) IN (...)
        let mut query = String::from(
            "SELECT domain, cred_type, value FROM sfae_credentials WHERE user_id = $1 AND (",
        );
        let mut bind_idx = 2u32;
        for (i, _) in parsed.iter().enumerate() {
            if i > 0 {
                query.push_str(" OR ");
            }
            query.push_str(&format!(
                "(domain = ${} AND cred_type = ${})",
                bind_idx,
                bind_idx + 1
            ));
            bind_idx += 2;
        }
        query.push(')');

        let mut q = sqlx::query_as::<_, (String, String, String)>(&query).bind(user_id);
        for (_, domain, cred_type) in &parsed {
            q = q.bind(domain).bind(cred_type);
        }

        match q.fetch_all(&state.pool).await {
            Ok(rows) => {
                for (domain, cred_type, value) in rows {
                    // Find the original key for this (domain, cred_type)
                    for (key, d, ct) in &parsed {
                        if d == &domain && ct == &cred_type {
                            values.insert(key.clone(), serde_json::Value::String(value.clone()));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("DB error resolving credentials: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                    .into_response();
            }
        }
    }

    axum::Json(ResolveResponse { values }).into_response()
}

/// DELETE /credentials/:domain/:cred_type — delete a credential (internal auth only)
async fn delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((domain, cred_type)): Path<(String, String)>,
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
        "DELETE FROM sfae_credentials WHERE user_id = $1 AND domain = $2 AND cred_type = $3",
    )
    .bind(user_id)
    .bind(&domain)
    .bind(&cred_type)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => axum::Json(OkResponse { ok: true }).into_response(),
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
/// Both Bearer JWT and internal auth accepted. Reads OAuth metadata from the
/// ACCESS_TOKEN row, fetches a new token from the provider, and updates the DB.
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

    // 1. Read ACCESS_TOKEN row to get metadata (token_url, client_id)
    let access_row = sqlx::query_as::<_, (Option<serde_json::Value>,)>(
        "SELECT metadata FROM sfae_credentials \
         WHERE user_id = $1 AND domain = $2 AND cred_type = 'ACCESS_TOKEN'",
    )
    .bind(&user_id)
    .bind(&body.domain)
    .fetch_optional(&state.pool)
    .await;

    let metadata = match access_row {
        Ok(Some((Some(m),))) => m,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                "No OAuth metadata found for this domain".to_string(),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("DB error reading access token metadata: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
    };

    let token_url = match metadata.get("token_url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "OAuth metadata missing token_url".to_string(),
            )
                .into_response();
        }
    };
    let client_id = match metadata.get("client_id").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "OAuth metadata missing client_id".to_string(),
            )
                .into_response();
        }
    };

    // 2. Read REFRESH_TOKEN row
    let refresh_row = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM sfae_credentials \
         WHERE user_id = $1 AND domain = $2 AND cred_type = 'REFRESH_TOKEN'",
    )
    .bind(&user_id)
    .bind(&body.domain)
    .fetch_optional(&state.pool)
    .await;

    let refresh_token = match refresh_row {
        Ok(Some((val,))) => val,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "No refresh token found for this domain".to_string(),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("DB error reading refresh token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
    };

    // 3. Look up client_secret: config env var first, then CLIENT_SECRET credential row
    let client_secret =
        if body.domain == "googleapis.com" || body.domain.ends_with(".googleapis.com") {
            state.google_client_secret.clone()
        } else {
            None
        };
    let client_secret = match client_secret {
        Some(s) => Some(s),
        None => {
            // Fallback: look for a CLIENT_SECRET credential row
            sqlx::query_as::<_, (String,)>(
                "SELECT value FROM sfae_credentials \
                 WHERE user_id = $1 AND domain = $2 AND cred_type = 'CLIENT_SECRET'",
            )
            .bind(&user_id)
            .bind(&body.domain)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .map(|(v,)| v)
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

    let provider_resp = http.post(&token_url).form(&params).send().await;

    let provider_resp = match provider_resp {
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

    // 5. Update ACCESS_TOKEN in DB (preserve existing metadata)
    let update_access = sqlx::query(
        "UPDATE sfae_credentials SET value = $1, updated_at = now() \
         WHERE user_id = $2 AND domain = $3 AND cred_type = 'ACCESS_TOKEN'",
    )
    .bind(&new_access_token)
    .bind(&user_id)
    .bind(&body.domain)
    .execute(&state.pool)
    .await;

    if let Err(e) = update_access {
        tracing::error!("DB error updating access token: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
    }

    // 6. Update REFRESH_TOKEN if provider rotated it
    if let Some(new_refresh) = token_data.get("refresh_token").and_then(|v| v.as_str()) {
        let update_refresh = sqlx::query(
            "UPDATE sfae_credentials SET value = $1, updated_at = now() \
             WHERE user_id = $2 AND domain = $3 AND cred_type = 'REFRESH_TOKEN'",
        )
        .bind(new_refresh)
        .bind(&user_id)
        .bind(&body.domain)
        .execute(&state.pool)
        .await;

        if let Err(e) = update_refresh {
            tracing::error!("DB error updating refresh token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
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

    let google_client_secret = std::env::var("SFAE_GOOGLE_CLIENT_SECRET").ok();

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        internal_auth_secret,
        google_client_secret,
    });

    let app = Router::new()
        .route(
            "/credentials",
            post(store_credential).get(list_all_credentials),
        )
        .route("/credentials/{domain}", get(list_credentials))
        .route("/credentials/resolve", post(resolve_credentials))
        .route(
            "/credentials/{domain}/{cred_type}",
            delete(delete_credential),
        )
        .route("/credentials/refresh", post(refresh_credential))
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
    fn parse_credential_key_access_token() {
        let (domain, cred_type) = parse_credential_key("github.com_ACCESS_TOKEN").unwrap();
        assert_eq!(domain, "github.com");
        assert_eq!(cred_type, "ACCESS_TOKEN");
    }

    #[test]
    fn parse_credential_key_api_key() {
        let (domain, cred_type) = parse_credential_key("stripe.com_API_KEY").unwrap();
        assert_eq!(domain, "stripe.com");
        assert_eq!(cred_type, "API_KEY");
    }

    #[test]
    fn parse_credential_key_password() {
        let (domain, cred_type) = parse_credential_key("example.org_PASSWORD").unwrap();
        assert_eq!(domain, "example.org");
        assert_eq!(cred_type, "PASSWORD");
    }

    #[test]
    fn parse_credential_key_client_secret() {
        let (domain, cred_type) = parse_credential_key("oauth.example.com_CLIENT_SECRET").unwrap();
        assert_eq!(domain, "oauth.example.com");
        assert_eq!(cred_type, "CLIENT_SECRET");
    }

    #[test]
    fn parse_credential_key_refresh_token() {
        let (domain, cred_type) = parse_credential_key("googleapis.com_REFRESH_TOKEN").unwrap();
        assert_eq!(domain, "googleapis.com");
        assert_eq!(cred_type, "REFRESH_TOKEN");
    }

    #[test]
    fn parse_credential_key_unknown_suffix() {
        assert!(parse_credential_key("github.com_UNKNOWN").is_none());
    }

    #[test]
    fn parse_credential_key_empty_domain() {
        assert!(parse_credential_key("_ACCESS_TOKEN").is_none());
    }

    #[test]
    fn parse_credential_key_no_suffix() {
        assert!(parse_credential_key("github.com").is_none());
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
