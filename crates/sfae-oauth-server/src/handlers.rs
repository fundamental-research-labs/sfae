//! HTTP handlers for public OAuth callbacks and private OAuth session APIs.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto::generate_state;
use crate::provider::{
    self, BuildAuthorization, ExchangeCode, FetchUser, ProviderToken, ProviderUser,
};
use crate::state::AppState;
use crate::types::{
    CreateSessionReq, CreateSessionResp, HealthResp, ProviderListResp, ProviderResp,
    RedeemedCredentialResp, SessionStatusResp,
};

/// GET /health — process and router health check.
pub(crate) async fn health() -> impl IntoResponse {
    axum::Json(HealthResp { status: "ok" })
}

/// GET /v1/oauth/providers — public provider metadata for client discovery.
pub(crate) async fn list_providers() -> impl IntoResponse {
    axum::Json(ProviderListResp {
        providers: provider::provider_metadata()
            .iter()
            .map(|provider| ProviderResp {
                provider: provider.provider,
                domains: provider.domains.to_vec(),
            })
            .collect(),
    })
}

/// GET /v1/done — minimal human-visible smoke-test completion page.
pub(crate) async fn done(Query(query): Query<DoneQuery>) -> impl IntoResponse {
    let status = query.status.unwrap_or_else(|| "unknown".to_string());
    let session_id = query.session_id.unwrap_or_else(|| "unknown".to_string());
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>SFAE OAuth</title>\
         <body style=\"font-family:system-ui;margin:3rem;line-height:1.5\">\
         <h1>SFAE OAuth {}</h1><p>Session: <code>{}</code></p></body>",
        html_escape(&status),
        html_escape(&session_id)
    ))
}

#[derive(Deserialize)]
pub(crate) struct DoneQuery {
    pub(crate) session_id: Option<String>,
    pub(crate) status: Option<String>,
}

/// POST /internal/oauth/sessions — create a one-time hosted OAuth browser flow.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreateSessionReq>,
) -> Response {
    if let Err(resp) = require_internal(RequireInternal {
        state: &state,
        headers: &headers,
    }) {
        return resp.into_response();
    }
    let Some(provider_name) = provider::canonical_provider_name(&body.provider) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported OAuth provider \"{}\"", body.provider),
        )
            .into_response();
    };

    let raw_state = generate_state();
    let state_hash = state.state_hasher.hash(&raw_state);
    let requested_scopes = body.scopes.unwrap_or_default();
    let provider_session = match provider::build_authorization(BuildAuthorization {
        provider: provider_name,
        config: &state.config,
        state: &raw_state,
        requested_scopes: &requested_scopes,
    }) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let return_url = body
        .return_url
        .unwrap_or_else(|| state.config.default_return_url());
    if !state.config.return_url_allowed(&return_url) {
        return (StatusCode::BAD_REQUEST, "return_url origin is not allowed").into_response();
    }

    let domain = body
        .domain
        .unwrap_or_else(|| provider::default_domain(provider_name).unwrap().to_string());
    let expires_at = Utc::now() + Duration::minutes(10);
    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO oauth_sessions \
         (state_hash, provider, user_id, domain, label, scopes, return_url, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id",
    )
    .bind(&state_hash)
    .bind(provider_name)
    .bind(&body.user_id)
    .bind(&domain)
    .bind(&body.label)
    .bind(&provider_session.scopes)
    .bind(&return_url)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await;

    match row {
        Ok((session_id,)) => axum::Json(CreateSessionResp {
            session_id,
            authorization_url: provider_session.authorization_url,
            expires_at,
        })
        .into_response(),
        Err(e) => {
            tracing::error!("failed to create OAuth session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create OAuth session",
            )
                .into_response()
        }
    }
}

/// GET /internal/oauth/sessions/:id — fetch session status.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_internal(RequireInternal {
        state: &state,
        headers: &headers,
    }) {
        return resp.into_response();
    }

    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
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
        "SELECT id, provider, user_id, domain, label, scopes, status, error_code, \
         provider_subject, credential_id, expires_at \
         FROM oauth_sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(row)) => axum::Json(SessionStatusResp {
            id: row.0,
            provider: row.1,
            user_id: row.2,
            domain: row.3,
            label: row.4,
            scopes: row.5,
            status: row.6,
            error_code: row.7,
            provider_subject: row.8,
            credential_id: row.9,
            expires_at: row.10,
        })
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "session not found").into_response(),
        Err(e) => {
            tracing::error!("failed to fetch OAuth session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch OAuth session",
            )
                .into_response()
        }
    }
}

/// GET /oauth/callback — provider-neutral OAuth redirect target.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn callback_oauth(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    callback_for_provider(CallbackRequest {
        state: &state,
        query,
        required_provider: None,
    })
    .await
}

/// GET /v1/callback/discord — legacy Discord OAuth redirect target.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn callback_discord(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    callback_for_provider(CallbackRequest {
        state: &state,
        query,
        required_provider: Some("discord"),
    })
    .await
}

struct CallbackRequest<'a> {
    state: &'a AppState,
    query: CallbackQuery,
    required_provider: Option<&'a str>,
}

async fn callback_for_provider(args: CallbackRequest<'_>) -> Response {
    let CallbackRequest {
        state,
        query,
        required_provider,
    } = args;
    let Some(raw_state) = query.state.as_deref() else {
        return (StatusCode::BAD_REQUEST, "missing state").into_response();
    };
    let state_hash = state.state_hasher.hash(raw_state);
    let session = match consume_session(ConsumeSession {
        state,
        state_hash: &state_hash,
        required_provider,
    })
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
        Err(resp) => return resp,
    };

    if let Some(error) = query.error {
        mark_session_error(MarkSession {
            state,
            session_id: session.id,
            error_code: &error,
        })
        .await;
        return Redirect::to(&redirect_url(RedirectTarget {
            base: &session.return_url,
            session_id: session.id,
            status: "error",
            completion_verifier: None,
        }))
        .into_response();
    }

    let Some(code) = query.code.as_deref() else {
        mark_session_error(MarkSession {
            state,
            session_id: session.id,
            error_code: "missing_code",
        })
        .await;
        return Redirect::to(&redirect_url(RedirectTarget {
            base: &session.return_url,
            session_id: session.id,
            status: "error",
            completion_verifier: None,
        }))
        .into_response();
    };

    let completion_verifier = match local_completion_verifier(LocalCompletion {
        state,
        session: &session,
    }) {
        Ok(value) => value,
        Err(error_code) => {
            mark_session_error(MarkSession {
                state,
                session_id: session.id,
                error_code: &error_code,
            })
            .await;
            return Redirect::to(&redirect_url(RedirectTarget {
                base: &session.return_url,
                session_id: session.id,
                status: "error",
                completion_verifier: None,
            }))
            .into_response();
        }
    };

    match complete_provider_callback(CompleteCallback {
        state,
        session: &session,
        code,
    })
    .await
    {
        Ok(_) => Redirect::to(&redirect_url(RedirectTarget {
            base: &session.return_url,
            session_id: session.id,
            status: "success",
            completion_verifier: completion_verifier.as_deref(),
        }))
        .into_response(),
        Err(error_code) => {
            mark_session_error(MarkSession {
                state,
                session_id: session.id,
                error_code: &error_code,
            })
            .await;
            Redirect::to(&redirect_url(RedirectTarget {
                base: &session.return_url,
                session_id: session.id,
                status: "error",
                completion_verifier: None,
            }))
            .into_response()
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
}

struct ConsumedSession {
    id: Uuid,
    provider: String,
    user_id: String,
    domain: String,
    label: Option<String>,
    scopes: Vec<String>,
    return_url: String,
    session_mode: String,
    completion_verifier_ciphertext: Option<String>,
}

struct ConsumeSession<'a> {
    state: &'a AppState,
    state_hash: &'a str,
    required_provider: Option<&'a str>,
}

async fn consume_session(args: ConsumeSession<'_>) -> Result<Option<ConsumedSession>, Response> {
    let ConsumeSession {
        state,
        state_hash,
        required_provider,
    } = args;
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            Option<String>,
            Vec<String>,
            String,
            String,
            Option<String>,
        ),
    >(
        "UPDATE oauth_sessions \
         SET consumed_at = now(), status = 'consuming', updated_at = now() \
         WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
           AND ($2::text IS NULL OR provider = $2) \
         RETURNING id, provider, user_id, domain, label, scopes, return_url, session_mode, \
                   completion_verifier_ciphertext",
    )
    .bind(state_hash)
    .bind(required_provider)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some((
            id,
            provider,
            user_id,
            domain,
            label,
            scopes,
            return_url,
            session_mode,
            completion_verifier_ciphertext,
        ))) => Ok(Some(ConsumedSession {
            id,
            provider,
            user_id,
            domain,
            label,
            scopes,
            return_url,
            session_mode,
            completion_verifier_ciphertext,
        })),
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::error!("failed to consume OAuth state: {e}");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "failed to consume state").into_response())
        }
    }
}

struct CompleteCallback<'a> {
    state: &'a AppState,
    session: &'a ConsumedSession,
    code: &'a str,
}

struct LocalCompletion<'a> {
    state: &'a AppState,
    session: &'a ConsumedSession,
}

fn local_completion_verifier(args: LocalCompletion<'_>) -> Result<Option<String>, String> {
    let LocalCompletion { state, session } = args;
    if session.session_mode != "local" {
        return Ok(None);
    }
    let ciphertext = session
        .completion_verifier_ciphertext
        .as_deref()
        .ok_or_else(|| "local_completion_missing".to_string())?;
    state
        .cipher
        .decrypt(ciphertext)
        .map(Some)
        .map_err(|_| "local_completion_decrypt_failed".to_string())
}

async fn complete_provider_callback(args: CompleteCallback<'_>) -> Result<(), String> {
    let CompleteCallback {
        state,
        session,
        code,
    } = args;
    let token = provider::exchange_code(ExchangeCode {
        provider: &session.provider,
        http: &state.http,
        config: &state.config,
        code,
        requested_scopes: &session.scopes,
    })
    .await?;
    let user = provider::fetch_user(FetchUser {
        provider: &session.provider,
        http: &state.http,
        config: &state.config,
        access_token: &token.access_token,
    })
    .await?;

    if session.session_mode == "local" {
        mark_local_session_success(MarkLocalSuccess {
            state,
            session,
            token: &token,
            user: &user,
        })
        .await?;
        return Ok(());
    }

    let account_id = upsert_account(UpsertAccount {
        state,
        session,
        user: &user,
        scopes: &token.scopes,
    })
    .await?;
    upsert_token(UpsertToken {
        state,
        account_id,
        token: &token,
    })
    .await?;
    let credential_id = upsert_credential(UpsertCredential {
        state,
        session,
        account_id,
        token: &token,
    })
    .await?;
    mark_session_success(MarkSuccess {
        state,
        session_id: session.id,
        provider_subject: &user.subject,
        credential_id: Some(credential_id),
    })
    .await?;
    Ok(())
}

struct MarkLocalSuccess<'a> {
    state: &'a AppState,
    session: &'a ConsumedSession,
    token: &'a ProviderToken,
    user: &'a ProviderUser,
}

async fn mark_local_session_success(args: MarkLocalSuccess<'_>) -> Result<(), String> {
    let MarkLocalSuccess {
        state,
        session,
        token,
        user,
    } = args;
    let credential = local_credential_blob(LocalCredentialBlob {
        state,
        provider: &session.provider,
        token,
        user,
    })
    .await?;
    let value_json = serde_json::to_string(&credential)
        .map_err(|e| format!("local_credential_serialize_failed: {e}"))?;
    let ciphertext = state.cipher.encrypt(&value_json)?;
    sqlx::query(
        "UPDATE oauth_sessions \
         SET status = 'success', provider_subject = $2, credential_id = NULL, \
             local_credential_ciphertext = $3, updated_at = now() \
         WHERE id = $1 AND session_mode = 'local'",
    )
    .bind(session.id)
    .bind(&user.subject)
    .bind(ciphertext)
    .execute(&state.pool)
    .await
    .map_err(|e| format!("local_session_success_failed: {e}"))?;
    Ok(())
}

struct LocalCredentialBlob<'a> {
    state: &'a AppState,
    provider: &'a str,
    token: &'a ProviderToken,
    user: &'a ProviderUser,
}

async fn local_credential_blob(
    args: LocalCredentialBlob<'_>,
) -> Result<RedeemedCredentialResp, String> {
    let LocalCredentialBlob {
        state,
        provider,
        token,
        user,
    } = args;
    let broker_credential_secret = generate_state();
    let broker_credential_secret_hash = state.state_hasher.hash(&broker_credential_secret);
    let refresh_token_hash = token
        .refresh_token
        .as_deref()
        .map(|refresh_token| state.state_hasher.hash(refresh_token));
    let (broker_credential_id,) = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO local_oauth_grants \
         (provider, provider_subject, secret_hash, refresh_token_hash) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(provider)
    .bind(&user.subject)
    .bind(&broker_credential_secret_hash)
    .bind(&refresh_token_hash)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| format!("local_grant_insert_failed: {e}"))?;

    let mut values = HashMap::new();
    values.insert("OAUTH_ACCESS_TOKEN".to_string(), token.access_token.clone());

    let mut internal = HashMap::new();
    if let Some(refresh_token) = token.refresh_token.as_deref() {
        internal.insert("OAUTH_REFRESH_TOKEN".to_string(), refresh_token.to_string());
    }
    internal.insert(
        "OAUTH_BROKER_CREDENTIAL_SECRET".to_string(),
        broker_credential_secret,
    );

    let mut metadata = HashMap::new();
    metadata.insert("OAUTH_PROVIDER".to_string(), provider.to_string());
    metadata.insert(
        "OAUTH_BROKER_URL".to_string(),
        state.config.base_url.to_string(),
    );
    metadata.insert(
        "OAUTH_BROKER_CREDENTIAL_ID".to_string(),
        broker_credential_id.to_string(),
    );
    metadata.insert("OAUTH_SCOPES".to_string(), token.scopes.join(" "));
    metadata.insert("OAUTH_PROVIDER_SUBJECT".to_string(), user.subject.clone());
    if let Some(display_name) = user.display_name.as_deref() {
        metadata.insert("OAUTH_DISPLAY_NAME".to_string(), display_name.to_string());
    }
    if let Some(email) = user.email.as_deref() {
        metadata.insert("OAUTH_EMAIL".to_string(), email.to_string());
    }
    if let Some(token_type) = token.token_type.as_deref() {
        metadata.insert("OAUTH_TOKEN_TYPE".to_string(), token_type.to_string());
    }
    if let Some(expires_at) = token.expires_at.as_ref() {
        metadata.insert("OAUTH_EXPIRES_AT".to_string(), expires_at.to_rfc3339());
    }

    Ok(RedeemedCredentialResp {
        values,
        internal,
        metadata,
    })
}

struct UpsertAccount<'a> {
    state: &'a AppState,
    session: &'a ConsumedSession,
    user: &'a ProviderUser,
    scopes: &'a [String],
}

async fn upsert_account(args: UpsertAccount<'_>) -> Result<Uuid, String> {
    let UpsertAccount {
        state,
        session,
        user,
        scopes,
    } = args;
    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO oauth_accounts \
         (user_id, provider, provider_subject, display_name, email, scopes, last_authorized_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now()) \
         ON CONFLICT (user_id, provider, provider_subject) DO UPDATE SET \
           display_name = EXCLUDED.display_name, email = EXCLUDED.email, scopes = EXCLUDED.scopes, \
           status = 'active', last_authorized_at = now(), updated_at = now() \
         RETURNING id",
    )
    .bind(&session.user_id)
    .bind(&session.provider)
    .bind(&user.subject)
    .bind(&user.display_name)
    .bind(&user.email)
    .bind(scopes)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| format!("account_upsert_failed: {e}"))?;
    Ok(row.0)
}

struct UpsertToken<'a> {
    state: &'a AppState,
    account_id: Uuid,
    token: &'a ProviderToken,
}

async fn upsert_token(args: UpsertToken<'_>) -> Result<(), String> {
    let UpsertToken {
        state,
        account_id,
        token,
    } = args;
    let access_ciphertext = state.cipher.encrypt(&token.access_token)?;
    let refresh_ciphertext = token
        .refresh_token
        .as_deref()
        .map(|t| state.cipher.encrypt(t))
        .transpose()?;
    sqlx::query(
        "INSERT INTO oauth_tokens \
         (account_id, access_token_ciphertext, refresh_token_ciphertext, token_type, scopes, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (account_id) DO UPDATE SET \
           access_token_ciphertext = EXCLUDED.access_token_ciphertext, \
           refresh_token_ciphertext = COALESCE(EXCLUDED.refresh_token_ciphertext, oauth_tokens.refresh_token_ciphertext), \
           token_type = EXCLUDED.token_type, scopes = EXCLUDED.scopes, expires_at = EXCLUDED.expires_at, \
           refresh_version = oauth_tokens.refresh_version + 1, last_refresh_at = now(), updated_at = now()",
    )
    .bind(account_id)
    .bind(access_ciphertext)
    .bind(refresh_ciphertext)
    .bind(&token.token_type)
    .bind(&token.scopes)
    .bind(token.expires_at.as_ref().cloned())
    .execute(&state.pool)
    .await
    .map_err(|e| format!("token_upsert_failed: {e}"))?;
    Ok(())
}

struct UpsertCredential<'a> {
    state: &'a AppState,
    session: &'a ConsumedSession,
    account_id: Uuid,
    token: &'a ProviderToken,
}

async fn upsert_credential(args: UpsertCredential<'_>) -> Result<Uuid, String> {
    let UpsertCredential {
        state,
        session,
        account_id,
        token,
    } = args;
    let values = credential_blob(CredentialBlob {
        provider: &session.provider,
        account_id,
        token,
    });
    let mut keys: Vec<String> = values.keys().cloned().collect();
    keys.sort();
    let value_json =
        serde_json::to_string(&values).map_err(|e| format!("credential_serialize_failed: {e}"))?;

    let existing = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM sfae_credentials \
         WHERE user_id = $1 AND domain = $2 AND label IS NOT DISTINCT FROM $3 \
           AND 'OAUTH_ACCESS_TOKEN' = ANY(keys) \
         ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(&session.user_id)
    .bind(&session.domain)
    .bind(&session.label)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| format!("credential_lookup_failed: {e}"))?;

    if let Some((id,)) = existing {
        sqlx::query(
            "UPDATE sfae_credentials SET keys = $1, value = $2, updated_at = now() WHERE id = $3",
        )
        .bind(&keys)
        .bind(&value_json)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| format!("credential_update_failed: {e}"))?;
        return Ok(id);
    }

    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO sfae_credentials (user_id, domain, label, keys, value) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&session.user_id)
    .bind(&session.domain)
    .bind(&session.label)
    .bind(&keys)
    .bind(&value_json)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| format!("credential_insert_failed: {e}"))?;
    Ok(row.0)
}

struct CredentialBlob<'a> {
    provider: &'a str,
    account_id: Uuid,
    token: &'a ProviderToken,
}

fn credential_blob(args: CredentialBlob<'_>) -> HashMap<String, String> {
    let CredentialBlob {
        provider,
        account_id,
        token,
    } = args;
    let mut values = HashMap::new();
    values.insert("OAUTH_ACCESS_TOKEN".to_string(), token.access_token.clone());
    values.insert("OAUTH_PROVIDER".to_string(), provider.to_string());
    values.insert("OAUTH_ACCOUNT_ID".to_string(), account_id.to_string());
    values
}

struct MarkSuccess<'a> {
    state: &'a AppState,
    session_id: Uuid,
    provider_subject: &'a str,
    credential_id: Option<Uuid>,
}

async fn mark_session_success(args: MarkSuccess<'_>) -> Result<(), String> {
    let MarkSuccess {
        state,
        session_id,
        provider_subject,
        credential_id,
    } = args;
    sqlx::query(
        "UPDATE oauth_sessions \
         SET status = 'success', provider_subject = $2, credential_id = $3, updated_at = now() \
         WHERE id = $1",
    )
    .bind(session_id)
    .bind(provider_subject)
    .bind(credential_id)
    .execute(&state.pool)
    .await
    .map_err(|e| format!("session_success_update_failed: {e}"))?;
    Ok(())
}

struct MarkSession<'a> {
    state: &'a AppState,
    session_id: Uuid,
    error_code: &'a str,
}

async fn mark_session_error(args: MarkSession<'_>) {
    let MarkSession {
        state,
        session_id,
        error_code,
    } = args;
    let _ = sqlx::query(
        "UPDATE oauth_sessions SET status = 'error', error_code = $2, updated_at = now() \
         WHERE id = $1",
    )
    .bind(session_id)
    .bind(error_code)
    .execute(&state.pool)
    .await;
}

struct RequireInternal<'a> {
    state: &'a AppState,
    headers: &'a HeaderMap,
}

fn require_internal(args: RequireInternal<'_>) -> Result<(), (StatusCode, &'static str)> {
    let RequireInternal { state, headers } = args;
    let provided = headers
        .get("x-internal-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.config.internal_auth_secret {
        return Err((StatusCode::UNAUTHORIZED, "internal auth required"));
    }
    Ok(())
}

struct RedirectTarget<'a> {
    base: &'a str,
    session_id: Uuid,
    status: &'a str,
    completion_verifier: Option<&'a str>,
}

fn redirect_url(target: RedirectTarget<'_>) -> String {
    let RedirectTarget {
        base,
        session_id,
        status,
        completion_verifier,
    } = target;
    let mut url = url::Url::parse(base).expect("return_url was validated when session was created");
    let mut pairs = url.query_pairs_mut();
    pairs
        .append_pair("session_id", &session_id.to_string())
        .append_pair("status", status);
    if let Some(verifier) = completion_verifier {
        pairs.append_pair("completion_verifier", verifier);
    }
    drop(pairs);
    url.to_string()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_url_appends_completion_without_dropping_existing_query() {
        let session_id = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let redirected = redirect_url(RedirectTarget {
            base: "http://127.0.0.1:49152/oauth-complete?source=browser",
            session_id,
            status: "success",
            completion_verifier: Some("completion-secret"),
        });
        let url = url::Url::parse(&redirected).unwrap();
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(pairs["source"], "browser");
        assert_eq!(pairs["session_id"], session_id.to_string());
        assert_eq!(pairs["status"], "success");
        assert_eq!(pairs["completion_verifier"], "completion-secret");
    }

    #[test]
    fn html_escape_prevents_completion_page_markup_injection() {
        let escaped = html_escape(r#"<script>alert("x")</script>&"#);

        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;"
        );
    }

    #[test]
    fn backend_credential_blob_contains_only_injectable_access_token() {
        let account_id = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let token = ProviderToken {
            access_token: "access-token".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            token_type: Some("Bearer".to_string()),
            scopes: vec!["email".to_string(), "profile".to_string()],
            expires_at: Some(Utc::now()),
        };

        let blob = credential_blob(CredentialBlob {
            provider: "google",
            account_id,
            token: &token,
        });

        assert_eq!(blob["OAUTH_ACCESS_TOKEN"], "access-token");
        assert_eq!(blob["OAUTH_PROVIDER"], "google");
        assert_eq!(blob["OAUTH_ACCOUNT_ID"], account_id.to_string());
        assert!(!blob.contains_key("OAUTH_REFRESH_TOKEN"));
    }
}
