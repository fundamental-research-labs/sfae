//! Public local-CLI OAuth handoff endpoints for the hosted broker.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::crypto::StateHasher;
use crate::crypto::{generate_state, redeem_challenge};
use crate::discord::{self, DiscordAuthorize, DiscordRefreshRequest, DiscordRevokeRequest};
use crate::state::AppState;
use crate::types::{
    CreateLocalSessionReq, CreateLocalSessionResp, LocalSessionStatusResp, RedeemLocalSessionReq,
    RedeemedCredentialResp, RefreshLocalCredentialReq, RevokeLocalCredentialReq,
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
            format!("unsupported OAuth provider \"{}\"", body.provider),
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

/// POST /v1/local/oauth/refresh — refresh local CLI token material through the broker.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn refresh_local_credential(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<RefreshLocalCredentialReq>,
) -> Response {
    if body.provider != "discord" {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported OAuth provider \"{}\"", body.provider),
        )
            .into_response();
    }
    if body.refresh_token.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "refresh_token is required").into_response();
    }
    let Some(grant) = authorize_local_grant(LocalGrantAuth {
        state: &state,
        provider: &body.provider,
        grant_id: body.broker_credential_id,
        secret: &body.broker_credential_secret,
    })
    .await
    else {
        return (StatusCode::FORBIDDEN, "broker credential rejected").into_response();
    };
    if !refresh_token_matches_grant(RefreshTokenGrantMatch {
        state_hasher: &state.state_hasher,
        grant: &grant,
        refresh_token: &body.refresh_token,
    }) {
        return (StatusCode::FORBIDDEN, "refresh token rejected").into_response();
    }

    let token = match discord::refresh_token(DiscordRefreshRequest {
        http: &state.http,
        config: &state.config,
        refresh_token: &body.refresh_token,
    })
    .await
    {
        Ok(token) => token,
        Err(error_code) => return (StatusCode::BAD_GATEWAY, error_code).into_response(),
    };
    if let Some(refresh_token) = token.refresh_token.as_deref()
        && update_local_grant_refresh_hash(UpdateLocalGrantRefreshHash {
            state: &state,
            grant_id: grant.id,
            refresh_token,
        })
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to update broker credential",
        )
            .into_response();
    }

    axum::Json(refreshed_credential_blob(RefreshedCredentialBlob {
        state: &state,
        token: &token,
    }))
    .into_response()
}

/// POST /v1/local/oauth/revoke — revoke local CLI token material through the broker.
// xtask: allow-multi-param - axum handler extractors
pub(crate) async fn revoke_local_credential(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<RevokeLocalCredentialReq>,
) -> Response {
    if body.provider != "discord" {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported OAuth provider \"{}\"", body.provider),
        )
            .into_response();
    }
    let has_access = body.access_token.as_deref().is_some_and(|t| !t.is_empty());
    let has_refresh = body.refresh_token.as_deref().is_some_and(|t| !t.is_empty());
    if !has_access && !has_refresh {
        return (
            StatusCode::BAD_REQUEST,
            "access_token or refresh_token is required",
        )
            .into_response();
    }
    let Some(grant) = authorize_local_grant(LocalGrantAuth {
        state: &state,
        provider: &body.provider,
        grant_id: body.broker_credential_id,
        secret: &body.broker_credential_secret,
    })
    .await
    else {
        return (StatusCode::FORBIDDEN, "broker credential rejected").into_response();
    };
    if let Some(refresh_token) = body.refresh_token.as_deref().filter(|t| !t.is_empty())
        && !refresh_token_matches_grant(RefreshTokenGrantMatch {
            state_hasher: &state.state_hasher,
            grant: &grant,
            refresh_token,
        })
    {
        return (StatusCode::FORBIDDEN, "refresh token rejected").into_response();
    }

    let token_to_revoke = body
        .refresh_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(|token| (token, "refresh_token"))
        .or_else(|| {
            body.access_token
                .as_deref()
                .filter(|t| !t.is_empty())
                .map(|token| (token, "access_token"))
        });

    let Some((token, token_type_hint)) = token_to_revoke else {
        return (
            StatusCode::BAD_REQUEST,
            "access_token or refresh_token is required",
        )
            .into_response();
    };

    if discord::revoke_token(DiscordRevokeRequest {
        http: &state.http,
        config: &state.config,
        token,
        token_type_hint,
    })
    .await
    .is_err()
    {
        return (StatusCode::BAD_GATEWAY, "failed to revoke OAuth token").into_response();
    }
    mark_local_grant_revoked(MarkLocalGrantRevoked {
        state: &state,
        grant_id: body.broker_credential_id,
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

struct LocalGrantAuth<'a> {
    state: &'a AppState,
    provider: &'a str,
    grant_id: Uuid,
    secret: &'a str,
}

struct LocalGrant {
    id: Uuid,
    refresh_token_hash: Option<String>,
}

async fn authorize_local_grant(args: LocalGrantAuth<'_>) -> Option<LocalGrant> {
    let LocalGrantAuth {
        state,
        provider,
        grant_id,
        secret,
    } = args;
    if secret.trim().is_empty() {
        return None;
    }
    let secret_hash = state.state_hasher.hash(secret);
    let row = sqlx::query_as::<_, (Uuid, Option<String>)>(
        "SELECT id, refresh_token_hash FROM local_oauth_grants \
         WHERE id = $1 AND provider = $2 AND secret_hash = $3 AND status = 'active'",
    )
    .bind(grant_id)
    .bind(provider)
    .bind(secret_hash)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some((id, refresh_token_hash))) => Some(LocalGrant {
            id,
            refresh_token_hash,
        }),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("failed to authorize local OAuth grant: {e}");
            None
        }
    }
}

struct RefreshTokenGrantMatch<'a> {
    state_hasher: &'a StateHasher,
    grant: &'a LocalGrant,
    refresh_token: &'a str,
}

fn refresh_token_matches_grant(args: RefreshTokenGrantMatch<'_>) -> bool {
    let RefreshTokenGrantMatch {
        state_hasher,
        grant,
        refresh_token,
    } = args;
    let Some(stored_hash) = grant.refresh_token_hash.as_deref() else {
        return false;
    };
    state_hasher.hash(refresh_token) == stored_hash
}

struct UpdateLocalGrantRefreshHash<'a> {
    state: &'a AppState,
    grant_id: Uuid,
    refresh_token: &'a str,
}

async fn update_local_grant_refresh_hash(args: UpdateLocalGrantRefreshHash<'_>) -> Result<(), ()> {
    let UpdateLocalGrantRefreshHash {
        state,
        grant_id,
        refresh_token,
    } = args;
    let refresh_token_hash = state.state_hasher.hash(refresh_token);
    let result = sqlx::query(
        "UPDATE local_oauth_grants \
         SET refresh_token_hash = $2, updated_at = now() WHERE id = $1",
    )
    .bind(grant_id)
    .bind(refresh_token_hash)
    .execute(&state.pool)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => Ok(()),
        Ok(_) => {
            tracing::warn!("failed to update local OAuth grant refresh hash: no row updated");
            Err(())
        }
        Err(e) => {
            tracing::warn!("failed to update local OAuth grant refresh hash: {e}");
            Err(())
        }
    }
}

struct MarkLocalGrantRevoked<'a> {
    state: &'a AppState,
    grant_id: Uuid,
}

async fn mark_local_grant_revoked(args: MarkLocalGrantRevoked<'_>) {
    let MarkLocalGrantRevoked { state, grant_id } = args;
    let _ = sqlx::query(
        "UPDATE local_oauth_grants \
         SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(grant_id)
    .execute(&state.pool)
    .await;
}

struct RefreshedCredentialBlob<'a> {
    state: &'a AppState,
    token: &'a discord::DiscordToken,
}

fn refreshed_credential_blob(args: RefreshedCredentialBlob<'_>) -> RedeemedCredentialResp {
    let RefreshedCredentialBlob { state, token } = args;
    let mut values = HashMap::new();
    values.insert("OAUTH_ACCESS_TOKEN".to_string(), token.access_token.clone());

    let mut internal = HashMap::new();
    if let Some(refresh_token) = token.refresh_token.as_deref() {
        internal.insert("OAUTH_REFRESH_TOKEN".to_string(), refresh_token.to_string());
    }

    let mut metadata = HashMap::new();
    metadata.insert("OAUTH_PROVIDER".to_string(), "discord".to_string());
    metadata.insert(
        "OAUTH_BROKER_URL".to_string(),
        state.config.base_url.to_string(),
    );
    let scopes = token.scopes(&[]);
    if !scopes.is_empty() {
        metadata.insert("OAUTH_SCOPES".to_string(), scopes.join(" "));
    }
    if let Some(token_type) = token.token_type.as_deref() {
        metadata.insert("OAUTH_TOKEN_TYPE".to_string(), token_type.to_string());
    }
    if let Some(expires_at) = token.expires_at() {
        metadata.insert("OAUTH_EXPIRES_AT".to_string(), expires_at.to_rfc3339());
    }

    RedeemedCredentialResp {
        values,
        internal,
        metadata,
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

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::crypto::StateHasher;

    #[test]
    fn refresh_token_match_requires_stored_hash() {
        let hasher = StateHasher::new("test-secret");
        let grant = LocalGrant {
            id: Uuid::new_v4(),
            refresh_token_hash: Some(hasher.hash("refresh-token")),
        };

        assert!(refresh_token_matches_grant(RefreshTokenGrantMatch {
            state_hasher: &hasher,
            grant: &grant,
            refresh_token: "refresh-token",
        }));
        assert!(!refresh_token_matches_grant(RefreshTokenGrantMatch {
            state_hasher: &hasher,
            grant: &grant,
            refresh_token: "different-token",
        }));
    }

    #[test]
    fn refresh_token_match_rejects_missing_hash() {
        let hasher = StateHasher::new("test-secret");
        let grant = LocalGrant {
            id: Uuid::new_v4(),
            refresh_token_hash: None,
        };

        assert!(!refresh_token_matches_grant(RefreshTokenGrantMatch {
            state_hasher: &hasher,
            grant: &grant,
            refresh_token: "refresh-token",
        }));
    }

    #[test]
    fn local_return_url_allows_only_http_loopback() {
        assert!(local_return_url_allowed(
            "http://127.0.0.1:49152/oauth-complete"
        ));
        assert!(local_return_url_allowed(
            "http://localhost:49152/oauth-complete"
        ));
        assert!(!local_return_url_allowed(
            "https://127.0.0.1:49152/oauth-complete"
        ));
        assert!(!local_return_url_allowed(
            "http://192.168.1.10:49152/oauth-complete"
        ));
        assert!(!local_return_url_allowed("https://oauth.sfae.io/v1/done"));
    }

    #[tokio::test]
    async fn refreshed_blob_keeps_refresh_material_internal_only() {
        let config = crate::config::Config {
            database_url: "postgres://localhost/sfae_test".to_string(),
            internal_auth_secret: "internal".to_string(),
            token_encryption_key: "token-key".to_string(),
            discord_client_id: "client-id".to_string(),
            discord_client_secret: "client-secret".to_string(),
            discord_authorize_url: url::Url::parse("https://discord.com/oauth2/authorize").unwrap(),
            discord_token_url: url::Url::parse("https://discord.com/api/oauth2/token").unwrap(),
            discord_token_revoke_url: url::Url::parse(
                "https://discord.com/api/oauth2/token/revoke",
            )
            .unwrap(),
            discord_userinfo_url: url::Url::parse("https://discord.com/api/v10/users/@me").unwrap(),
            base_url: url::Url::parse("https://oauth.sfae.io").unwrap(),
            allowed_return_origins: std::collections::HashSet::new(),
            port: 3100,
        };
        let state = AppState {
            http: reqwest::Client::new(),
            pool: sqlx::PgPool::connect_lazy("postgres://localhost/sfae_test").unwrap(),
            config,
            cipher: crate::crypto::TokenCipher::from_base64_key(
                &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
            )
            .unwrap(),
            state_hasher: StateHasher::new("hash-secret"),
        };
        let token = discord::DiscordToken {
            access_token: "new-access".to_string(),
            refresh_token: Some("new-refresh".to_string()),
            token_type: Some("Bearer".to_string()),
            scope: Some("identify scope.read".to_string()),
            expires_in: Some(60),
        };

        let credential = refreshed_credential_blob(RefreshedCredentialBlob {
            state: &state,
            token: &token,
        });

        assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "new-access");
        assert!(!credential.values.contains_key("OAUTH_REFRESH_TOKEN"));
        assert_eq!(credential.internal["OAUTH_REFRESH_TOKEN"], "new-refresh");
        assert_eq!(credential.metadata["OAUTH_PROVIDER"], "discord");
        assert_eq!(
            credential.metadata["OAUTH_BROKER_URL"],
            "https://oauth.sfae.io/"
        );
        assert_eq!(credential.metadata["OAUTH_SCOPES"], "identify scope.read");
        assert!(credential.metadata.contains_key("OAUTH_EXPIRES_AT"));
    }
}
