//! Small per-request helpers: domain-aware OAuth client lookup, OAuth credential
//! discovery in the DB, and a uniform DB-error → HTTP response shim.

use axum::http::StatusCode;
use sqlx::PgPool;

use crate::state::AppState;

/// Resolve OAuth client_id and client_secret from env config for a domain.
/// Walks up parent domains (e.g. gmail.googleapis.com -> googleapis.com).
pub(crate) fn resolve_oauth_client(
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

/// Convenience wrapper that pulls Google OAuth credentials from `AppState`.
pub(crate) fn resolve_oauth_client_from_state(
    state: &AppState,
    domain: &str,
) -> Option<(String, Option<String>)> {
    resolve_oauth_client(
        state.google_client_id.as_deref(),
        state.google_client_secret.as_deref(),
        domain,
    )
}

/// Find an OAuth credential set for a domain (one containing OAUTH_ACCESS_TOKEN).
/// Walks up parent domains for fallback.
pub(crate) async fn find_oauth_set_for_domain(
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

/// Log a sqlx error and convert it to an internal-server-error response tuple.
pub(crate) fn db_error(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("DB error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_oauth_client_google() {
        let (id, secret) = resolve_oauth_client(
            Some("test-client-id"),
            Some("test-secret"),
            "googleapis.com",
        )
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
}
