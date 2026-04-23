//! Small per-request helpers: domain-aware OAuth client lookup, OAuth credential
//! discovery in the DB, and a uniform DB-error → HTTP response shim.

use axum::http::StatusCode;
use sqlx::PgPool;

use crate::state::AppState;

/// Inputs to `resolve_oauth_client`: Google OAuth env config plus target domain.
pub(crate) struct OAuthClientLookup<'a> {
    pub google_client_id: Option<&'a str>,
    pub google_client_secret: Option<&'a str>,
    pub domain: &'a str,
}

/// Resolve OAuth client_id and client_secret from env config for a domain.
/// Walks up parent domains (e.g. gmail.googleapis.com -> googleapis.com).
pub(crate) fn resolve_oauth_client(
    lookup: OAuthClientLookup<'_>,
) -> Option<(String, Option<String>)> {
    let OAuthClientLookup {
        google_client_id,
        google_client_secret,
        domain,
    } = lookup;
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

/// `(state, domain)` pair for the convenience wrapper below.
pub(crate) struct StateDomain<'a> {
    pub state: &'a AppState,
    pub domain: &'a str,
}

/// Convenience wrapper that pulls Google OAuth credentials from `AppState`.
pub(crate) fn resolve_oauth_client_from_state(
    sd: StateDomain<'_>,
) -> Option<(String, Option<String>)> {
    let StateDomain { state, domain } = sd;
    resolve_oauth_client(OAuthClientLookup {
        google_client_id: state.google_client_id.as_deref(),
        google_client_secret: state.google_client_secret.as_deref(),
        domain,
    })
}

/// Inputs for `find_oauth_set_for_domain`.
pub(crate) struct OAuthSetQuery<'a> {
    pub pool: &'a PgPool,
    pub user_id: &'a str,
    pub domain: &'a str,
}

/// Find an OAuth credential set for a domain (one containing OAUTH_ACCESS_TOKEN).
/// Walks up parent domains for fallback.
pub(crate) async fn find_oauth_set_for_domain(
    query: OAuthSetQuery<'_>,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    let OAuthSetQuery {
        pool,
        user_id,
        domain,
    } = query;
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
        let (id, secret) = resolve_oauth_client(OAuthClientLookup {
            google_client_id: Some("test-client-id"),
            google_client_secret: Some("test-secret"),
            domain: "googleapis.com",
        })
        .unwrap();
        assert_eq!(id, "test-client-id");
        assert_eq!(secret.unwrap(), "test-secret");
    }

    #[test]
    fn resolve_oauth_client_google_subdomain() {
        let (id, _) = resolve_oauth_client(OAuthClientLookup {
            google_client_id: Some("test-client-id"),
            google_client_secret: Some("test-secret"),
            domain: "gmail.googleapis.com",
        })
        .unwrap();
        assert_eq!(id, "test-client-id");
    }

    #[test]
    fn resolve_oauth_client_unknown_domain() {
        assert!(
            resolve_oauth_client(OAuthClientLookup {
                google_client_id: Some("test-client-id"),
                google_client_secret: Some("test-secret"),
                domain: "github.com",
            })
            .is_none()
        );
    }

    #[test]
    fn resolve_oauth_client_no_env_config() {
        assert!(
            resolve_oauth_client(OAuthClientLookup {
                google_client_id: None,
                google_client_secret: None,
                domain: "googleapis.com",
            })
            .is_none()
        );
    }

    #[test]
    fn resolve_oauth_client_secret_optional() {
        let (id, secret) = resolve_oauth_client(OAuthClientLookup {
            google_client_id: Some("test-client-id"),
            google_client_secret: None,
            domain: "googleapis.com",
        })
        .unwrap();
        assert_eq!(id, "test-client-id");
        assert!(secret.is_none());
    }
}
