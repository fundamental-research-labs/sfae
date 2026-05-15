//! Shared server helper functions for converting lower-level errors into HTTP responses.

use axum::http::StatusCode;

/// Log a sqlx error and convert it to an internal-server-error response tuple.
pub(crate) fn db_error(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("DB error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}
