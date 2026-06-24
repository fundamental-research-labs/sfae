//! Database bootstrap for the OAuth service schema and compatibility tables.

use sqlx::{Executor, PgPool};

const MIGRATION_LOCK_ID: i64 = 0x5fae_0a11;

/// Apply idempotent schema SQL on service startup.
pub(crate) async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK_ID)
        .execute(&mut *tx)
        .await?;
    tx.execute(sqlx::raw_sql(include_str!("../migrations/001_init.sql")))
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Clear expired local handoff material immediately and from a background task.
pub(crate) async fn clear_expired_local_handoffs(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_sessions \
         SET local_credential_ciphertext = NULL, completion_verifier_ciphertext = NULL, \
             updated_at = now() \
         WHERE session_mode = 'local' AND expires_at <= now() \
           AND (local_credential_ciphertext IS NOT NULL \
                OR completion_verifier_ciphertext IS NOT NULL)",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Spawn periodic cleanup so broker-retained local handoff material expires.
pub(crate) fn spawn_local_handoff_cleanup(pool: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = clear_expired_local_handoffs(&pool).await {
                tracing::warn!("failed to clear expired local OAuth handoffs: {e}");
            }
        }
    });
}
