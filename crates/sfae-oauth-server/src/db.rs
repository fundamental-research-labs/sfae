//! Database bootstrap for the OAuth service schema and compatibility tables.

use sqlx::{Executor, PgPool};

/// Apply idempotent schema SQL on service startup.
pub(crate) async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    pool.execute(sqlx::raw_sql(include_str!("../migrations/001_init.sql")))
        .await?;
    Ok(())
}
