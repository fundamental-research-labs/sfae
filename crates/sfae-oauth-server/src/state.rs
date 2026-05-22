//! Shared application state for request handlers in the OAuth service.

use crate::config::Config;
use crate::crypto::{StateHasher, TokenCipher};

/// Clonable dependencies shared by every Axum handler.
pub(crate) struct AppState {
    pub(crate) http: reqwest::Client,
    pub(crate) pool: sqlx::PgPool,
    pub(crate) config: Config,
    pub(crate) cipher: TokenCipher,
    pub(crate) state_hasher: StateHasher,
}
