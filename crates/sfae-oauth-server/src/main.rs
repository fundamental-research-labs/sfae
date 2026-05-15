//! Axum entrypoint for the hosted SFAE OAuth broker deployed at oauth.sfae.io.
//!
//! The service owns public provider callbacks and private session APIs while
//! materializing OAuth tokens into SFAE-compatible credential sets.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use tracing::info;

mod config;
mod crypto;
mod db;
mod discord;
mod handlers;
mod state;
mod types;

use crate::config::Config;
use crate::crypto::{StateHasher, TokenCipher};
use crate::handlers::{callback_discord, create_session, done, get_session, health};
use crate::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sfae_oauth_server=info,tower_http=info".parse().unwrap()),
        )
        .init();

    let config = Config::from_env();
    let pool = PgPool::connect(&config.database_url)
        .await
        .expect("failed to connect to database");
    db::run_migrations(&pool)
        .await
        .expect("failed to initialize database schema");

    let cipher = TokenCipher::from_base64_key(&config.token_encryption_key)
        .expect("SFAE_OAUTH_TOKEN_ENCRYPTION_KEY must be base64-encoded 32 bytes");
    let state_hasher = StateHasher::new(&config.token_encryption_key);

    let port = config.port;
    let state = Arc::new(AppState {
        http: reqwest::Client::new(),
        pool,
        config,
        cipher,
        state_hasher,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/done", get(done))
        .route("/v1/callback/discord", get(callback_discord))
        .route("/internal/oauth/sessions", post(create_session))
        .route("/internal/oauth/sessions/{id}", get(get_session))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    info!("sfae-oauth-server listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}
