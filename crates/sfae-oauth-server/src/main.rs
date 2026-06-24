//! Axum entrypoint for the hosted SFAE OAuth broker deployed at oauth.sfae.io.
//!
//! The service owns public provider callbacks and private session APIs while
//! materializing OAuth tokens into SFAE-compatible credential sets.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    http::Request,
    routing::{get, post},
};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use tracing::info;

mod config;
mod crypto;
mod db;
mod discord;
mod google;
mod handlers;
mod local;
mod provider;
mod state;
mod types;

use crate::config::Config;
use crate::crypto::{StateHasher, TokenCipher};
use crate::handlers::{
    callback_discord, callback_oauth, create_session, done, get_session, health, list_providers,
};
use crate::local::{
    create_local_session, get_local_session, redeem_local_session, refresh_local_credential,
    revoke_local_credential,
};
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
    db::clear_expired_local_handoffs(&pool)
        .await
        .expect("failed to clear expired local OAuth handoffs");
    db::spawn_local_handoff_cleanup(pool.clone());

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
        .route("/v1/oauth/providers", get(list_providers))
        .route("/oauth/callback", get(callback_oauth))
        .route("/v1/callback/discord", get(callback_discord))
        .route("/v1/local/oauth/sessions", post(create_local_session))
        .route("/v1/local/oauth/sessions/{id}", get(get_local_session))
        .route(
            "/v1/local/oauth/sessions/{id}/redeem",
            post(redeem_local_session),
        )
        .route("/v1/local/oauth/refresh", post(refresh_local_credential))
        .route("/v1/local/oauth/revoke", post(revoke_local_credential))
        .route("/internal/oauth/sessions", post(create_session))
        .route("/internal/oauth/sessions/{id}", get(get_session))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                tracing::info_span!(
                    "request",
                    method = %request.method(),
                    path = %request.uri().path()
                )
            }),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    info!("sfae-oauth-server listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}
