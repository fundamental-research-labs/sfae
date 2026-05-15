//! Binary entrypoint for the SFAE HTTP server.
//!
//! Parses environment configuration, builds the axum router from the handlers
//! module, and serves it on the configured port. Domain-specific logic lives
//! in the sibling modules (`state`, `auth`, `helpers`, `handlers`, `types`).

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod db;
mod handlers;
mod helpers;
mod state;
mod types;

use crate::handlers::{
    create_hosted_oauth_session, delete_credential, get_blob, get_hosted_oauth_session, health,
    list_all_credentials, list_credentials, mint_token, refresh_credential, store_credential,
    update_credential,
};
use crate::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sfae_server=info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = std::env::var("SFAE_JWT_SECRET").expect("SFAE_JWT_SECRET must be set");
    let internal_auth_secret =
        std::env::var("SFAE_INTERNAL_AUTH_SECRET").expect("SFAE_INTERNAL_AUTH_SECRET must be set");
    let port: u16 = std::env::var("SFAE_SERVER_PORT")
        .unwrap_or_else(|_| "3100".into())
        .parse()
        .expect("SFAE_SERVER_PORT must be a valid port number");

    let oauth_broker_url =
        std::env::var("SFAE_OAUTH_BROKER_URL").unwrap_or_else(|_| "https://oauth.sfae.io".into());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    db::run_migrations(&pool)
        .await
        .expect("Failed to run database migrations");

    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        internal_auth_secret,
        oauth_broker_url: oauth_broker_url.trim_end_matches('/').to_string(),
        http: reqwest::Client::new(),
    });

    let app = Router::new()
        .route(
            "/credentials",
            post(store_credential).get(list_all_credentials),
        )
        .route("/credentials/refresh", post(refresh_credential))
        .route("/credentials/{id}/blob", get(get_blob))
        .route(
            "/credentials/{id_or_domain}",
            get(list_credentials)
                .put(update_credential)
                .delete(delete_credential),
        )
        .route("/oauth/sessions", post(create_hosted_oauth_session))
        .route("/oauth/sessions/{id}", get(get_hosted_oauth_session))
        .route("/auth/token", post(mint_token))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("Failed to bind");
    info!("sfae-server listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}
