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

mod handlers;
mod helpers;
mod state;
mod types;

use crate::handlers::{
    consume_pending_oauth, create_pending_oauth, delete_credential, get_blob, health,
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

    let google_client_id = std::env::var("SFAE_GOOGLE_CLIENT_ID").ok();
    let google_client_secret = std::env::var("SFAE_GOOGLE_CLIENT_SECRET").ok();

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        internal_auth_secret,
        google_client_id,
        google_client_secret,
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
        .route("/oauth/pending", post(create_pending_oauth))
        .route("/oauth/pending/{state}", get(consume_pending_oauth))
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
