//! Core library for SFAE: secret storage, credential resolution, OAuth flows,
//! and the browser-based prompt used by the CLI and HTTP server.

pub mod api_store;
pub mod browser;
pub mod browser_html;
pub mod credential;
pub mod error;
pub mod oauth;
pub mod proxy;
pub mod spec;
pub mod store;
#[cfg(feature = "cli")]
pub mod ui;

pub use credential::CredentialType;
pub use error::SfaeError;
pub use spec::{FieldSpec, GroupSpec, OAuthSpec, PromptSpec};

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SfaeError>;
