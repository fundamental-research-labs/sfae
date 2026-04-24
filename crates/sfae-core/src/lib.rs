pub mod api_store;
pub mod browser;
pub mod credential;
pub mod error;
pub mod http;
pub mod oauth;
pub mod proxy;
pub mod store;
#[cfg(feature = "cli")]
pub mod ui;

pub use credential::CredentialType;
pub use error::SfaeError;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SfaeError>;
