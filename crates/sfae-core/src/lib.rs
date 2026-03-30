pub mod browser;
pub mod credential;
pub mod error;
pub mod proxy;
pub mod store;
pub mod ui;

pub use credential::CredentialType;
pub use error::SfaeError;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SfaeError>;
