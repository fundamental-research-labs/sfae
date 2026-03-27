pub mod credential;
pub mod error;
pub mod proxy;
pub mod secret;
pub mod service;
pub mod store;
pub mod ui;

pub use credential::Credential;
pub use error::SfaeError;
pub use secret::SecretHandle;
pub use service::ServiceConfig;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SfaeError>;
