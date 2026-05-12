//! Subcommand implementations for the `sfae` CLI, one module per command.

pub mod credentials;
#[cfg(feature = "native-keychain")]
pub mod delete;
#[cfg(feature = "native-keychain")]
pub mod flush;
#[cfg(feature = "native-keychain")]
pub mod prompt;
pub mod request;
