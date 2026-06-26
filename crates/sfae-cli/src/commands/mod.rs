//! Subcommand implementations for the `sfae` CLI, one module per command.

pub mod code;
pub mod credentials;
#[cfg(feature = "native-keychain")]
pub mod delete;
pub mod embedded_skill;
pub mod install_skill;
#[cfg(feature = "native-keychain")]
pub mod prompt;
pub mod request;
pub mod show;
pub mod update;
