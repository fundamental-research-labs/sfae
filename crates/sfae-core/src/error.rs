//! The shared error type returned by every fallible operation in sfae-core.

use std::io;

/// All errors that can occur in the sfae-core library.
#[derive(Debug, thiserror::Error)]
pub enum SfaeError {
    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    #[error("secret store error: {0}")]
    StoreError(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

impl serde::Serialize for SfaeError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<io::Error> for SfaeError {
    fn from(err: io::Error) -> Self {
        SfaeError::ConfigError(err.to_string())
    }
}

impl From<serde_json::Error> for SfaeError {
    fn from(err: serde_json::Error) -> Self {
        SfaeError::ConfigError(err.to_string())
    }
}

impl SfaeError {
    /// True when the failure happened while selecting, reading, or resolving
    /// credentials before the downstream request can be built.
    pub fn is_credential_resolution_error(&self) -> bool {
        matches!(
            self,
            SfaeError::CredentialNotFound(_) | SfaeError::StoreError(_)
        )
    }
}
