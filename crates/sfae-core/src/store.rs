use crate::credential::Credential;
use crate::error::SfaeError;

/// Abstraction over secret storage backends.
///
/// Implementations must store [`Credential`] values keyed by name and support
/// enumeration of stored credential names.
pub trait SecretStore {
    /// Store a credential under the given name, overwriting any existing value.
    fn set(&mut self, name: &str, credential: &Credential) -> Result<(), SfaeError>;

    /// Retrieve a credential by name.
    fn get(&self, name: &str) -> Result<Credential, SfaeError>;

    /// Delete a credential by name.
    fn delete(&mut self, name: &str) -> Result<(), SfaeError>;

    /// List all stored credential names.
    fn list(&self) -> Result<Vec<String>, SfaeError>;
}
