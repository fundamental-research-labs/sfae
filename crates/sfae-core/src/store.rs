use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

/// Returns the path to the SFAE config directory (`~/.config/sfae`).
pub(crate) fn config_dir() -> Result<PathBuf, SfaeError> {
    let base = dirs::config_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine config directory".into()))?;
    Ok(base.join("sfae"))
}

/// Returns the path to the credential index file.
fn index_path() -> Result<PathBuf, SfaeError> {
    Ok(config_dir()?.join("credentials.json"))
}

/// Reads the credential name index from disk. Returns an empty vec if the file
/// does not exist yet.
fn read_index() -> Result<Vec<String>, SfaeError> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)?;
    let names: Vec<String> = serde_json::from_str(&data)?;
    Ok(names)
}

/// Writes the credential name index to disk, creating the config directory if
/// needed.
fn write_index(names: &[String]) -> Result<(), SfaeError> {
    let path = index_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(names)?;
    fs::write(&path, data)?;
    Ok(())
}

const KEYRING_SERVICE: &str = "sfae";

/// Secret store backed by the OS keychain via the `keyring` crate.
///
/// Credential names are tracked in a local index file
/// (`~/.config/sfae/credentials.json`). Only names live in the index; actual
/// secret values stay exclusively in the keychain.
#[derive(Default)]
pub struct KeyringStore;

impl KeyringStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(name: &str) -> Result<keyring::Entry, SfaeError> {
        keyring::Entry::new(KEYRING_SERVICE, name).map_err(|e| SfaeError::StoreError(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn set(&mut self, name: &str, credential: &Credential) -> Result<(), SfaeError> {
        let entry = Self::entry(name)?;
        let json = serde_json::to_string(credential)?;
        entry
            .set_password(&json)
            .map_err(|e| SfaeError::StoreError(e.to_string()))?;

        // Update the index
        let mut names = read_index()?;
        if !names.contains(&name.to_string()) {
            names.push(name.to_string());
            names.sort();
            write_index(&names)?;
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Credential, SfaeError> {
        let entry = Self::entry(name)?;
        let json = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => SfaeError::CredentialNotFound(name.to_string()),
            other => SfaeError::StoreError(other.to_string()),
        })?;
        let credential: Credential = serde_json::from_str(&json)?;
        Ok(credential)
    }

    fn delete(&mut self, name: &str) -> Result<(), SfaeError> {
        let entry = Self::entry(name)?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => SfaeError::CredentialNotFound(name.to_string()),
            other => SfaeError::StoreError(other.to_string()),
        })?;

        // Update the index
        let mut names = read_index()?;
        names.retain(|n| n != name);
        write_index(&names)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, SfaeError> {
        read_index()
    }
}

/// In-memory secret store for testing. Not backed by any persistent storage.
#[derive(Default)]
pub struct InMemoryStore {
    entries: HashMap<String, Credential>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemoryStore {
    fn set(&mut self, name: &str, credential: &Credential) -> Result<(), SfaeError> {
        self.entries.insert(name.to_string(), credential.clone());
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Credential, SfaeError> {
        self.entries
            .get(name)
            .cloned()
            .ok_or_else(|| SfaeError::CredentialNotFound(name.to_string()))
    }

    fn delete(&mut self, name: &str) -> Result<(), SfaeError> {
        self.entries
            .remove(name)
            .ok_or_else(|| SfaeError::CredentialNotFound(name.to_string()))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, SfaeError> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str) -> Credential {
        Credential::AccessToken {
            token: value.to_string(),
        }
    }

    #[test]
    fn set_and_get() {
        let mut store = InMemoryStore::new();
        store.set("gh", &token("abc")).unwrap();
        let cred = store.get("gh").unwrap();
        assert_eq!(cred.secret_value(), "abc");
    }

    #[test]
    fn get_missing_returns_not_found() {
        let store = InMemoryStore::new();
        let err = store.get("nope").unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    #[test]
    fn set_overwrites() {
        let mut store = InMemoryStore::new();
        store.set("gh", &token("old")).unwrap();
        store.set("gh", &token("new")).unwrap();
        assert_eq!(store.get("gh").unwrap().secret_value(), "new");
    }

    #[test]
    fn delete_removes_credential() {
        let mut store = InMemoryStore::new();
        store.set("gh", &token("abc")).unwrap();
        store.delete("gh").unwrap();
        assert!(store.get("gh").is_err());
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let mut store = InMemoryStore::new();
        let err = store.delete("nope").unwrap_err();
        assert!(matches!(err, SfaeError::CredentialNotFound(_)));
    }

    #[test]
    fn list_returns_sorted_names() {
        let mut store = InMemoryStore::new();
        store.set("dropbox", &token("d")).unwrap();
        store.set("aws", &token("a")).unwrap();
        store.set("github", &token("g")).unwrap();
        let names = store.list().unwrap();
        assert_eq!(names, vec!["aws", "dropbox", "github"]);
    }

    #[test]
    fn list_empty_store() {
        let store = InMemoryStore::new();
        assert!(store.list().unwrap().is_empty());
    }
}
