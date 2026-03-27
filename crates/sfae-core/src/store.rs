use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::credential::{credential_key, CredentialType};
use crate::error::SfaeError;

/// Abstraction over secret storage backends.
pub trait SecretStore {
    /// Store a secret value under the given key.
    fn set(&mut self, key: &str, value: &str) -> Result<(), SfaeError>;

    /// Retrieve a secret value by key.
    fn get(&self, key: &str) -> Result<String, SfaeError>;

    /// Delete a secret by key.
    fn delete(&mut self, key: &str) -> Result<(), SfaeError>;

    /// List all stored keys.
    fn list_keys(&self) -> Result<Vec<String>, SfaeError>;
}

/// List credential types stored for a domain (and optional username).
pub fn list_credential_types(
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<Vec<CredentialType>, SfaeError> {
    let keys = store.list_keys()?;
    let mut types = Vec::new();
    for ct in CredentialType::all() {
        let key = credential_key(domain, username, *ct);
        if keys.contains(&key) {
            types.push(*ct);
        }
    }
    Ok(types)
}

// --- Index file for tracking credential keys ---

fn config_dir() -> Result<PathBuf, SfaeError> {
    let base = dirs::config_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine config directory".into()))?;
    Ok(base.join("sfae"))
}

fn index_path() -> Result<PathBuf, SfaeError> {
    Ok(config_dir()?.join("credentials.json"))
}

fn read_index() -> Result<Vec<String>, SfaeError> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)?;
    let keys: Vec<String> = serde_json::from_str(&data)?;
    Ok(keys)
}

fn write_index(keys: &[String]) -> Result<(), SfaeError> {
    let path = index_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(keys)?;
    fs::write(&path, data)?;
    Ok(())
}

const KEYRING_SERVICE: &str = "sfae";

/// Secret store backed by the OS keychain (macOS Passwords).
///
/// Credential keys are tracked in a local index file
/// (`~/.config/sfae/credentials.json`). Only keys live in the index; actual
/// secret values stay exclusively in the keychain.
#[derive(Default)]
pub struct KeyringStore;

impl KeyringStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(key: &str) -> Result<keyring::Entry, SfaeError> {
        keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| SfaeError::StoreError(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn set(&mut self, key: &str, value: &str) -> Result<(), SfaeError> {
        let entry = Self::entry(key)?;
        entry
            .set_password(value)
            .map_err(|e| SfaeError::StoreError(e.to_string()))?;

        let mut keys = read_index()?;
        if !keys.contains(&key.to_string()) {
            keys.push(key.to_string());
            keys.sort();
            write_index(&keys)?;
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<String, SfaeError> {
        let entry = Self::entry(key)?;
        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => SfaeError::CredentialNotFound(key.to_string()),
            other => SfaeError::StoreError(other.to_string()),
        })
    }

    fn delete(&mut self, key: &str) -> Result<(), SfaeError> {
        let entry = Self::entry(key)?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => SfaeError::CredentialNotFound(key.to_string()),
            other => SfaeError::StoreError(other.to_string()),
        })?;

        let mut keys = read_index()?;
        keys.retain(|k| k != key);
        write_index(&keys)?;
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
        read_index()
    }
}

/// In-memory secret store for testing.
#[derive(Default)]
pub struct InMemoryStore {
    entries: HashMap<String, String>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemoryStore {
    fn set(&mut self, key: &str, value: &str) -> Result<(), SfaeError> {
        self.entries.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<String, SfaeError> {
        self.entries
            .get(key)
            .cloned()
            .ok_or_else(|| SfaeError::CredentialNotFound(key.to_string()))
    }

    fn delete(&mut self, key: &str) -> Result<(), SfaeError> {
        self.entries
            .remove(key)
            .ok_or_else(|| SfaeError::CredentialNotFound(key.to_string()))?;
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
        let mut keys: Vec<String> = self.entries.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut store = InMemoryStore::new();
        store.set("github.com_API_KEY", "abc123").unwrap();
        assert_eq!(store.get("github.com_API_KEY").unwrap(), "abc123");
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
        store.set("k", "old").unwrap();
        store.set("k", "new").unwrap();
        assert_eq!(store.get("k").unwrap(), "new");
    }

    #[test]
    fn delete_removes() {
        let mut store = InMemoryStore::new();
        store.set("k", "v").unwrap();
        store.delete("k").unwrap();
        assert!(store.get("k").is_err());
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let mut store = InMemoryStore::new();
        assert!(matches!(
            store.delete("nope").unwrap_err(),
            SfaeError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn list_keys_sorted() {
        let mut store = InMemoryStore::new();
        store.set("z_KEY", "1").unwrap();
        store.set("a_KEY", "2").unwrap();
        store.set("m_KEY", "3").unwrap();
        assert_eq!(
            store.list_keys().unwrap(),
            vec!["a_KEY", "m_KEY", "z_KEY"]
        );
    }

    #[test]
    fn list_credential_types_for_domain() {
        let mut store = InMemoryStore::new();
        store.set("github.com_API_KEY", "key1").unwrap();
        store.set("github.com_ACCESS_TOKEN", "tok1").unwrap();
        store.set("gitlab.com_PASSWORD", "pw").unwrap();

        let types = list_credential_types(&store, "github.com", None).unwrap();
        assert_eq!(
            types,
            vec![CredentialType::AccessToken, CredentialType::ApiKey]
        );

        let types = list_credential_types(&store, "gitlab.com", None).unwrap();
        assert_eq!(types, vec![CredentialType::Password]);

        let types = list_credential_types(&store, "unknown.com", None).unwrap();
        assert!(types.is_empty());
    }

    #[test]
    fn list_credential_types_with_username() {
        let mut store = InMemoryStore::new();
        store.set("github.com_API_KEY", "key1").unwrap();
        store
            .set("github.com_aduermael_PASSWORD", "pw")
            .unwrap();

        // Without username: only API_KEY
        let types = list_credential_types(&store, "github.com", None).unwrap();
        assert_eq!(types, vec![CredentialType::ApiKey]);

        // With username: only PASSWORD
        let types = list_credential_types(&store, "github.com", Some("aduermael")).unwrap();
        assert_eq!(types, vec![CredentialType::Password]);
    }
}
