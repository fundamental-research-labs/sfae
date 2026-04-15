use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::SfaeError;

/// Metadata about a stored credential set (one JSON blob of related fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSetInfo {
    pub id: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub keys: Vec<String>,
}

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

    // -- Credential set operations (JSON blob storage) -------------------------

    /// Whether this store supports credential set operations.
    ///
    /// When true, `store_credential_set`, `list_credential_sets`, and
    /// `delete_credential_set` are available. When false, the proxy layer
    /// falls back to the legacy `domain_TYPE` flat-key format.
    fn supports_credential_sets(&self) -> bool {
        false
    }

    /// Store a credential set as a JSON blob. Returns the generated UUID.
    fn store_credential_set(
        &mut self,
        _domain: &str,
        _label: Option<&str>,
        _values: &HashMap<String, String>,
    ) -> Result<String, SfaeError> {
        Err(SfaeError::Other(
            "credential set operations not supported by this store".into(),
        ))
    }

    /// List credential sets, optionally filtered by domain.
    fn list_credential_sets(
        &self,
        _domain: Option<&str>,
    ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
        Err(SfaeError::Other(
            "credential set operations not supported by this store".into(),
        ))
    }

    /// Delete a credential set by UUID.
    fn delete_credential_set(&mut self, _id: &str) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "credential set operations not supported by this store".into(),
        ))
    }
}

/// List credential types stored for a domain (and optional username/label).
///
/// Returns the raw type strings (e.g. `"ACCESS_TOKEN"`, `"HOST"`, `"USERNAME"`)
/// extracted from credential sets (new path) or flat keys (legacy fallback).
///
/// The `username` parameter maps to credential set labels when using the new
/// credential set storage. When `None`, returns keys from all sets for the domain.
pub fn list_credential_types(
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
) -> Result<Vec<String>, SfaeError> {
    // New path: credential sets (falls through to legacy if no sets found)
    if store.supports_credential_sets() {
        let sets = store.list_credential_sets(Some(domain))?;
        let filtered: Vec<_> = if let Some(user) = username {
            sets.into_iter()
                .filter(|s| s.label.as_deref() == Some(user))
                .collect()
        } else {
            sets
        };

        if !filtered.is_empty() {
            let mut types: Vec<String> = filtered.into_iter().flat_map(|s| s.keys).collect();
            types.sort();
            types.dedup();
            return Ok(types);
        }
        // No credential sets found — fall through to legacy flat-key lookup
    }

    // Legacy fallback: flat domain_TYPE keys
    let keys = store.list_keys()?;
    let prefix = match username {
        Some(user) => format!("{domain}_{user}_"),
        None => format!("{domain}_"),
    };

    let mut types: Vec<String> = Vec::new();
    for key in &keys {
        if let Some(type_str) = key.strip_prefix(&prefix) {
            if type_str.is_empty() {
                continue;
            }
            if username.is_none() && type_str.chars().any(|c| c.is_ascii_lowercase()) {
                continue;
            }
            types.push(type_str.to_string());
        }
    }

    types.sort();
    types.dedup();
    Ok(types)
}

// --- Credential index file ---

fn config_dir() -> Result<PathBuf, SfaeError> {
    let base = dirs::config_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine config directory".into()))?;
    Ok(base.join("sfae"))
}

fn index_path() -> Result<PathBuf, SfaeError> {
    Ok(config_dir()?.join("credentials.json"))
}

/// On-disk credential index. Supports migration from the old `Vec<String>` format.
#[derive(Default, Serialize, Deserialize)]
struct CredentialIndex {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    sets: Vec<CredentialSetInfo>,
    #[serde(default)]
    legacy_keys: Vec<String>,
}

fn read_credential_index() -> Result<CredentialIndex, SfaeError> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(CredentialIndex {
            version: 2,
            ..Default::default()
        });
    }
    let data = fs::read_to_string(&path)?;

    // Try new format (JSON object with version/sets/legacy_keys)
    if let Ok(index) = serde_json::from_str::<CredentialIndex>(&data) {
        return Ok(index);
    }

    // Fall back to old format (JSON array of strings)
    if let Ok(keys) = serde_json::from_str::<Vec<String>>(&data) {
        return Ok(CredentialIndex {
            version: 1,
            sets: vec![],
            legacy_keys: keys,
        });
    }

    // Corrupted — start fresh
    Ok(CredentialIndex {
        version: 2,
        ..Default::default()
    })
}

fn write_credential_index(index: &CredentialIndex) -> Result<(), SfaeError> {
    let path = index_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(index)?;
    fs::write(&path, data)?;
    Ok(())
}

/// Legacy wrapper: read only the flat key list from the index.
fn read_index() -> Result<Vec<String>, SfaeError> {
    Ok(read_credential_index()?.legacy_keys)
}

/// Legacy wrapper: update the flat key list, preserving credential sets.
fn write_index(keys: &[String]) -> Result<(), SfaeError> {
    let mut index = read_credential_index()?;
    index.legacy_keys = keys.to_vec();
    index.version = 2;
    write_credential_index(&index)
}

// --- macOS: use security-framework (modern SecItem APIs) ---

#[cfg(all(feature = "native-keychain", target_os = "macos"))]
mod keyring_store {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const KEYRING_SERVICE: &str = "sfae";

    /// Secret store backed by the macOS keychain via modern SecItem APIs.
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
    }

    /// `errSecItemNotFound` (-25300)
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    fn is_not_found(e: &security_framework::base::Error) -> bool {
        e.code() == ERR_SEC_ITEM_NOT_FOUND
    }

    impl SecretStore for KeyringStore {
        fn set(&mut self, key: &str, value: &str) -> Result<(), SfaeError> {
            set_generic_password(KEYRING_SERVICE, key, value.as_bytes())
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
            match get_generic_password(KEYRING_SERVICE, key) {
                Ok(bytes) => String::from_utf8(bytes)
                    .map_err(|e| SfaeError::StoreError(format!("invalid UTF-8: {e}"))),
                Err(e) if is_not_found(&e) => Err(SfaeError::CredentialNotFound(key.to_string())),
                Err(e) => Err(SfaeError::StoreError(e.to_string())),
            }
        }

        fn delete(&mut self, key: &str) -> Result<(), SfaeError> {
            let keychain_result = delete_generic_password(KEYRING_SERVICE, key);

            // Always clean the index, even if the keychain entry is already gone.
            let mut keys = read_index()?;
            let had_key = keys.contains(&key.to_string());
            keys.retain(|k| k != key);
            if had_key {
                write_index(&keys)?;
            }

            match keychain_result {
                Ok(()) => Ok(()),
                Err(e) if is_not_found(&e) => Err(SfaeError::CredentialNotFound(key.to_string())),
                Err(e) => Err(SfaeError::StoreError(e.to_string())),
            }
        }

        fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
            read_index()
        }

        fn supports_credential_sets(&self) -> bool {
            true
        }

        fn store_credential_set(
            &mut self,
            domain: &str,
            label: Option<&str>,
            values: &HashMap<String, String>,
        ) -> Result<String, SfaeError> {
            let id = uuid::Uuid::new_v4().to_string();
            let mut keys: Vec<String> = values.keys().cloned().collect();
            keys.sort();

            let json = serde_json::to_string(values)
                .map_err(|e| SfaeError::StoreError(format!("failed to serialize: {e}")))?;
            set_generic_password(KEYRING_SERVICE, &id, json.as_bytes())
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            let mut index = read_credential_index()?;
            index.sets.push(CredentialSetInfo {
                id: id.clone(),
                domain: domain.to_string(),
                label: label.map(String::from),
                keys,
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn list_credential_sets(
            &self,
            domain: Option<&str>,
        ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
            let index = read_credential_index()?;
            let sets = match domain {
                Some(d) => index.sets.into_iter().filter(|s| s.domain == d).collect(),
                None => index.sets,
            };
            Ok(sets)
        }

        fn delete_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
            let mut index = read_credential_index()?;
            if !index.sets.iter().any(|s| s.id == id) {
                return Err(SfaeError::CredentialNotFound(id.to_string()));
            }

            // Remove from keychain (ignore if already gone)
            let _ = delete_generic_password(KEYRING_SERVICE, id);

            index.sets.retain(|s| s.id != id);
            index.version = 2;
            write_credential_index(&index)?;

            Ok(())
        }
    }
}

// --- Non-macOS: use keyring crate (Windows/Linux) ---

#[cfg(all(feature = "native-keychain", not(target_os = "macos")))]
mod keyring_store {
    use super::*;

    const KEYRING_SERVICE: &str = "sfae";

    /// Secret store backed by the OS keychain via the `keyring` crate.
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
            let keychain_result = entry.delete_credential();

            // Always clean the index, even if the keychain entry is already gone.
            let mut keys = read_index()?;
            let had_key = keys.contains(&key.to_string());
            keys.retain(|k| k != key);
            if had_key {
                write_index(&keys)?;
            }

            keychain_result.map_err(|e| match e {
                keyring::Error::NoEntry => SfaeError::CredentialNotFound(key.to_string()),
                other => SfaeError::StoreError(other.to_string()),
            })?;
            Ok(())
        }

        fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
            read_index()
        }

        fn supports_credential_sets(&self) -> bool {
            true
        }

        fn store_credential_set(
            &mut self,
            domain: &str,
            label: Option<&str>,
            values: &HashMap<String, String>,
        ) -> Result<String, SfaeError> {
            let id = uuid::Uuid::new_v4().to_string();
            let mut keys: Vec<String> = values.keys().cloned().collect();
            keys.sort();

            let json = serde_json::to_string(values)
                .map_err(|e| SfaeError::StoreError(format!("failed to serialize: {e}")))?;
            let entry = Self::entry(&id)?;
            entry
                .set_password(&json)
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            let mut index = read_credential_index()?;
            index.sets.push(CredentialSetInfo {
                id: id.clone(),
                domain: domain.to_string(),
                label: label.map(String::from),
                keys,
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn list_credential_sets(
            &self,
            domain: Option<&str>,
        ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
            let index = read_credential_index()?;
            let sets = match domain {
                Some(d) => index.sets.into_iter().filter(|s| s.domain == d).collect(),
                None => index.sets,
            };
            Ok(sets)
        }

        fn delete_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
            let mut index = read_credential_index()?;
            if !index.sets.iter().any(|s| s.id == id) {
                return Err(SfaeError::CredentialNotFound(id.to_string()));
            }

            // Remove from keychain (ignore if already gone)
            let entry = Self::entry(id)?;
            let _ = entry.delete_credential();

            index.sets.retain(|s| s.id != id);
            index.version = 2;
            write_credential_index(&index)?;

            Ok(())
        }
    }
}

#[cfg(feature = "native-keychain")]
pub use keyring_store::KeyringStore;

/// In-memory secret store for testing.
#[derive(Default)]
pub struct InMemoryStore {
    entries: HashMap<String, String>,
    credential_sets: Vec<CredentialSetInfo>,
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

    fn supports_credential_sets(&self) -> bool {
        true
    }

    fn store_credential_set(
        &mut self,
        domain: &str,
        label: Option<&str>,
        values: &HashMap<String, String>,
    ) -> Result<String, SfaeError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut keys: Vec<String> = values.keys().cloned().collect();
        keys.sort();

        let json = serde_json::to_string(values)?;
        self.entries.insert(id.clone(), json);

        self.credential_sets.push(CredentialSetInfo {
            id: id.clone(),
            domain: domain.to_string(),
            label: label.map(String::from),
            keys,
        });

        Ok(id)
    }

    fn list_credential_sets(
        &self,
        domain: Option<&str>,
    ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
        let sets = match domain {
            Some(d) => self
                .credential_sets
                .iter()
                .filter(|s| s.domain == d)
                .cloned()
                .collect(),
            None => self.credential_sets.clone(),
        };
        Ok(sets)
    }

    fn delete_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
        if !self.credential_sets.iter().any(|s| s.id == id) {
            return Err(SfaeError::CredentialNotFound(id.to_string()));
        }
        self.credential_sets.retain(|s| s.id != id);
        self.entries.remove(id);
        Ok(())
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
        assert_eq!(store.list_keys().unwrap(), vec!["a_KEY", "m_KEY", "z_KEY"]);
    }

    #[test]
    fn list_credential_types_for_domain() {
        let mut store = InMemoryStore::new();
        let mut github = HashMap::new();
        github.insert("API_KEY".to_string(), "key1".to_string());
        github.insert("ACCESS_TOKEN".to_string(), "tok1".to_string());
        store
            .store_credential_set("github.com", None, &github)
            .unwrap();

        let mut gitlab = HashMap::new();
        gitlab.insert("PASSWORD".to_string(), "pw".to_string());
        store
            .store_credential_set("gitlab.com", None, &gitlab)
            .unwrap();

        let types = list_credential_types(&store, "github.com", None).unwrap();
        assert_eq!(types, vec!["ACCESS_TOKEN", "API_KEY"]);

        let types = list_credential_types(&store, "gitlab.com", None).unwrap();
        assert_eq!(types, vec!["PASSWORD"]);

        let types = list_credential_types(&store, "unknown.com", None).unwrap();
        assert!(types.is_empty());
    }

    #[test]
    fn list_credential_types_with_label() {
        let mut store = InMemoryStore::new();
        let mut shared = HashMap::new();
        shared.insert("API_KEY".to_string(), "key1".to_string());
        store
            .store_credential_set("github.com", None, &shared)
            .unwrap();

        let mut user_creds = HashMap::new();
        user_creds.insert("PASSWORD".to_string(), "pw".to_string());
        store
            .store_credential_set("github.com", Some("aduermael"), &user_creds)
            .unwrap();

        // All sets for github.com (both sets' keys combined)
        let types = list_credential_types(&store, "github.com", None).unwrap();
        assert_eq!(types, vec!["API_KEY", "PASSWORD"]);

        // Filtered by label "aduermael": only PASSWORD
        let types = list_credential_types(&store, "github.com", Some("aduermael")).unwrap();
        assert_eq!(types, vec!["PASSWORD"]);
    }

    #[test]
    fn list_credential_types_custom() {
        let mut store = InMemoryStore::new();
        let mut ch = HashMap::new();
        ch.insert("HOST".to_string(), "h".to_string());
        ch.insert("USERNAME".to_string(), "u".to_string());
        ch.insert("PASSWORD".to_string(), "p".to_string());
        store
            .store_credential_set("clickhouse.cloud", None, &ch)
            .unwrap();

        let types = list_credential_types(&store, "clickhouse.cloud", None).unwrap();
        assert_eq!(types, vec!["HOST", "PASSWORD", "USERNAME"]);
    }

    // -- Credential set operation tests --

    #[test]
    fn store_credential_set_basic() {
        let mut store = InMemoryStore::new();
        let mut values = HashMap::new();
        values.insert("HOST".to_string(), "db.example.com".to_string());
        values.insert("PASSWORD".to_string(), "secret".to_string());

        let id = store
            .store_credential_set("example.com", None, &values)
            .unwrap();

        // ID is a valid UUID
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        // Blob is stored and parseable
        let blob = store.get(&id).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&blob).unwrap();
        assert_eq!(parsed.get("HOST").unwrap(), "db.example.com");
        assert_eq!(parsed.get("PASSWORD").unwrap(), "secret");

        // Metadata is tracked
        let sets = store.list_credential_sets(Some("example.com")).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].id, id);
        assert_eq!(sets[0].domain, "example.com");
        assert!(sets[0].label.is_none());
        assert_eq!(sets[0].keys, vec!["HOST", "PASSWORD"]); // sorted
    }

    #[test]
    fn list_credential_sets_filters_by_domain() {
        let mut store = InMemoryStore::new();
        let mut gh = HashMap::new();
        gh.insert("API_KEY".to_string(), "k".to_string());
        store.store_credential_set("github.com", None, &gh).unwrap();

        let mut gl = HashMap::new();
        gl.insert("PASSWORD".to_string(), "p".to_string());
        store.store_credential_set("gitlab.com", None, &gl).unwrap();

        assert_eq!(
            store
                .list_credential_sets(Some("github.com"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .list_credential_sets(Some("gitlab.com"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.list_credential_sets(None).unwrap().len(), 2);
        assert!(
            store
                .list_credential_sets(Some("unknown.com"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn delete_credential_set_removes_blob_and_metadata() {
        let mut store = InMemoryStore::new();
        let mut values = HashMap::new();
        values.insert("KEY".to_string(), "val".to_string());
        let id = store
            .store_credential_set("example.com", None, &values)
            .unwrap();

        store.delete_credential_set(&id).unwrap();

        assert!(store.list_credential_sets(None).unwrap().is_empty());
        assert!(store.get(&id).is_err());
    }

    #[test]
    fn delete_credential_set_not_found() {
        let mut store = InMemoryStore::new();
        assert!(matches!(
            store.delete_credential_set("nonexistent").unwrap_err(),
            SfaeError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn credential_set_with_label() {
        let mut store = InMemoryStore::new();
        let mut work = HashMap::new();
        work.insert("API_KEY".to_string(), "work_key".to_string());
        let id1 = store
            .store_credential_set("github.com", Some("Work"), &work)
            .unwrap();

        let mut personal = HashMap::new();
        personal.insert("API_KEY".to_string(), "personal_key".to_string());
        let id2 = store
            .store_credential_set("github.com", Some("Personal"), &personal)
            .unwrap();

        let sets = store.list_credential_sets(Some("github.com")).unwrap();
        assert_eq!(sets.len(), 2);

        // Each set has its own ID and label
        let s1 = sets.iter().find(|s| s.id == id1).unwrap();
        assert_eq!(s1.label.as_deref(), Some("Work"));
        let s2 = sets.iter().find(|s| s.id == id2).unwrap();
        assert_eq!(s2.label.as_deref(), Some("Personal"));
    }
}
