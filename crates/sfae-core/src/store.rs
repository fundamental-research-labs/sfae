//! Secret-store abstraction plus the OS-keychain and in-memory implementations.
//!
//! Defines the `SecretStore` trait used by every credential lookup and write
//! across the CLI and server.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::SfaeError;

/// Public index data about a stored credential set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSetInfo {
    pub id: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// A single `(key, value)` pair to persist via `SecretStore::set`.
pub struct StoreEntry<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// Input for `SecretStore::store_credential_set`.
pub struct CredentialSetInput<'a> {
    pub domain: &'a str,
    pub label: Option<&'a str>,
    pub values: &'a HashMap<String, String>,
}

/// Input for `SecretStore::store_structured_credential_set`.
pub struct StructuredCredentialSetInput<'a> {
    pub domain: &'a str,
    pub label: Option<&'a str>,
    pub values: &'a HashMap<String, String>,
    pub internal: Option<&'a HashMap<String, String>>,
    pub metadata: Option<&'a HashMap<String, String>>,
}

/// Input for merging refreshed material into an existing structured credential set.
pub struct StructuredCredentialSetUpdate<'a> {
    pub id: &'a str,
    pub values: Option<&'a HashMap<String, String>>,
    pub internal: Option<&'a HashMap<String, String>>,
    pub metadata: Option<&'a HashMap<String, String>>,
}

/// Parameters for `list_credential_types`.
pub struct CredentialTypesQuery<'a> {
    pub store: &'a dyn SecretStore,
    pub domain: &'a str,
    pub username: Option<&'a str>,
}

/// Abstraction over secret storage backends.
pub trait SecretStore {
    /// Store a secret value under the given key.
    fn set(&mut self, entry: StoreEntry<'_>) -> Result<(), SfaeError>;

    /// Retrieve a secret value by key.
    fn get(&self, key: &str) -> Result<String, SfaeError>;

    /// Delete a secret by key.
    fn delete(&mut self, key: &str) -> Result<(), SfaeError>;

    /// Forget a key from SFAE's public index without requiring secret access when possible.
    fn forget(&mut self, key: &str) -> Result<(), SfaeError> {
        self.delete(key)
    }

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
        _input: CredentialSetInput<'_>,
    ) -> Result<String, SfaeError> {
        Err(SfaeError::Other(
            "credential set operations not supported by this store".into(),
        ))
    }

    /// Store a credential set with separate injectable, internal, and metadata compartments.
    fn store_structured_credential_set(
        &mut self,
        input: StructuredCredentialSetInput<'_>,
    ) -> Result<String, SfaeError> {
        if input.internal.is_some_and(|m| !m.is_empty())
            || input.metadata.is_some_and(|m| !m.is_empty())
        {
            return Err(SfaeError::Other(
                "structured credential compartments are not supported by this store".into(),
            ));
        }
        self.store_credential_set(CredentialSetInput {
            domain: input.domain,
            label: input.label,
            values: input.values,
        })
    }

    /// Merge structured credential material into an existing credential set.
    fn update_structured_credential_set(
        &mut self,
        _input: StructuredCredentialSetUpdate<'_>,
    ) -> Result<(), SfaeError> {
        Err(SfaeError::Other(
            "credential set update operations not supported by this store".into(),
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

    /// Forget a credential set from SFAE's public index without requiring secret access when possible.
    fn forget_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
        self.delete_credential_set(id)
    }
}

const STRUCTURED_CREDENTIAL_SCHEMA: &str = "sfae.credential-set.v1";
const INTERNAL_ONLY_KEYS: &[&str] = &[
    "OAUTH_REFRESH_TOKEN",
    "OAUTH_BROKER_CREDENTIAL_ID",
    "OAUTH_BROKER_CREDENTIAL_SECRET",
];

/// Parsed credential-set compartments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialSetData {
    pub values: HashMap<String, String>,
    pub internal: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize)]
struct StoredCredentialSetBlob<'a> {
    schema: &'static str,
    values: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internal: Option<&'a HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a HashMap<String, String>>,
}

#[derive(Deserialize)]
struct ParsedCredentialSetBlob {
    values: HashMap<String, String>,
    #[serde(default)]
    internal: HashMap<String, String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

/// Serialize a structured credential blob for durable secret storage.
pub fn serialize_structured_credential_set(
    input: &StructuredCredentialSetInput<'_>,
) -> Result<String, SfaeError> {
    validate_injectable_values(input.values)?;
    serialize_credential_set_data(&CredentialSetData {
        values: input.values.clone(),
        internal: input.internal.cloned().unwrap_or_default(),
        metadata: input.metadata.cloned().unwrap_or_default(),
    })
}

/// Serialize credential-set compartments for durable secret storage.
pub fn serialize_credential_set_data(data: &CredentialSetData) -> Result<String, SfaeError> {
    validate_injectable_values(&data.values)?;
    let internal = (!data.internal.is_empty()).then_some(&data.internal);
    let metadata = (!data.metadata.is_empty()).then_some(&data.metadata);
    serde_json::to_string(&StoredCredentialSetBlob {
        schema: STRUCTURED_CREDENTIAL_SCHEMA,
        values: &data.values,
        internal,
        metadata,
    })
    .map_err(|e| SfaeError::StoreError(format!("failed to serialize: {e}")))
}

/// Parse all compartments from a credential blob.
///
/// Older credential sets are plain `{FIELD: value}` maps; they parse as
/// injectable values with empty internal and metadata compartments.
pub fn parse_structured_credential_set(blob: &str) -> Result<CredentialSetData, SfaeError> {
    let raw: serde_json::Value = serde_json::from_str(blob)
        .map_err(|e| SfaeError::StoreError(format!("invalid credential blob JSON: {e}")))?;
    if raw.get("values").is_some() {
        let parsed: ParsedCredentialSetBlob = serde_json::from_value(raw)
            .map_err(|e| SfaeError::StoreError(format!("invalid credential blob JSON: {e}")))?;
        return Ok(CredentialSetData {
            values: parsed.values,
            internal: parsed.internal,
            metadata: parsed.metadata,
        });
    }
    let values = serde_json::from_value(raw)
        .map_err(|e| SfaeError::StoreError(format!("invalid credential blob JSON: {e}")))?;
    Ok(CredentialSetData {
        values,
        internal: HashMap::new(),
        metadata: HashMap::new(),
    })
}

/// Parse only the injectable `values` compartment from a credential blob.
///
/// Older credential sets are plain `{FIELD: value}` JSON maps; newer OAuth
/// sets are structured so internal refresh/revoke material cannot be resolved
/// by request placeholders.
pub fn parse_injectable_credential_values(
    blob: &str,
) -> Result<HashMap<String, String>, SfaeError> {
    let mut values = parse_structured_credential_set(blob)?.values;
    values.retain(|key, _| !internal_only_key(key));
    Ok(values)
}

/// Load one credential set's public index fields and metadata by UUID.
// xtask: allow-multi-param - helper pairs selected store with credential id
pub fn load_credential_set_metadata(
    store: &dyn SecretStore,
    id: &str,
) -> Result<CredentialSetInfo, SfaeError> {
    if !store.supports_credential_sets() {
        return Err(SfaeError::Other(
            "credential set operations not supported by this store".into(),
        ));
    }
    store
        .list_credential_sets(None)?
        .into_iter()
        .find(|set| set.id == id)
        .ok_or_else(|| SfaeError::CredentialNotFound(id.to_string()))
}

// xtask: allow-multi-param - merge helper pairs current data with update input
fn merge_structured_credential_data(
    current: &mut CredentialSetData,
    update: &StructuredCredentialSetUpdate<'_>,
) {
    if let Some(values) = update.values {
        current.values.extend(values.clone());
    }
    if let Some(internal) = update.internal {
        current.internal.extend(internal.clone());
    }
    if let Some(metadata) = update.metadata {
        current.metadata.extend(metadata.clone());
    }
}

fn validate_injectable_values(values: &HashMap<String, String>) -> Result<(), SfaeError> {
    if let Some(key) = values.keys().find(|key| internal_only_key(key)) {
        return Err(SfaeError::StoreError(format!(
            "{key} is reserved for internal credential storage"
        )));
    }
    Ok(())
}

fn internal_only_key(key: &str) -> bool {
    INTERNAL_ONLY_KEYS.contains(&key)
}

/// List credential types stored for a domain (and optional username/label).
///
/// Returns the raw type strings (e.g. `"ACCESS_TOKEN"`, `"HOST"`, `"USERNAME"`)
/// extracted from credential sets (new path) or flat keys (legacy fallback).
///
/// The `username` parameter maps to credential set labels when using the new
/// credential set storage. When `None`, returns keys from all sets for the domain.
pub fn list_credential_types(query: CredentialTypesQuery<'_>) -> Result<Vec<String>, SfaeError> {
    let CredentialTypesQuery {
        store,
        domain,
        username,
    } = query;
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
    let home = dirs::home_dir()
        .ok_or_else(|| SfaeError::ConfigError("cannot determine home directory".into()))?;
    Ok(home.join(".sfae"))
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

fn forget_index_key(key: &str) -> Result<(), SfaeError> {
    let mut keys = read_index()?;
    if !keys.contains(&key.to_string()) {
        return Err(SfaeError::CredentialNotFound(key.to_string()));
    }
    keys.retain(|k| k != key);
    write_index(&keys)
}

fn forget_index_credential_set(id: &str) -> Result<(), SfaeError> {
    let mut index = read_credential_index()?;
    if !index.sets.iter().any(|s| s.id == id) {
        return Err(SfaeError::CredentialNotFound(id.to_string()));
    }
    index.sets.retain(|s| s.id != id);
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

    /// Secret store backed by the macOS login keychain via modern SecItem APIs.
    ///
    /// The login keychain ties item access to the app's **code signing identity**.
    /// When the binary is signed with a stable identity (see `make build`),
    /// rebuilds don't trigger password prompts — the keychain recognizes the
    /// same signing identity across builds.
    ///
    /// Credential keys are tracked in a local index file
    /// (`~/.sfae/credentials.json`). Only keys live in the index; actual
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
        fn set(&mut self, entry: StoreEntry<'_>) -> Result<(), SfaeError> {
            let StoreEntry { key, value } = entry;
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

        fn forget(&mut self, key: &str) -> Result<(), SfaeError> {
            forget_index_key(key)
        }

        fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
            read_index()
        }

        fn supports_credential_sets(&self) -> bool {
            true
        }

        fn store_credential_set(
            &mut self,
            input: CredentialSetInput<'_>,
        ) -> Result<String, SfaeError> {
            let CredentialSetInput {
                domain,
                label,
                values,
            } = input;
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
                metadata: HashMap::new(),
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn store_structured_credential_set(
            &mut self,
            input: StructuredCredentialSetInput<'_>,
        ) -> Result<String, SfaeError> {
            let id = uuid::Uuid::new_v4().to_string();
            let mut keys: Vec<String> = input.values.keys().cloned().collect();
            keys.sort();

            let json = serialize_structured_credential_set(&input)?;
            set_generic_password(KEYRING_SERVICE, &id, json.as_bytes())
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            let mut index = read_credential_index()?;
            index.sets.push(CredentialSetInfo {
                id: id.clone(),
                domain: input.domain.to_string(),
                label: input.label.map(String::from),
                keys,
                metadata: input.metadata.cloned().unwrap_or_default(),
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn update_structured_credential_set(
            &mut self,
            input: StructuredCredentialSetUpdate<'_>,
        ) -> Result<(), SfaeError> {
            let bytes = match get_generic_password(KEYRING_SERVICE, input.id) {
                Ok(bytes) => bytes,
                Err(e) if is_not_found(&e) => {
                    return Err(SfaeError::CredentialNotFound(input.id.to_string()));
                }
                Err(e) => return Err(SfaeError::StoreError(e.to_string())),
            };
            let blob = String::from_utf8(bytes)
                .map_err(|e| SfaeError::StoreError(format!("invalid UTF-8: {e}")))?;
            let mut data = parse_structured_credential_set(&blob)?;
            merge_structured_credential_data(&mut data, &input);
            let json = serialize_credential_set_data(&data)?;
            let mut index = read_credential_index()?;
            let Some(set_index) = index.sets.iter().position(|s| s.id == input.id) else {
                return Err(SfaeError::CredentialNotFound(input.id.to_string()));
            };
            set_generic_password(KEYRING_SERVICE, input.id, json.as_bytes())
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            index.sets[set_index].keys = data.values.keys().cloned().collect();
            index.sets[set_index].keys.sort();
            index.sets[set_index].metadata = data.metadata;
            index.version = 2;
            write_credential_index(&index)?;
            Ok(())
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

        fn forget_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
            forget_index_credential_set(id)
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
    /// (`~/.sfae/credentials.json`). Only keys live in the index; actual
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
        fn set(&mut self, entry: StoreEntry<'_>) -> Result<(), SfaeError> {
            let StoreEntry { key, value } = entry;
            let kr = Self::entry(key)?;
            kr.set_password(value)
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

        fn forget(&mut self, key: &str) -> Result<(), SfaeError> {
            forget_index_key(key)
        }

        fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
            read_index()
        }

        fn supports_credential_sets(&self) -> bool {
            true
        }

        fn store_credential_set(
            &mut self,
            input: CredentialSetInput<'_>,
        ) -> Result<String, SfaeError> {
            let CredentialSetInput {
                domain,
                label,
                values,
            } = input;
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
                metadata: HashMap::new(),
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn store_structured_credential_set(
            &mut self,
            input: StructuredCredentialSetInput<'_>,
        ) -> Result<String, SfaeError> {
            let id = uuid::Uuid::new_v4().to_string();
            let mut keys: Vec<String> = input.values.keys().cloned().collect();
            keys.sort();

            let json = serialize_structured_credential_set(&input)?;
            let entry = Self::entry(&id)?;
            entry
                .set_password(&json)
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            let mut index = read_credential_index()?;
            index.sets.push(CredentialSetInfo {
                id: id.clone(),
                domain: input.domain.to_string(),
                label: input.label.map(String::from),
                keys,
                metadata: input.metadata.cloned().unwrap_or_default(),
            });
            index.version = 2;
            write_credential_index(&index)?;

            Ok(id)
        }

        fn update_structured_credential_set(
            &mut self,
            input: StructuredCredentialSetUpdate<'_>,
        ) -> Result<(), SfaeError> {
            let blob = self.get(input.id)?;
            let mut data = parse_structured_credential_set(&blob)?;
            merge_structured_credential_data(&mut data, &input);
            let json = serialize_credential_set_data(&data)?;
            let mut index = read_credential_index()?;
            let Some(set_index) = index.sets.iter().position(|s| s.id == input.id) else {
                return Err(SfaeError::CredentialNotFound(input.id.to_string()));
            };
            let entry = Self::entry(input.id)?;
            entry
                .set_password(&json)
                .map_err(|e| SfaeError::StoreError(e.to_string()))?;

            index.sets[set_index].keys = data.values.keys().cloned().collect();
            index.sets[set_index].keys.sort();
            index.sets[set_index].metadata = data.metadata;
            index.version = 2;
            write_credential_index(&index)?;
            Ok(())
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

        fn forget_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
            forget_index_credential_set(id)
        }
    }
}

#[cfg(feature = "native-keychain")]
pub use keyring_store::KeyringStore;

#[path = "memory_store.rs"]
mod memory_store;
pub use memory_store::InMemoryStore;

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
