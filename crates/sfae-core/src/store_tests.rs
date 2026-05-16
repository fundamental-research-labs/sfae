//! Unit tests for the in-memory secret store and credential-set index behavior.

use std::collections::HashMap;

use crate::error::SfaeError;
use crate::store::{
    CredentialSetInput, CredentialTypesQuery, InMemoryStore, SecretStore, StoreEntry,
    list_credential_types,
};

#[test]
fn set_and_get() {
    let mut store = InMemoryStore::new();
    store
        .set(StoreEntry {
            key: "github.com_API_KEY",
            value: "abc123",
        })
        .unwrap();
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
    store
        .set(StoreEntry {
            key: "k",
            value: "old",
        })
        .unwrap();
    store
        .set(StoreEntry {
            key: "k",
            value: "new",
        })
        .unwrap();
    assert_eq!(store.get("k").unwrap(), "new");
}

#[test]
fn delete_removes() {
    let mut store = InMemoryStore::new();
    store
        .set(StoreEntry {
            key: "k",
            value: "v",
        })
        .unwrap();
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
    store
        .set(StoreEntry {
            key: "z_KEY",
            value: "1",
        })
        .unwrap();
    store
        .set(StoreEntry {
            key: "a_KEY",
            value: "2",
        })
        .unwrap();
    store
        .set(StoreEntry {
            key: "m_KEY",
            value: "3",
        })
        .unwrap();
    assert_eq!(store.list_keys().unwrap(), vec!["a_KEY", "m_KEY", "z_KEY"]);
}

#[test]
fn list_credential_types_for_domain() {
    let mut store = InMemoryStore::new();
    let mut github = HashMap::new();
    github.insert("API_KEY".to_string(), "key1".to_string());
    github.insert("ACCESS_TOKEN".to_string(), "tok1".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: None,
            values: &github,
        })
        .unwrap();

    let mut gitlab = HashMap::new();
    gitlab.insert("PASSWORD".to_string(), "pw".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "gitlab.com",
            label: None,
            values: &gitlab,
        })
        .unwrap();

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "github.com",
        username: None,
    })
    .unwrap();
    assert_eq!(types, vec!["ACCESS_TOKEN", "API_KEY"]);

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "gitlab.com",
        username: None,
    })
    .unwrap();
    assert_eq!(types, vec!["PASSWORD"]);

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "unknown.com",
        username: None,
    })
    .unwrap();
    assert!(types.is_empty());
}

#[test]
fn list_credential_types_with_label() {
    let mut store = InMemoryStore::new();
    let mut shared = HashMap::new();
    shared.insert("API_KEY".to_string(), "key1".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: None,
            values: &shared,
        })
        .unwrap();

    let mut user_creds = HashMap::new();
    user_creds.insert("PASSWORD".to_string(), "pw".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: Some("aduermael"),
            values: &user_creds,
        })
        .unwrap();

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "github.com",
        username: None,
    })
    .unwrap();
    assert_eq!(types, vec!["API_KEY", "PASSWORD"]);

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "github.com",
        username: Some("aduermael"),
    })
    .unwrap();
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
        .store_credential_set(CredentialSetInput {
            domain: "clickhouse.cloud",
            label: None,
            values: &ch,
        })
        .unwrap();

    let types = list_credential_types(CredentialTypesQuery {
        store: &store,
        domain: "clickhouse.cloud",
        username: None,
    })
    .unwrap();
    assert_eq!(types, vec!["HOST", "PASSWORD", "USERNAME"]);
}

#[test]
fn store_credential_set_basic() {
    let mut store = InMemoryStore::new();
    let mut values = HashMap::new();
    values.insert("HOST".to_string(), "db.example.com".to_string());
    values.insert("PASSWORD".to_string(), "secret".to_string());

    let id = store
        .store_credential_set(CredentialSetInput {
            domain: "example.com",
            label: None,
            values: &values,
        })
        .unwrap();

    assert!(uuid::Uuid::parse_str(&id).is_ok());
    let blob = store.get(&id).unwrap();
    let parsed: HashMap<String, String> = serde_json::from_str(&blob).unwrap();
    assert_eq!(parsed.get("HOST").unwrap(), "db.example.com");
    assert_eq!(parsed.get("PASSWORD").unwrap(), "secret");

    let sets = store.list_credential_sets(Some("example.com")).unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].id, id);
    assert_eq!(sets[0].domain, "example.com");
    assert!(sets[0].label.is_none());
    assert_eq!(sets[0].keys, vec!["HOST", "PASSWORD"]);
}

#[test]
fn list_credential_sets_filters_by_domain() {
    let mut store = InMemoryStore::new();
    let mut gh = HashMap::new();
    gh.insert("API_KEY".to_string(), "k".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: None,
            values: &gh,
        })
        .unwrap();

    let mut gl = HashMap::new();
    gl.insert("PASSWORD".to_string(), "p".to_string());
    store
        .store_credential_set(CredentialSetInput {
            domain: "gitlab.com",
            label: None,
            values: &gl,
        })
        .unwrap();

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
        .store_credential_set(CredentialSetInput {
            domain: "example.com",
            label: None,
            values: &values,
        })
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
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: Some("Work"),
            values: &work,
        })
        .unwrap();

    let mut personal = HashMap::new();
    personal.insert("API_KEY".to_string(), "personal_key".to_string());
    let id2 = store
        .store_credential_set(CredentialSetInput {
            domain: "github.com",
            label: Some("Personal"),
            values: &personal,
        })
        .unwrap();

    let sets = store.list_credential_sets(Some("github.com")).unwrap();
    assert_eq!(sets.len(), 2);
    let s1 = sets.iter().find(|s| s.id == id1).unwrap();
    assert_eq!(s1.label.as_deref(), Some("Work"));
    let s2 = sets.iter().find(|s| s.id == id2).unwrap();
    assert_eq!(s2.label.as_deref(), Some("Personal"));
}
