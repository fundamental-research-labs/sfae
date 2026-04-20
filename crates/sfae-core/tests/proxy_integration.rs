//! End-to-end proxy tests covering placeholder resolution against an in-memory store.

use std::collections::HashMap;

use sfae_core::proxy::{CredentialLookup, ProxyRequest, find_dynamic_placeholders};
use sfae_core::store::{InMemoryStore, SecretStore};

fn populated_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    let mut creds = HashMap::new();
    creds.insert("ACCESS_TOKEN".to_string(), "ghp_abc123".to_string());
    creds.insert("API_KEY".to_string(), "key-xyz-789".to_string());
    store
        .store_credential_set(sfae_core::store::CredentialSetInput {
            domain: "api.example.com",
            label: None,
            values: &creds,
        })
        .unwrap();
    store
}

#[test]
fn full_request_resolution() {
    let store = populated_store();

    let request = ProxyRequest {
        method: "POST".to_string(),
        url: "https://api.example.com/v1/data?key={API_KEY}".to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                "Bearer {ACCESS_TOKEN}".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: Some(r#"{"token": "{API_KEY}"}"#.to_string()),
    };

    let lookup = CredentialLookup {
        store: &store,
        domain: "api.example.com",
        username: None,
        cred_id: None,
    };

    // Resolve URL
    let resolved_url = lookup.resolve(&request.url).unwrap();
    assert_eq!(
        resolved_url,
        "https://api.example.com/v1/data?key=key-xyz-789"
    );

    // Resolve headers
    for (key, value) in &request.headers {
        let resolved = lookup.resolve(value).unwrap();
        if key == "Authorization" {
            assert_eq!(resolved, "Bearer ghp_abc123");
        } else {
            assert_eq!(resolved, "application/json");
        }
    }

    // Resolve body
    let resolved_body = lookup.resolve(request.body.as_ref().unwrap()).unwrap();
    assert_eq!(resolved_body, r#"{"token": "key-xyz-789"}"#);
}

#[test]
fn placeholder_discovery_across_request() {
    let request = ProxyRequest {
        method: "GET".to_string(),
        url: "https://api.example.com/resource?key={API_KEY}".to_string(),
        headers: vec![(
            "Authorization".to_string(),
            "Bearer {ACCESS_TOKEN}".to_string(),
        )],
        body: Some("data={PASSWORD}".to_string()),
    };

    let mut all_keys: Vec<String> = Vec::new();
    all_keys.extend(find_dynamic_placeholders(&request.url));
    for (_, value) in &request.headers {
        all_keys.extend(find_dynamic_placeholders(value));
    }
    if let Some(body) = &request.body {
        all_keys.extend(find_dynamic_placeholders(body));
    }

    all_keys.sort();
    all_keys.dedup();
    assert_eq!(all_keys, vec!["ACCESS_TOKEN", "API_KEY", "PASSWORD"]);
}

#[test]
fn resolution_fails_on_missing_credential() {
    let store = populated_store(); // has ACCESS_TOKEN and API_KEY for api.example.com

    let err = CredentialLookup {
        store: &store,
        domain: "api.example.com",
        username: None,
        cred_id: None,
    }
    .resolve("{PASSWORD}")
    .unwrap_err();
    assert!(matches!(
        err,
        sfae_core::SfaeError::CredentialNotFound(ref name) if name == "PASSWORD"
    ));
}

#[test]
fn credential_set_lifecycle() {
    let mut store = InMemoryStore::new();
    assert!(store.list_credential_sets(None).unwrap().is_empty());

    // Store a credential set
    let mut creds = HashMap::new();
    creds.insert("API_KEY".to_string(), "aaa".to_string());
    creds.insert("ACCESS_TOKEN".to_string(), "bbb".to_string());
    let id = store
        .store_credential_set(sfae_core::store::CredentialSetInput {
            domain: "github.com",
            label: None,
            values: &creds,
        })
        .unwrap();

    let sets = store.list_credential_sets(None).unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].domain, "github.com");
    assert_eq!(sets[0].keys, vec!["ACCESS_TOKEN", "API_KEY"]); // sorted

    // Resolve using proxy
    let resolved = CredentialLookup {
        store: &store,
        domain: "github.com",
        username: None,
        cred_id: None,
    }
    .resolve("val={API_KEY}")
    .unwrap();
    assert_eq!(resolved, "val=aaa");

    // Delete credential set
    store.delete_credential_set(&id).unwrap();
    assert!(store.list_credential_sets(None).unwrap().is_empty());

    // Resolution now fails
    let err = CredentialLookup {
        store: &store,
        domain: "github.com",
        username: None,
        cred_id: None,
    }
    .resolve("{API_KEY}")
    .unwrap_err();
    assert!(matches!(err, sfae_core::SfaeError::CredentialNotFound(_)));
}

#[test]
fn label_scoped_credentials() {
    let mut store = InMemoryStore::new();

    let mut shared = HashMap::new();
    shared.insert("API_KEY".to_string(), "shared_key".to_string());
    store
        .store_credential_set(sfae_core::store::CredentialSetInput {
            domain: "github.com",
            label: None,
            values: &shared,
        })
        .unwrap();

    let mut user_creds = HashMap::new();
    user_creds.insert("PASSWORD".to_string(), "user_pw".to_string());
    store
        .store_credential_set(sfae_core::store::CredentialSetInput {
            domain: "github.com",
            label: Some("aduermael"),
            values: &user_creds,
        })
        .unwrap();

    // Resolve with label filter — gets the labeled set
    let result = CredentialLookup {
        store: &store,
        domain: "github.com",
        username: Some("aduermael"),
        cred_id: None,
    }
    .resolve("{PASSWORD}")
    .unwrap();
    assert_eq!(result, "user_pw");

    // Multiple sets without label filter → error
    let err = CredentialLookup {
        store: &store,
        domain: "github.com",
        username: None,
        cred_id: None,
    }
    .resolve("{API_KEY}")
    .unwrap_err();
    assert!(matches!(err, sfae_core::SfaeError::Other(_)));
}
