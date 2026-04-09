use sfae_core::proxy::{self, ProxyRequest, find_dynamic_placeholders};
use sfae_core::store::{InMemoryStore, SecretStore};

fn populated_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .set("api.example.com_ACCESS_TOKEN", "ghp_abc123")
        .unwrap();
    store.set("api.example.com_API_KEY", "key-xyz-789").unwrap();
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

    // Resolve URL
    let resolved_url =
        proxy::resolve_placeholders(&request.url, &store, "api.example.com", None).unwrap();
    assert_eq!(
        resolved_url,
        "https://api.example.com/v1/data?key=key-xyz-789"
    );

    // Resolve headers
    for (key, value) in &request.headers {
        let resolved = proxy::resolve_placeholders(value, &store, "api.example.com", None).unwrap();
        if key == "Authorization" {
            assert_eq!(resolved, "Bearer ghp_abc123");
        } else {
            assert_eq!(resolved, "application/json");
        }
    }

    // Resolve body
    let resolved_body = proxy::resolve_placeholders(
        request.body.as_ref().unwrap(),
        &store,
        "api.example.com",
        None,
    )
    .unwrap();
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

    let err =
        proxy::resolve_placeholders("{PASSWORD}", &store, "api.example.com", None).unwrap_err();
    assert!(matches!(
        err,
        sfae_core::SfaeError::CredentialNotFound(ref name) if name == "PASSWORD"
    ));
}

#[test]
fn store_crud_lifecycle() {
    let mut store = InMemoryStore::new();

    // Initially empty
    assert!(store.list_keys().unwrap().is_empty());

    // Add credentials
    store.set("github.com_API_KEY", "aaa").unwrap();
    store.set("github.com_ACCESS_TOKEN", "bbb").unwrap();
    assert_eq!(
        store.list_keys().unwrap(),
        vec!["github.com_ACCESS_TOKEN", "github.com_API_KEY"]
    );

    // Update
    store.set("github.com_API_KEY", "aaa_updated").unwrap();
    assert_eq!(store.get("github.com_API_KEY").unwrap(), "aaa_updated");
    assert_eq!(store.list_keys().unwrap().len(), 2);

    // Delete
    store.delete("github.com_ACCESS_TOKEN").unwrap();
    assert_eq!(store.list_keys().unwrap(), vec!["github.com_API_KEY"]);

    // Resolve using the updated store
    let resolved =
        proxy::resolve_placeholders("val={API_KEY}", &store, "github.com", None).unwrap();
    assert_eq!(resolved, "val=aaa_updated");
}

#[test]
fn username_scoped_credentials() {
    let mut store = InMemoryStore::new();
    store.set("github.com_API_KEY", "shared_key").unwrap();
    store
        .set("github.com_aduermael_PASSWORD", "user_pw")
        .unwrap();

    // Resolve without username — uses domain-level credential
    let result = proxy::resolve_placeholders("{API_KEY}", &store, "github.com", None).unwrap();
    assert_eq!(result, "shared_key");

    // Resolve with username — uses user-scoped credential
    let result =
        proxy::resolve_placeholders("{PASSWORD}", &store, "github.com", Some("aduermael")).unwrap();
    assert_eq!(result, "user_pw");
}
