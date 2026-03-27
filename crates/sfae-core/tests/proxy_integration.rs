use sfae_core::credential::Credential;
use sfae_core::proxy::{self, ProxyRequest};
use sfae_core::store::{InMemoryStore, SecretStore};

fn populated_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .set(
            "github_token",
            &Credential::AccessToken {
                token: "ghp_abc123".to_string(),
            },
        )
        .unwrap();
    store
        .set(
            "api_key",
            &Credential::AccessToken {
                token: "key-xyz-789".to_string(),
            },
        )
        .unwrap();
    store
}

#[test]
fn full_request_resolution() {
    let store = populated_store();

    let request = ProxyRequest {
        method: "POST".to_string(),
        url: "https://api.example.com/v1/data?key={{sfae:api_key}}".to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                "Bearer {{sfae:github_token}}".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: Some(r#"{"token": "{{sfae:api_key}}"}"#.to_string()),
    };

    // Resolve URL
    let resolved_url = proxy::resolve_placeholders(&request.url, &store).unwrap();
    assert_eq!(
        resolved_url,
        "https://api.example.com/v1/data?key=key-xyz-789"
    );

    // Resolve headers
    for (key, value) in &request.headers {
        let resolved = proxy::resolve_placeholders(value, &store).unwrap();
        if key == "Authorization" {
            assert_eq!(resolved, "Bearer ghp_abc123");
        } else {
            assert_eq!(resolved, "application/json");
        }
    }

    // Resolve body
    let resolved_body =
        proxy::resolve_placeholders(request.body.as_ref().unwrap(), &store).unwrap();
    assert_eq!(resolved_body, r#"{"token": "key-xyz-789"}"#);
}

#[test]
fn placeholder_discovery_across_request() {
    let request = ProxyRequest {
        method: "GET".to_string(),
        url: "https://api.example.com/{{sfae:path_token}}/resource".to_string(),
        headers: vec![(
            "Authorization".to_string(),
            "Bearer {{sfae:auth_token}}".to_string(),
        )],
        body: Some("data={{sfae:body_secret}}".to_string()),
    };

    // Collect all placeholders across the full request.
    let mut all_names: Vec<String> = Vec::new();
    for handle in proxy::find_placeholders(&request.url) {
        all_names.push(handle.name);
    }
    for (_, value) in &request.headers {
        for handle in proxy::find_placeholders(value) {
            all_names.push(handle.name);
        }
    }
    if let Some(body) = &request.body {
        for handle in proxy::find_placeholders(body) {
            all_names.push(handle.name);
        }
    }

    all_names.sort();
    assert_eq!(all_names, vec!["auth_token", "body_secret", "path_token"]);
}

#[test]
fn resolution_fails_on_first_missing_credential() {
    let store = populated_store(); // has github_token and api_key

    let request = ProxyRequest {
        method: "GET".to_string(),
        url: "https://example.com".to_string(),
        headers: vec![(
            "Authorization".to_string(),
            "Bearer {{sfae:nonexistent}}".to_string(),
        )],
        body: None,
    };

    let err = proxy::resolve_placeholders(&request.headers[0].1, &store).unwrap_err();
    assert!(matches!(err, sfae_core::SfaeError::CredentialNotFound(name) if name == "nonexistent"));
}

#[test]
fn store_crud_lifecycle() {
    let mut store = InMemoryStore::new();

    // Initially empty
    assert!(store.list().unwrap().is_empty());

    // Add credentials
    store
        .set(
            "token_a",
            &Credential::AccessToken {
                token: "aaa".to_string(),
            },
        )
        .unwrap();
    store
        .set(
            "token_b",
            &Credential::AccessToken {
                token: "bbb".to_string(),
            },
        )
        .unwrap();
    assert_eq!(store.list().unwrap(), vec!["token_a", "token_b"]);

    // Update
    store
        .set(
            "token_a",
            &Credential::AccessToken {
                token: "aaa_updated".to_string(),
            },
        )
        .unwrap();
    assert_eq!(store.get("token_a").unwrap().secret_value(), "aaa_updated");
    assert_eq!(store.list().unwrap().len(), 2);

    // Delete
    store.delete("token_b").unwrap();
    assert_eq!(store.list().unwrap(), vec!["token_a"]);

    // Resolve using the updated store
    let resolved = proxy::resolve_placeholders("val={{sfae:token_a}}", &store).unwrap();
    assert_eq!(resolved, "val=aaa_updated");
}
