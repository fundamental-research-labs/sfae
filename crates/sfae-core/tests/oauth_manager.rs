//! Unit-style coverage for hosted OAuth manager behavior and provider resolution.

use std::cell::RefCell;
use std::collections::HashMap;

use sfae_core::SfaeError;
use sfae_core::oauth::{
    BackendProxyConfig, BackendProxyHostedOAuthBroker, DirectHostedOAuthBroker, HostedOAuthBroker,
    HostedOAuthCredential, HostedOAuthProvider, HostedOAuthProviderRegistry, HostedOAuthRefresh,
    HostedOAuthRevoke, HostedOAuthStart, HostedOAuthStatus, HostedProviderResolve,
    OAuthCredentialManager, StartedHostedOAuthSession, redeem_challenge, resolve_hosted_provider,
};

struct MockHostedOAuthBroker {
    credential: HostedOAuthCredential,
    redeemed: RefCell<Vec<String>>,
    refreshed: RefCell<Vec<String>>,
    revoked: RefCell<Vec<String>>,
}

impl HostedOAuthBroker for MockHostedOAuthBroker {
    fn provider_registry(&self) -> Result<HostedOAuthProviderRegistry, SfaeError> {
        Ok(test_provider_registry())
    }

    fn start_session(
        &self,
        _input: HostedOAuthStart<'_>,
    ) -> Result<StartedHostedOAuthSession, SfaeError> {
        Ok(StartedHostedOAuthSession {
            session_id: "session-1".to_string(),
            authorization_url: "https://oauth.example/authorize".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            redeem_verifier: Some("verifier".to_string()),
        })
    }

    fn session_status(&self, session_id: &str) -> Result<HostedOAuthStatus, SfaeError> {
        Ok(HostedOAuthStatus {
            session_id: session_id.to_string(),
            provider: "discord".to_string(),
            domain: "discord.com".to_string(),
            label: None,
            scopes: vec!["scope.read".to_string()],
            status: "success".to_string(),
            error_code: None,
            provider_subject: Some("123".to_string()),
            credential_id: None,
            expires_at: "2026-01-01T00:00:00Z".to_string(),
        })
    }

    // xtask: allow-multi-param - mock records session id and verifier
    fn redeem_session(
        &self,
        session_id: &str,
        redeem_verifier: &str,
        completion_verifier: &str,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        self.redeemed.borrow_mut().push(format!(
            "{session_id}:{redeem_verifier}:{completion_verifier}"
        ));
        Ok(self.credential.clone())
    }

    fn refresh_credential(
        &self,
        input: HostedOAuthRefresh<'_>,
    ) -> Result<HostedOAuthCredential, SfaeError> {
        self.refreshed.borrow_mut().push(format!(
            "{}:{}:{}:{}",
            input.provider,
            input.broker_credential_id,
            input.broker_credential_secret,
            input.refresh_token
        ));
        Ok(self.credential.clone())
    }

    fn revoke_credential(&self, input: HostedOAuthRevoke<'_>) -> Result<(), SfaeError> {
        self.revoked.borrow_mut().push(format!(
            "{}:{}:{}:{}:{}",
            input.provider,
            input.broker_credential_id,
            input.broker_credential_secret,
            input.access_token.unwrap_or("-"),
            input.refresh_token.unwrap_or("-")
        ));
        Ok(())
    }
}

fn test_provider_registry() -> HostedOAuthProviderRegistry {
    HostedOAuthProviderRegistry {
        providers: vec![
            HostedOAuthProvider {
                provider: "discord".to_string(),
                domains: vec!["discord.com".to_string()],
            },
            HostedOAuthProvider {
                provider: "google".to_string(),
                domains: vec!["googleapis.com".to_string()],
            },
            HostedOAuthProvider {
                provider: "github".to_string(),
                domains: vec!["github.com".to_string()],
            },
        ],
    }
}

fn mock_broker_with_access_token(access_token: &str) -> MockHostedOAuthBroker {
    let mut values = HashMap::new();
    values.insert("OAUTH_ACCESS_TOKEN".to_string(), access_token.to_string());
    MockHostedOAuthBroker {
        credential: HostedOAuthCredential {
            values,
            internal: HashMap::new(),
            metadata: HashMap::new(),
        },
        redeemed: RefCell::new(vec![]),
        refreshed: RefCell::new(vec![]),
        revoked: RefCell::new(vec![]),
    }
}

#[test]
fn manager_redeems_through_broker() {
    let broker = mock_broker_with_access_token("access");
    let manager = OAuthCredentialManager::new(&broker);
    let credential = manager
        .redeem_session("session-1", Some("verifier"), Some("completion"))
        .unwrap()
        .unwrap();

    assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "access");
    assert_eq!(
        broker.redeemed.borrow().as_slice(),
        ["session-1:verifier:completion"]
    );
}

#[test]
fn manager_skips_redeem_when_session_has_no_verifier() {
    let broker = mock_broker_with_access_token("access");
    let manager = OAuthCredentialManager::new(&broker);

    assert!(
        manager
            .redeem_session("session-1", None, Some("completion"))
            .unwrap()
            .is_none()
    );
    assert!(broker.redeemed.borrow().is_empty());
}

#[test]
fn manager_refreshes_and_revokes_through_broker() {
    let broker = mock_broker_with_access_token("new-access");
    let manager = OAuthCredentialManager::new(&broker);

    let credential = manager
        .refresh_credential(HostedOAuthRefresh {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "grant-secret",
            refresh_token: "refresh",
        })
        .unwrap();
    assert_eq!(credential.values["OAUTH_ACCESS_TOKEN"], "new-access");
    manager
        .revoke_credential(HostedOAuthRevoke {
            provider: "discord",
            broker_credential_id: "grant-id",
            broker_credential_secret: "grant-secret",
            access_token: Some("access"),
            refresh_token: Some("refresh"),
        })
        .unwrap();

    assert_eq!(
        broker.refreshed.borrow().as_slice(),
        ["discord:grant-id:grant-secret:refresh"]
    );
    assert_eq!(
        broker.revoked.borrow().as_slice(),
        ["discord:grant-id:grant-secret:access:refresh"]
    );
}

#[test]
fn redeem_challenge_is_stable_and_not_plaintext() {
    let challenge = redeem_challenge("verifier");
    assert_eq!(challenge, redeem_challenge("verifier"));
    assert_ne!(challenge, "verifier");
    assert!(!challenge.contains('='));
}

#[test]
fn resolves_explicit_discord_provider() {
    let provider = resolve_hosted_provider(HostedProviderResolve {
        domain: "example.com",
        requested_provider: Some("discord"),
        registry: &test_provider_registry(),
    })
    .unwrap();
    assert_eq!(provider, "discord");
}

#[test]
fn resolves_discord_from_domain() {
    let provider = resolve_hosted_provider(HostedProviderResolve {
        domain: "discord.com",
        requested_provider: None,
        registry: &test_provider_registry(),
    })
    .unwrap();
    assert_eq!(provider, "discord");
}

#[test]
fn resolves_discord_from_subdomain() {
    let provider = resolve_hosted_provider(HostedProviderResolve {
        domain: "api.discord.com",
        requested_provider: None,
        registry: &test_provider_registry(),
    })
    .unwrap();
    assert_eq!(provider, "discord");
}

#[test]
fn resolves_google_provider_and_googleapis_subdomains() {
    for domain in [
        "googleapis.com",
        "gmail.googleapis.com",
        "docs.googleapis.com",
        "sheets.googleapis.com",
        "people.googleapis.com",
        "www.googleapis.com",
    ] {
        let provider = resolve_hosted_provider(HostedProviderResolve {
            domain,
            requested_provider: None,
            registry: &test_provider_registry(),
        })
        .unwrap();
        assert_eq!(provider, "google");
    }
}

#[test]
fn resolves_explicit_google_provider() {
    let provider = resolve_hosted_provider(HostedProviderResolve {
        domain: "example.com",
        requested_provider: Some("google"),
        registry: &test_provider_registry(),
    })
    .unwrap();
    assert_eq!(provider, "google");
}

#[test]
fn resolves_github_provider() {
    let provider = resolve_hosted_provider(HostedProviderResolve {
        domain: "api.github.com",
        requested_provider: None,
        registry: &test_provider_registry(),
    })
    .unwrap();
    assert_eq!(provider, "github");
}

#[test]
fn rejects_unknown_provider() {
    let err = resolve_hosted_provider(HostedProviderResolve {
        domain: "example.com",
        requested_provider: Some("slack"),
        registry: &test_provider_registry(),
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported hosted OAuth provider")
    );
}

#[test]
fn rejects_unknown_domain_without_provider() {
    let err = resolve_hosted_provider(HostedProviderResolve {
        domain: "example.com",
        requested_provider: None,
        registry: &test_provider_registry(),
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("supported providers: discord, github, google")
    );
}

#[test]
fn direct_broker_allows_production_and_loopback_urls() {
    assert!(DirectHostedOAuthBroker::new("https://oauth.sfae.io").is_ok());
    assert!(DirectHostedOAuthBroker::new("http://127.0.0.1:3100").is_ok());
    assert!(DirectHostedOAuthBroker::new("http://localhost:3100").is_ok());
}

#[test]
fn direct_broker_rejects_unknown_urls() {
    assert!(DirectHostedOAuthBroker::new("http://oauth.sfae.io").is_err());
    assert!(DirectHostedOAuthBroker::new("https://evil.example").is_err());
}

#[test]
fn backend_proxy_rejects_empty_explicit_config() {
    assert!(
        BackendProxyHostedOAuthBroker::new(BackendProxyConfig {
            base_url: "",
            token: "store-token",
        })
        .is_err()
    );
    assert!(
        BackendProxyHostedOAuthBroker::new(BackendProxyConfig {
            base_url: "http://127.0.0.1:3100",
            token: " ",
        })
        .is_err()
    );
}
