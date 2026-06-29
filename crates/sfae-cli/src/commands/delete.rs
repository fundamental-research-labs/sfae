//! `sfae delete`: forget credential sets or legacy flat credentials.

use std::collections::HashSet;

use sfae_core::credential::{CredentialKey, CredentialType, credential_key};
use sfae_core::error::SfaeError;
use sfae_core::store::{
    CredentialSetInfo, SecretStore, load_credential_set_metadata, parse_structured_credential_set,
};

use crate::store_factory::{create_store, uses_remote_store};

/// Check if a string looks like a UUID (8-4-4-4-12 hex pattern).
fn looks_like_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// All inputs for `delete::run`: a target (UUID or domain), or the bulk `--all` mode.
pub struct RunArgs<'a> {
    pub target: Option<&'a str>,
    pub cred_type_str: Option<&'a str>,
    pub username: Option<&'a str>,
    pub all: bool,
    pub dry_run: bool,
    pub purge: bool,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        target,
        cred_type_str,
        username,
        all,
        dry_run,
        purge,
    } = args;
    let mut store = create_store();

    if all {
        if target.is_some() {
            anyhow::bail!("--all cannot be used with a credential UUID or domain target");
        }
        if cred_type_str.is_some() || username.is_some() {
            anyhow::bail!("--type and --label/--user flags are not used with --all");
        }
        return delete_all_credentials(BulkDeleteRequest {
            store: &mut *store,
            opts: BulkDeleteOpts {
                purge,
                dry_run,
                remote_store: uses_remote_store(),
            },
        });
    }

    if dry_run {
        anyhow::bail!("--dry-run is only supported with --all");
    }

    let Some(target) = target else {
        anyhow::bail!("pass a credential UUID, a legacy domain, or --all");
    };

    // If target looks like a UUID, delete by credential set ID.
    if looks_like_uuid(target) {
        if cred_type_str.is_some() || username.is_some() {
            anyhow::bail!("--type and --label/--user flags are not used with UUID deletion");
        }
        let revoke_outcome = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &*store,
            id: target,
            metadata: None,
            remote_store: uses_remote_store(),
            revoker: &DirectHostedOAuthRevoker,
        });
        report_hosted_oauth_revoke_outcome(target, &revoke_outcome);
        if purge {
            store.delete_credential_set(target)?;
            eprintln!("Purged credential set: {target}");
        } else {
            store.forget_credential_set(target)?;
            eprintln!("Forgot credential set: {target}");
        }
        return Ok(());
    }

    // Otherwise treat as domain (legacy path).
    let domain = target;

    if let Some(ct_str) = cred_type_str {
        let cred_type: CredentialType = ct_str.parse().map_err(|e: String| anyhow::anyhow!(e))?;
        let key = credential_key(CredentialKey {
            domain,
            username,
            cred_type,
        });
        if purge {
            store.delete(&key)?;
            eprintln!("Purged: {key}");
        } else {
            store.forget(&key)?;
            eprintln!("Forgot: {key}");
        }
    } else {
        let mut deleted = 0;
        for ct in CredentialType::all() {
            let key = credential_key(CredentialKey {
                domain,
                username,
                cred_type: *ct,
            });
            let result = if purge {
                store.delete(&key)
            } else {
                store.forget(&key)
            };
            if result.is_ok() {
                let verb = if purge { "Purged" } else { "Forgot" };
                eprintln!("{verb}: {key}");
                deleted += 1;
            }
        }
        if deleted == 0 {
            let target = match username {
                Some(user) => format!("{user}@{domain}"),
                None => domain.to_string(),
            };
            eprintln!("No credentials found for '{target}'.");
        }
    }
    Ok(())
}

struct BulkDeleteOpts {
    purge: bool,
    dry_run: bool,
    remote_store: bool,
}

struct BulkDeleteRequest<'a> {
    store: &'a mut dyn SecretStore,
    opts: BulkDeleteOpts,
}

struct BulkTargets {
    credential_sets: Vec<CredentialSetInfo>,
    legacy_keys: Vec<String>,
}

fn collect_bulk_targets(store: &dyn SecretStore) -> anyhow::Result<BulkTargets> {
    let credential_sets = if store.supports_credential_sets() {
        store.list_credential_sets(None)?
    } else {
        Vec::new()
    };

    let set_ids: HashSet<&str> = credential_sets.iter().map(|set| set.id.as_str()).collect();
    let legacy_keys = store
        .list_keys()?
        .into_iter()
        .filter(|key| !set_ids.contains(key.as_str()))
        .collect();

    Ok(BulkTargets {
        credential_sets,
        legacy_keys,
    })
}

fn delete_all_credentials(request: BulkDeleteRequest<'_>) -> anyhow::Result<()> {
    let BulkDeleteRequest { store, opts } = request;
    let targets = collect_bulk_targets(store)?;
    let total = targets.credential_sets.len() + targets.legacy_keys.len();

    if total == 0 {
        eprintln!("No credentials stored.");
        return Ok(());
    }

    let action = if opts.purge { "purge" } else { "forget" };
    if opts.dry_run {
        eprintln!("Would {action} {total} credential(s):");
        for set in &targets.credential_sets {
            eprintln!("  credential set {}", format_credential_set(set));
        }
        for key in &targets.legacy_keys {
            eprintln!("  legacy credential {key}");
        }
        return Ok(());
    }

    let mut failed = 0usize;

    for set in &targets.credential_sets {
        let revoke_outcome = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store,
            id: &set.id,
            metadata: Some(set),
            remote_store: opts.remote_store,
            revoker: &DirectHostedOAuthRevoker,
        });
        report_hosted_oauth_revoke_outcome(&set.id, &revoke_outcome);

        let result = if opts.purge {
            store.delete_credential_set(&set.id)
        } else {
            store.forget_credential_set(&set.id)
        };

        match result {
            Ok(()) => {
                let verb = if opts.purge { "Purged" } else { "Forgot" };
                eprintln!("{verb} credential set: {}", set.id);
            }
            Err(e) => {
                failed += 1;
                eprintln!("Failed to {action} credential set {}: {e}", set.id);
            }
        }
    }

    for key in &targets.legacy_keys {
        let result = if opts.purge {
            store.delete(key)
        } else {
            store.forget(key)
        };

        match result {
            Ok(()) => {
                let verb = if opts.purge { "Purged" } else { "Forgot" };
                eprintln!("{verb}: {key}");
            }
            Err(sfae_core::error::SfaeError::CredentialNotFound(_)) if opts.purge => {
                eprintln!("Removed stale legacy index entry: {key}");
            }
            Err(e) => {
                failed += 1;
                eprintln!("Failed to {action} legacy credential {key}: {e}");
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("failed to {action} {failed} credential(s)");
    }

    eprintln!(
        "{} {} credential(s).",
        if opts.purge { "Purged" } else { "Forgot" },
        total
    );
    Ok(())
}

fn format_credential_set(set: &CredentialSetInfo) -> String {
    let label = set.label.as_deref().unwrap_or("-");
    let keys = if set.keys.is_empty() {
        "-".to_string()
    } else {
        set.keys.join(", ")
    };
    format!("{} {} {} [{}]", set.id, set.domain, label, keys)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostedOAuthRevokeOutcome {
    Revoked,
    RevokeFailed { error: String },
    NotHostedOAuth,
    MissingRevokeMaterial,
    MissingBrokerMaterial,
    RemoteStoreSkipped,
}

struct HostedOAuthRevokeAttempt<'a> {
    store: &'a dyn SecretStore,
    id: &'a str,
    metadata: Option<&'a CredentialSetInfo>,
    remote_store: bool,
    revoker: &'a dyn HostedOAuthRevoker,
}

trait HostedOAuthRevoker {
    fn revoke_hosted_oauth(&self, material: HostedOAuthRevokeMaterial<'_>)
    -> Result<(), SfaeError>;
}

struct DirectHostedOAuthRevoker;

impl HostedOAuthRevoker for DirectHostedOAuthRevoker {
    fn revoke_hosted_oauth(
        &self,
        material: HostedOAuthRevokeMaterial<'_>,
    ) -> Result<(), SfaeError> {
        let broker = sfae_core::oauth::DirectHostedOAuthBroker::from_env()?;
        let manager = sfae_core::oauth::OAuthCredentialManager::new(&broker);
        manager.revoke_credential(sfae_core::oauth::HostedOAuthRevoke {
            provider: material.provider,
            broker_credential_id: material.broker_credential_id,
            broker_credential_secret: material.broker_credential_secret,
            access_token: material.access_token,
            refresh_token: material.refresh_token,
        })
    }
}

fn hosted_oauth_revoke_outcome(attempt: HostedOAuthRevokeAttempt<'_>) -> HostedOAuthRevokeOutcome {
    let HostedOAuthRevokeAttempt {
        store,
        id,
        metadata,
        remote_store,
        revoker,
    } = attempt;
    let loaded_metadata;
    let metadata = match metadata {
        Some(metadata) => metadata,
        None => {
            loaded_metadata = match load_credential_set_metadata(store, id) {
                Ok(metadata) => metadata,
                Err(_) => return HostedOAuthRevokeOutcome::NotHostedOAuth,
            };
            &loaded_metadata
        }
    };
    if !credential_set_metadata_is_hosted_oauth(metadata) {
        return HostedOAuthRevokeOutcome::NotHostedOAuth;
    }
    if remote_store {
        return HostedOAuthRevokeOutcome::RemoteStoreSkipped;
    }
    let blob = match store.get(id) {
        Ok(blob) => blob,
        Err(_) => return HostedOAuthRevokeOutcome::MissingRevokeMaterial,
    };
    let data = match parse_structured_credential_set(&blob) {
        Ok(data) => data,
        Err(_) => return HostedOAuthRevokeOutcome::MissingRevokeMaterial,
    };
    let material = match hosted_oauth_revoke_material(&data) {
        HostedOAuthRevokeMaterialOutcome::Ready(material) => material,
        HostedOAuthRevokeMaterialOutcome::MissingRevokeMaterial => {
            return HostedOAuthRevokeOutcome::MissingRevokeMaterial;
        }
        HostedOAuthRevokeMaterialOutcome::MissingBrokerMaterial => {
            return HostedOAuthRevokeOutcome::MissingBrokerMaterial;
        }
    };

    match revoker.revoke_hosted_oauth(material) {
        Ok(()) => HostedOAuthRevokeOutcome::Revoked,
        Err(SfaeError::ConfigError(_)) => HostedOAuthRevokeOutcome::MissingBrokerMaterial,
        Err(e) => HostedOAuthRevokeOutcome::RevokeFailed {
            error: e.to_string(),
        },
    }
}

fn credential_set_metadata_is_hosted_oauth(info: &CredentialSetInfo) -> bool {
    info.metadata
        .get("OAUTH_PROVIDER")
        .is_some_and(|provider| supported_hosted_oauth_provider(provider))
}

fn supported_hosted_oauth_provider(provider: &str) -> bool {
    matches!(provider, "discord" | "google" | "github" | "dropbox")
}

// xtask: allow-multi-param - output helper pairs credential id with revoke outcome
fn report_hosted_oauth_revoke_outcome(id: &str, outcome: &HostedOAuthRevokeOutcome) {
    match outcome {
        HostedOAuthRevokeOutcome::Revoked => {
            eprintln!("Revoked hosted OAuth credential: {id}");
        }
        HostedOAuthRevokeOutcome::RevokeFailed { error } => {
            eprintln!(
                "OAuth provider revoke failed for credential set {id}; deleting locally anyway: {error}"
            );
        }
        HostedOAuthRevokeOutcome::NotHostedOAuth => {
            eprintln!("No hosted OAuth provider revoke needed for credential set: {id}");
        }
        HostedOAuthRevokeOutcome::MissingRevokeMaterial => {
            eprintln!(
                "Could not revoke hosted OAuth credential set {id}; missing local token material. Deleting locally only."
            );
        }
        HostedOAuthRevokeOutcome::MissingBrokerMaterial => {
            eprintln!(
                "Could not revoke hosted OAuth credential set {id}; missing broker credential material. Deleting locally only."
            );
        }
        HostedOAuthRevokeOutcome::RemoteStoreSkipped => {
            eprintln!(
                "Skipped OAuth provider revoke for remote-store credential set {id}; deleting from the remote store only."
            );
        }
    }
}

struct HostedOAuthRevokeMaterial<'a> {
    provider: &'a str,
    broker_credential_id: &'a str,
    broker_credential_secret: &'a str,
    access_token: Option<&'a str>,
    refresh_token: Option<&'a str>,
}

enum HostedOAuthRevokeMaterialOutcome<'a> {
    Ready(HostedOAuthRevokeMaterial<'a>),
    MissingRevokeMaterial,
    MissingBrokerMaterial,
}

fn hosted_oauth_revoke_material(
    data: &sfae_core::store::CredentialSetData,
) -> HostedOAuthRevokeMaterialOutcome<'_> {
    let Some(provider) = data.metadata.get("OAUTH_PROVIDER") else {
        return HostedOAuthRevokeMaterialOutcome::MissingRevokeMaterial;
    };
    if !supported_hosted_oauth_provider(provider) {
        return HostedOAuthRevokeMaterialOutcome::MissingRevokeMaterial;
    }
    let access_token = data.values.get("OAUTH_ACCESS_TOKEN").map(String::as_str);
    let refresh_token = data.internal.get("OAUTH_REFRESH_TOKEN").map(String::as_str);
    if access_token.is_none() && refresh_token.is_none() {
        return HostedOAuthRevokeMaterialOutcome::MissingRevokeMaterial;
    }
    let Some(broker_credential_id) = data.metadata.get("OAUTH_BROKER_CREDENTIAL_ID") else {
        return HostedOAuthRevokeMaterialOutcome::MissingBrokerMaterial;
    };
    let Some(broker_credential_secret) = data.internal.get("OAUTH_BROKER_CREDENTIAL_SECRET") else {
        return HostedOAuthRevokeMaterialOutcome::MissingBrokerMaterial;
    };
    HostedOAuthRevokeMaterialOutcome::Ready(HostedOAuthRevokeMaterial {
        provider,
        broker_credential_id,
        broker_credential_secret,
        access_token,
        refresh_token,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use sfae_core::store::{InMemoryStore, StoreEntry, StructuredCredentialSetInput};

    use super::*;

    struct MockHostedOAuthRevoker {
        failure: Option<String>,
        revoked: RefCell<Vec<String>>,
    }

    impl MockHostedOAuthRevoker {
        fn success() -> Self {
            Self {
                failure: None,
                revoked: RefCell::new(Vec::new()),
            }
        }

        fn failure(error: &str) -> Self {
            Self {
                failure: Some(error.to_string()),
                revoked: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostedOAuthRevoker for MockHostedOAuthRevoker {
        fn revoke_hosted_oauth(
            &self,
            material: HostedOAuthRevokeMaterial<'_>,
        ) -> Result<(), SfaeError> {
            self.revoked.borrow_mut().push(format!(
                "{}:{}:{}:{}",
                material.provider,
                material.broker_credential_id,
                material.access_token.unwrap_or("-"),
                material.refresh_token.unwrap_or("-")
            ));
            match self.failure.as_deref() {
                Some(error) => Err(SfaeError::StoreError(error.to_string())),
                None => Ok(()),
            }
        }
    }

    struct OAuthSetFixture {
        include_tokens: bool,
        include_broker_id: bool,
        include_broker_secret: bool,
    }

    // xtask: allow-multi-param - test helper pairs store with fixture data
    fn store_oauth_set(store: &mut InMemoryStore, fixture: OAuthSetFixture) -> String {
        let mut values = HashMap::new();
        if fixture.include_tokens {
            values.insert("OAUTH_ACCESS_TOKEN".to_string(), "access-token".to_string());
        }
        let mut internal = HashMap::new();
        if fixture.include_tokens {
            internal.insert(
                "OAUTH_REFRESH_TOKEN".to_string(),
                "refresh-token".to_string(),
            );
        }
        if fixture.include_broker_secret {
            internal.insert(
                "OAUTH_BROKER_CREDENTIAL_SECRET".to_string(),
                "broker-secret".to_string(),
            );
        }
        let mut metadata = HashMap::from([("OAUTH_PROVIDER".to_string(), "github".to_string())]);
        if fixture.include_broker_id {
            metadata.insert(
                "OAUTH_BROKER_CREDENTIAL_ID".to_string(),
                "broker-id".to_string(),
            );
        }
        store
            .store_structured_credential_set(StructuredCredentialSetInput {
                domain: "github.com",
                label: None,
                values: &values,
                internal: Some(&internal),
                metadata: Some(&metadata),
            })
            .unwrap()
    }

    #[test]
    fn bulk_target_collection_includes_sets_and_legacy_keys_once() {
        let mut store = InMemoryStore::new();
        store
            .set(StoreEntry {
                key: "github.com_API_KEY",
                value: "legacy-secret",
            })
            .unwrap();
        let set_id = store
            .store_credential_set(sfae_core::store::CredentialSetInput {
                domain: "github.com",
                label: Some("Work"),
                values: &HashMap::from([("ACCESS_TOKEN".to_string(), "token".to_string())]),
            })
            .unwrap();

        let targets = collect_bulk_targets(&store).unwrap();

        assert_eq!(targets.credential_sets.len(), 1);
        assert_eq!(targets.credential_sets[0].id, set_id);
        assert_eq!(targets.legacy_keys, vec!["github.com_API_KEY"]);
    }

    #[test]
    fn bulk_delete_dry_run_does_not_mutate_store() {
        let mut store = InMemoryStore::new();
        store
            .set(StoreEntry {
                key: "github.com_API_KEY",
                value: "legacy-secret",
            })
            .unwrap();
        let set_id = store
            .store_credential_set(sfae_core::store::CredentialSetInput {
                domain: "github.com",
                label: None,
                values: &HashMap::from([("ACCESS_TOKEN".to_string(), "token".to_string())]),
            })
            .unwrap();

        delete_all_credentials(BulkDeleteRequest {
            store: &mut store,
            opts: BulkDeleteOpts {
                purge: true,
                dry_run: true,
                remote_store: true,
            },
        })
        .unwrap();

        assert_eq!(store.get("github.com_API_KEY").unwrap(), "legacy-secret");
        assert!(store.get(&set_id).is_ok());
        assert_eq!(store.list_credential_sets(None).unwrap().len(), 1);
    }

    #[test]
    fn bulk_delete_forgets_indexes_without_purging_credential_set_material() {
        let mut store = InMemoryStore::new();
        store
            .set(StoreEntry {
                key: "github.com_API_KEY",
                value: "legacy-secret",
            })
            .unwrap();
        let set_id = store
            .store_credential_set(sfae_core::store::CredentialSetInput {
                domain: "github.com",
                label: None,
                values: &HashMap::from([("ACCESS_TOKEN".to_string(), "token".to_string())]),
            })
            .unwrap();

        delete_all_credentials(BulkDeleteRequest {
            store: &mut store,
            opts: BulkDeleteOpts {
                purge: false,
                dry_run: false,
                remote_store: true,
            },
        })
        .unwrap();

        assert!(store.get("github.com_API_KEY").is_err());
        assert!(store.get(&set_id).is_ok());
        assert!(store.list_credential_sets(None).unwrap().is_empty());
    }

    #[test]
    fn bulk_delete_purges_credential_set_material() {
        let mut store = InMemoryStore::new();
        let set_id = store
            .store_credential_set(sfae_core::store::CredentialSetInput {
                domain: "github.com",
                label: None,
                values: &HashMap::from([("ACCESS_TOKEN".to_string(), "token".to_string())]),
            })
            .unwrap();

        delete_all_credentials(BulkDeleteRequest {
            store: &mut store,
            opts: BulkDeleteOpts {
                purge: true,
                dry_run: false,
                remote_store: true,
            },
        })
        .unwrap();

        assert!(store.get(&set_id).is_err());
        assert!(store.list_credential_sets(None).unwrap().is_empty());
    }

    #[test]
    fn hosted_oauth_revoke_material_accepts_dropbox_provider() {
        let data = sfae_core::store::CredentialSetData {
            values: HashMap::from([("OAUTH_ACCESS_TOKEN".to_string(), "access-token".to_string())]),
            internal: HashMap::from([
                (
                    "OAUTH_REFRESH_TOKEN".to_string(),
                    "refresh-token".to_string(),
                ),
                (
                    "OAUTH_BROKER_CREDENTIAL_SECRET".to_string(),
                    "broker-secret".to_string(),
                ),
            ]),
            metadata: HashMap::from([
                ("OAUTH_PROVIDER".to_string(), "dropbox".to_string()),
                (
                    "OAUTH_BROKER_CREDENTIAL_ID".to_string(),
                    "broker-id".to_string(),
                ),
            ]),
        };

        let material = match hosted_oauth_revoke_material(&data) {
            HostedOAuthRevokeMaterialOutcome::Ready(material) => material,
            _ => panic!("expected hosted OAuth revoke material"),
        };

        assert_eq!(material.provider, "dropbox");
        assert_eq!(material.access_token, Some("access-token"));
        assert_eq!(material.refresh_token, Some("refresh-token"));
        assert_eq!(material.broker_credential_id, "broker-id");
        assert_eq!(material.broker_credential_secret, "broker-secret");
    }

    #[test]
    fn metadata_gate_identifies_oauth_without_blob_access() {
        let oauth = CredentialSetInfo {
            id: "oauth-id".to_string(),
            domain: "googleapis.com".to_string(),
            label: None,
            keys: vec!["OAUTH_ACCESS_TOKEN".to_string()],
            metadata: HashMap::from([("OAUTH_PROVIDER".to_string(), "google".to_string())]),
        };
        let non_oauth = CredentialSetInfo {
            id: "api-key-id".to_string(),
            domain: "api.example.com".to_string(),
            label: None,
            keys: vec!["API_KEY".to_string()],
            metadata: HashMap::new(),
        };

        assert!(credential_set_metadata_is_hosted_oauth(&oauth));
        assert!(!credential_set_metadata_is_hosted_oauth(&non_oauth));
    }

    #[test]
    fn hosted_oauth_revoke_outcome_reports_success() {
        let mut store = InMemoryStore::new();
        let id = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: true,
                include_broker_id: true,
                include_broker_secret: true,
            },
        );
        let revoker = MockHostedOAuthRevoker::success();

        let outcome = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &id,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });

        assert_eq!(outcome, HostedOAuthRevokeOutcome::Revoked);
        assert_eq!(
            revoker.revoked.borrow().as_slice(),
            ["github:broker-id:access-token:refresh-token"]
        );
    }

    #[test]
    fn hosted_oauth_revoke_outcome_reports_provider_failure() {
        let mut store = InMemoryStore::new();
        let id = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: true,
                include_broker_id: true,
                include_broker_secret: true,
            },
        );
        let revoker = MockHostedOAuthRevoker::failure("provider_revoke_status_401");

        let outcome = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &id,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });

        assert_eq!(
            outcome,
            HostedOAuthRevokeOutcome::RevokeFailed {
                error: "secret store error: provider_revoke_status_401".to_string()
            }
        );
        assert_eq!(revoker.revoked.borrow().len(), 1);
    }

    #[test]
    fn hosted_oauth_revoke_outcome_reports_missing_revoke_material() {
        let mut store = InMemoryStore::new();
        let id = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: false,
                include_broker_id: true,
                include_broker_secret: true,
            },
        );
        let revoker = MockHostedOAuthRevoker::success();

        let outcome = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &id,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });

        assert_eq!(outcome, HostedOAuthRevokeOutcome::MissingRevokeMaterial);
        assert!(revoker.revoked.borrow().is_empty());
    }

    #[test]
    fn hosted_oauth_revoke_outcome_reports_missing_broker_material() {
        let mut store = InMemoryStore::new();
        let id_without_broker_id = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: true,
                include_broker_id: false,
                include_broker_secret: true,
            },
        );
        let id_without_broker_secret = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: true,
                include_broker_id: true,
                include_broker_secret: false,
            },
        );
        let revoker = MockHostedOAuthRevoker::success();

        let missing_id = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &id_without_broker_id,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });
        let missing_secret = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &id_without_broker_secret,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });

        assert_eq!(missing_id, HostedOAuthRevokeOutcome::MissingBrokerMaterial);
        assert_eq!(
            missing_secret,
            HostedOAuthRevokeOutcome::MissingBrokerMaterial
        );
        assert!(revoker.revoked.borrow().is_empty());
    }

    #[test]
    fn hosted_oauth_revoke_outcome_skips_non_oauth_and_remote_store_sets() {
        let mut store = InMemoryStore::new();
        let non_oauth_id = store
            .store_credential_set(sfae_core::store::CredentialSetInput {
                domain: "github.com",
                label: None,
                values: &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            })
            .unwrap();
        let oauth_id = store_oauth_set(
            &mut store,
            OAuthSetFixture {
                include_tokens: true,
                include_broker_id: true,
                include_broker_secret: true,
            },
        );
        let revoker = MockHostedOAuthRevoker::success();

        let non_oauth = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &non_oauth_id,
            metadata: None,
            remote_store: false,
            revoker: &revoker,
        });
        let remote = hosted_oauth_revoke_outcome(HostedOAuthRevokeAttempt {
            store: &store,
            id: &oauth_id,
            metadata: None,
            remote_store: true,
            revoker: &revoker,
        });

        assert_eq!(non_oauth, HostedOAuthRevokeOutcome::NotHostedOAuth);
        assert_eq!(remote, HostedOAuthRevokeOutcome::RemoteStoreSkipped);
        assert!(revoker.revoked.borrow().is_empty());
    }
}
