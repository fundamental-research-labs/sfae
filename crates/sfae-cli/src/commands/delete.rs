//! `sfae delete`: forget credential sets or legacy flat credentials.

use std::collections::HashSet;

use sfae_core::credential::{CredentialKey, CredentialType, credential_key};
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
        return delete_all_credentials(
            &mut *store,
            BulkDeleteOpts {
                purge,
                dry_run,
                remote_store: uses_remote_store(),
            },
        );
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
        if should_attempt_hosted_oauth_revoke(uses_remote_store(), purge) {
            revoke_hosted_oauth_if_needed(&*store, target);
        }
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

fn delete_all_credentials(store: &mut dyn SecretStore, opts: BulkDeleteOpts) -> anyhow::Result<()> {
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
        if should_attempt_hosted_oauth_revoke(opts.remote_store, opts.purge) {
            revoke_hosted_oauth_if_needed(store, &set.id);
        }

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

// xtask: allow-multi-param - helper makes purge-independent revoke behavior explicit
fn should_attempt_hosted_oauth_revoke(remote_store: bool, _purge: bool) -> bool {
    !remote_store
}

// xtask: allow-multi-param - deletion needs the selected store and credential id
fn revoke_hosted_oauth_if_needed(store: &dyn SecretStore, id: &str) {
    let Ok(metadata) = load_credential_set_metadata(store, id) else {
        return;
    };
    if !credential_set_metadata_is_hosted_oauth(&metadata) {
        return;
    }
    let Ok(blob) = store.get(id) else {
        return;
    };
    let Ok(data) = parse_structured_credential_set(&blob) else {
        return;
    };
    let Some(material) = hosted_oauth_revoke_material(&data) else {
        return;
    };

    let broker = match sfae_core::oauth::DirectHostedOAuthBroker::from_env() {
        Ok(broker) => broker,
        Err(e) => {
            eprintln!("Could not configure OAuth broker for revoke; deleting locally only: {e}");
            return;
        }
    };
    let manager = sfae_core::oauth::OAuthCredentialManager::new(&broker);
    if let Err(e) = manager.revoke_credential(sfae_core::oauth::HostedOAuthRevoke {
        provider: material.provider,
        broker_credential_id: material.broker_credential_id,
        broker_credential_secret: material.broker_credential_secret,
        access_token: material.access_token,
        refresh_token: material.refresh_token,
    }) {
        eprintln!("OAuth revoke failed; deleting local credential anyway: {e}");
    } else {
        eprintln!("Revoked hosted OAuth credential.");
    }
}

fn credential_set_metadata_is_hosted_oauth(info: &CredentialSetInfo) -> bool {
    info.metadata.contains_key("OAUTH_PROVIDER")
}

struct HostedOAuthRevokeMaterial<'a> {
    provider: &'a str,
    broker_credential_id: &'a str,
    broker_credential_secret: &'a str,
    access_token: Option<&'a str>,
    refresh_token: Option<&'a str>,
}

fn hosted_oauth_revoke_material(
    data: &sfae_core::store::CredentialSetData,
) -> Option<HostedOAuthRevokeMaterial<'_>> {
    let provider = data.metadata.get("OAUTH_PROVIDER")?;
    let access_token = data.values.get("OAUTH_ACCESS_TOKEN").map(String::as_str);
    let refresh_token = data.internal.get("OAUTH_REFRESH_TOKEN").map(String::as_str);
    if access_token.is_none() && refresh_token.is_none() {
        return None;
    }
    let Some(broker_credential_id) = data.metadata.get("OAUTH_BROKER_CREDENTIAL_ID") else {
        eprintln!("OAuth credential has no broker credential id; deleting locally only.");
        return None;
    };
    let Some(broker_credential_secret) = data.internal.get("OAUTH_BROKER_CREDENTIAL_SECRET") else {
        eprintln!("OAuth credential has no broker credential secret; deleting locally only.");
        return None;
    };
    Some(HostedOAuthRevokeMaterial {
        provider,
        broker_credential_id,
        broker_credential_secret,
        access_token,
        refresh_token,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sfae_core::store::{InMemoryStore, StoreEntry};

    use super::*;

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

        delete_all_credentials(
            &mut store,
            BulkDeleteOpts {
                purge: true,
                dry_run: true,
                remote_store: true,
            },
        )
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

        delete_all_credentials(
            &mut store,
            BulkDeleteOpts {
                purge: false,
                dry_run: false,
                remote_store: true,
            },
        )
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

        delete_all_credentials(
            &mut store,
            BulkDeleteOpts {
                purge: true,
                dry_run: false,
                remote_store: true,
            },
        )
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

        let material = hosted_oauth_revoke_material(&data).unwrap();

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
    fn hosted_oauth_revoke_is_attempted_for_local_uuid_delete_with_or_without_purge() {
        assert!(should_attempt_hosted_oauth_revoke(false, false));
        assert!(should_attempt_hosted_oauth_revoke(false, true));
        assert!(!should_attempt_hosted_oauth_revoke(true, false));
        assert!(!should_attempt_hosted_oauth_revoke(true, true));
    }
}
