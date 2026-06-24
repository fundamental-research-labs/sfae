//! `sfae delete`: forget a credential set by UUID or legacy flat credentials.

use sfae_core::credential::{CredentialKey, CredentialType, credential_key};
use sfae_core::store::{SecretStore, parse_structured_credential_set};

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

/// All inputs for `delete::run`: the target (UUID or domain) plus optional filters.
pub struct RunArgs<'a> {
    pub target: &'a str,
    pub cred_type_str: Option<&'a str>,
    pub username: Option<&'a str>,
    pub purge: bool,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        target,
        cred_type_str,
        username,
        purge,
    } = args;
    let mut store = create_store();

    // If target looks like a UUID, delete by credential set ID.
    if looks_like_uuid(target) {
        if cred_type_str.is_some() || username.is_some() {
            anyhow::bail!("--type and --label/--user flags are not used with UUID deletion");
        }
        if purge && !uses_remote_store() {
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

// xtask: allow-multi-param - deletion needs the selected store and credential id
fn revoke_hosted_oauth_if_needed(store: &dyn SecretStore, id: &str) {
    let Ok(blob) = store.get(id) else {
        return;
    };
    let Ok(data) = parse_structured_credential_set(&blob) else {
        return;
    };
    let Some(provider) = data.metadata.get("OAUTH_PROVIDER") else {
        return;
    };
    if provider != "discord" {
        return;
    }

    let access_token = data.values.get("OAUTH_ACCESS_TOKEN").map(String::as_str);
    let refresh_token = data.internal.get("OAUTH_REFRESH_TOKEN").map(String::as_str);
    if access_token.is_none() && refresh_token.is_none() {
        return;
    }
    let Some(broker_credential_id) = data.metadata.get("OAUTH_BROKER_CREDENTIAL_ID") else {
        eprintln!("OAuth credential has no broker credential id; deleting locally only.");
        return;
    };
    let Some(broker_credential_secret) = data.internal.get("OAUTH_BROKER_CREDENTIAL_SECRET") else {
        eprintln!("OAuth credential has no broker credential secret; deleting locally only.");
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
        provider,
        broker_credential_id,
        broker_credential_secret,
        access_token,
        refresh_token,
    }) {
        eprintln!("OAuth revoke failed; deleting local credential anyway: {e}");
    } else {
        eprintln!("Revoked hosted OAuth credential.");
    }
}
