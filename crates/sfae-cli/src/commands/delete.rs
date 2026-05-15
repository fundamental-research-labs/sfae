//! `sfae delete`: remove a credential set by UUID or legacy flat credentials.

use sfae_core::credential::{CredentialKey, CredentialType, credential_key};

use crate::store_factory::create_store;

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
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        target,
        cred_type_str,
        username,
    } = args;
    let mut store = create_store();

    // If target looks like a UUID, delete by credential set ID.
    if looks_like_uuid(target) {
        if cred_type_str.is_some() || username.is_some() {
            anyhow::bail!("--type and --label/--user flags are not used with UUID deletion");
        }
        store.delete_credential_set(target)?;
        eprintln!("Deleted credential set: {target}");
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
        store.delete(&key)?;
        eprintln!("Deleted: {key}");
    } else {
        let mut deleted = 0;
        for ct in CredentialType::all() {
            let key = credential_key(CredentialKey {
                domain,
                username,
                cred_type: *ct,
            });
            if store.delete(&key).is_ok() {
                eprintln!("Deleted: {key}");
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
