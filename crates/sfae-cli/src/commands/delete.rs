use sfae_core::credential::{CredentialType, credential_key};
use sfae_core::oauth;
use sfae_core::store::SecretStore;

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

pub fn run(
    target: &str,
    cred_type_str: Option<&str>,
    username: Option<&str>,
) -> anyhow::Result<()> {
    let mut store = create_store();

    // If target looks like a UUID, delete by credential set ID.
    if looks_like_uuid(target) {
        if cred_type_str.is_some() || username.is_some() {
            anyhow::bail!("--type and --user flags are not used with UUID deletion");
        }
        store.delete_credential_set(target)?;
        eprintln!("Deleted credential set: {target}");
        return Ok(());
    }

    // Otherwise treat as domain (legacy path).
    let domain = target;

    if let Some(ct_str) = cred_type_str {
        let cred_type: CredentialType = ct_str.parse().map_err(|e: String| anyhow::anyhow!(e))?;
        let key = credential_key(domain, username, cred_type);
        store.delete(&key)?;
        eprintln!("Deleted: {key}");

        // When deleting ACCESS_TOKEN, also clean up OAuth metadata and client secret
        // since the refresh flow is useless without an access token placeholder.
        if cred_type == CredentialType::AccessToken {
            cleanup_oauth(domain, username, &mut *store);
        }
    } else {
        let mut deleted = 0;
        for ct in CredentialType::all() {
            let key = credential_key(domain, username, *ct);
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
        } else {
            // Full-domain deletion: clean up OAuth metadata too.
            cleanup_oauth(domain, username, &mut *store);
        }
    }
    Ok(())
}

/// Remove OAuth metadata and client secret for a domain.
fn cleanup_oauth(domain: &str, username: Option<&str>, store: &mut dyn SecretStore) {
    if let Err(e) = (oauth::MetadataKey { domain, username }.remove()) {
        eprintln!("Warning: failed to remove OAuth metadata: {e}");
    }
    let cs_key = credential_key(domain, username, CredentialType::ClientSecret);
    if store.delete(&cs_key).is_ok() {
        eprintln!("Deleted: {cs_key}");
    }
}
