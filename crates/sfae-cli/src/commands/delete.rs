use sfae_core::credential::{credential_key, CredentialType};
use sfae_core::store::{KeyringStore, SecretStore};

pub fn run(domain: &str, cred_type_str: Option<&str>, username: Option<&str>) -> anyhow::Result<()> {
    let mut store = KeyringStore::new();

    if let Some(ct_str) = cred_type_str {
        let cred_type: CredentialType = ct_str
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        let key = credential_key(domain, username, cred_type);
        store.delete(&key)?;
        eprintln!("Deleted: {key}");
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
        }
    }
    Ok(())
}
