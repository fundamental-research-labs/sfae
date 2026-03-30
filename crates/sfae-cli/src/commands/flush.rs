use sfae_core::store::{KeyringStore, SecretStore};

pub fn run(dry_run: bool) -> anyhow::Result<()> {
    let mut store = KeyringStore::new();
    let keys = store.list_keys()?;

    if keys.is_empty() {
        eprintln!("No credentials stored.");
        return Ok(());
    }

    if dry_run {
        eprintln!("Would delete {} credential(s):", keys.len());
        for key in &keys {
            eprintln!("  {key}");
        }
        return Ok(());
    }

    for key in &keys {
        match store.delete(key) {
            Ok(()) => {
                eprintln!("Deleted: {key}");
            }
            Err(sfae_core::error::SfaeError::CredentialNotFound(_)) => {
                eprintln!("Removed stale index entry: {key}");
            }
            Err(e) => {
                eprintln!("Failed to delete {key}: {e}");
            }
        }
    }
    eprintln!("Flushed {} credential(s).", keys.len());
    Ok(())
}
