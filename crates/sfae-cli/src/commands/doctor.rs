//! `sfae doctor`: privacy-conscious checks for credential-store availability.

use sfae_core::{SfaeError, store::parse_structured_credential_set};

use crate::store_factory::{StoreBackend, create_store, selected_backend};

pub struct RunArgs<'a> {
    pub cred_id: Option<&'a str>,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let mut failed = false;
    println!("SFAE doctor");

    match selected_backend() {
        StoreBackend::Remote => {
            println!("Store backend: remote credential store");
            println!("Remote store URL: set");
            if std::env::var("SFAE_STORE_TOKEN").is_ok() {
                println!("Remote store token: set");
            } else {
                println!("Remote store token: missing");
                failed = true;
            }
        }
        #[cfg(feature = "native-keychain")]
        StoreBackend::NativeKeychain => {
            println!("Store backend: native OS credential store");
            println!("Remote store URL: not set");
        }
        #[cfg(not(feature = "native-keychain"))]
        StoreBackend::Unavailable => {
            println!("Store backend: unavailable");
            failed = true;
        }
    }

    if failed {
        anyhow::bail!("SFAE credential-store configuration is incomplete");
    }

    let store = create_store();
    match inspect_index(&*store) {
        Ok(()) => println!("Credential index: readable"),
        Err(error) => {
            println!("Credential index: failed");
            return Err(error);
        }
    }

    if let Some(id) = args.cred_id {
        match store.get(id) {
            Ok(blob) => {
                parse_structured_credential_set(&blob).map_err(|e| {
                    anyhow::anyhow!("Credential blob read succeeded but parse failed: {e}")
                })?;
                println!("Credential blob read: ok");
            }
            Err(error) => {
                println!("Credential blob read: failed");
                match error {
                    SfaeError::CredentialNotFound(_) => {
                        anyhow::bail!("credential-store check failed: credential not found");
                    }
                    SfaeError::StoreError(message) => {
                        anyhow::bail!("credential-store check failed: {message}");
                    }
                    other => return Err(other.into()),
                }
            }
        }
    }

    Ok(())
}

fn inspect_index(store: &dyn sfae_core::store::SecretStore) -> anyhow::Result<()> {
    if store.supports_credential_sets() {
        store.list_credential_sets(None)?;
    } else {
        store.list_keys()?;
    }
    Ok(())
}
