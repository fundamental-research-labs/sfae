//! `sfae credentials`: list stored credential sets or inspect non-secret metadata.

use crate::store_factory::create_store;
use sfae_core::store::{CredentialSetMetadata, SecretStore, load_credential_set_metadata};

/// Operation requested by the `credentials` command.
pub enum RunAction<'a> {
    List {
        domain: Option<&'a str>,
        username: Option<&'a str>,
    },
    Show {
        id: &'a str,
    },
}

/// Parsed inputs for the `credentials` command.
pub struct RunArgs<'a> {
    pub action: RunAction<'a>,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs { action } = args;
    let store = create_store();
    match action {
        RunAction::List { domain, username } => list_credentials(&*store, domain, username),
        RunAction::Show { id } => show_credential(&*store, id),
    }
}

// xtask: allow-multi-param - command helper pairs selected store with list filters
fn list_credentials(
    store: &dyn SecretStore,
    domain: Option<&str>,
    username: Option<&str>,
) -> anyhow::Result<()> {
    if store.supports_credential_sets() {
        let sets = store.list_credential_sets(domain)?;
        let filtered: Vec<_> = if let Some(user) = username {
            sets.into_iter()
                .filter(|s| s.label.as_deref() == Some(user))
                .collect()
        } else {
            sets
        };

        if filtered.is_empty() {
            let target = match (domain, username) {
                (Some(d), Some(u)) => format!("{u}@{d}"),
                (Some(d), None) => d.to_string(),
                (None, Some(u)) => format!("user '{u}'"),
                (None, None) => "any domain".to_string(),
            };
            eprintln!("No credentials stored for {target}.");
        } else {
            for s in &filtered {
                let label = s.label.as_deref().unwrap_or("-");
                println!(
                    "{id}  {domain}  {label}  [{keys}]",
                    id = s.id,
                    domain = s.domain,
                    keys = s.keys.join(", "),
                );
            }
        }
        return Ok(());
    }

    // Legacy fallback: flat domain_TYPE keys
    let Some(domain) = domain else {
        anyhow::bail!("domain is required for legacy credential stores");
    };
    let types = sfae_core::store::list_credential_types(sfae_core::store::CredentialTypesQuery {
        store,
        domain,
        username,
    })?;
    if types.is_empty() {
        let target = match username {
            Some(user) => format!("{user}@{domain}"),
            None => domain.to_string(),
        };
        eprintln!("No credentials stored for '{target}'.");
    } else {
        for ct in types {
            println!("{ct}");
        }
    }
    Ok(())
}

// xtask: allow-multi-param - command helper pairs selected store with credential id
fn show_credential(store: &dyn SecretStore, id: &str) -> anyhow::Result<()> {
    let metadata = load_credential_set_metadata(store, id)?;
    print!("{}", format_credential_set_metadata(&metadata));
    Ok(())
}

fn format_credential_set_metadata(metadata: &CredentialSetMetadata) -> String {
    let info = &metadata.info;
    let label = info.label.as_deref().unwrap_or("-");
    let mut output = format!(
        "id: {id}\ndomain: {domain}\nlabel: {label}\nkeys:\n",
        id = info.id,
        domain = info.domain,
    );

    if info.keys.is_empty() {
        output.push_str("  -\n");
    } else {
        for key in &info.keys {
            output.push_str(&format!("  {key}\n"));
        }
    }

    output.push_str("metadata:\n");
    let mut entries: Vec<_> = metadata.metadata.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    if entries.is_empty() {
        output.push_str("  -\n");
    } else {
        for (key, value) in entries {
            output.push_str(&format!("  {key}: {value}\n"));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sfae_core::store::{
        InMemoryStore, SecretStore, StructuredCredentialSetInput, load_credential_set_metadata,
    };

    use super::format_credential_set_metadata;

    #[test]
    fn show_output_includes_metadata_without_secret_values() {
        let mut store = InMemoryStore::new();
        let mut values = HashMap::new();
        values.insert(
            "OAUTH_ACCESS_TOKEN".to_string(),
            "secret-access".to_string(),
        );
        let mut internal = HashMap::new();
        internal.insert(
            "OAUTH_REFRESH_TOKEN".to_string(),
            "secret-refresh".to_string(),
        );
        let mut metadata = HashMap::new();
        metadata.insert("OAUTH_PROVIDER".to_string(), "discord".to_string());
        metadata.insert("OAUTH_SCOPES".to_string(), "identify guilds".to_string());
        metadata.insert(
            "OAUTH_EXPIRES_AT".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
        );
        metadata.insert("OAUTH_DISPLAY_NAME".to_string(), "Ada".to_string());

        let id = store
            .store_structured_credential_set(StructuredCredentialSetInput {
                domain: "discord.com",
                label: Some("Work"),
                values: &values,
                internal: Some(&internal),
                metadata: Some(&metadata),
            })
            .unwrap();

        let loaded = load_credential_set_metadata(&store, &id).unwrap();
        let output = format_credential_set_metadata(&loaded);

        assert!(output.contains("domain: discord.com"));
        assert!(output.contains("label: Work"));
        assert!(output.contains("OAUTH_ACCESS_TOKEN"));
        assert!(output.contains("OAUTH_PROVIDER: discord"));
        assert!(output.contains("OAUTH_SCOPES: identify guilds"));
        assert!(output.contains("OAUTH_EXPIRES_AT: 2026-01-01T00:00:00Z"));
        assert!(output.contains("OAUTH_DISPLAY_NAME: Ada"));
        assert!(!output.contains("secret-access"));
        assert!(!output.contains("secret-refresh"));
        assert!(!output.contains("OAUTH_REFRESH_TOKEN"));
    }
}
