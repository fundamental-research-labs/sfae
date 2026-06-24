//! `sfae show`: inspect public metadata for one stored credential set.

use crate::store_factory::create_store;
use sfae_core::store::{CredentialSetInfo, load_credential_set_metadata};

/// Inputs for the `show` command.
pub struct RunArgs<'a> {
    pub id: &'a str,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let store = create_store();
    let metadata = load_credential_set_metadata(&*store, args.id)?;
    print!("{}", format_credential_set_metadata(&metadata));
    Ok(())
}

fn format_credential_set_metadata(info: &CredentialSetInfo) -> String {
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
    let mut entries: Vec<_> = info.metadata.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
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
