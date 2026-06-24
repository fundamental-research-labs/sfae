//! `sfae prompt`: collect credentials from the user via the browser flow or terminal fallback.

use std::collections::HashMap;

use sfae_core::spec::{FieldSpec, PromptSpec};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;
use crate::store_factory::create_store;

const OAUTH_PROVIDER: &str = "OAUTH_PROVIDER";
const OAUTH_PROVIDER_SUBJECT: &str = "OAUTH_PROVIDER_SUBJECT";
const OAUTH_ACCOUNT_ID: &str = "OAUTH_ACCOUNT_ID";

/// All inputs for `prompt::run`: target domain + spec + runtime options.
pub struct RunArgs<'a> {
    pub domain: &'a str,
    pub spec: &'a PromptSpec,
    pub username: Option<&'a str>,
    pub terminal: bool,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        domain,
        spec,
        username,
        terminal,
    } = args;
    let display_label = match username {
        Some(user) => format!("Credentials for {user}@{domain}"),
        None => format!("Credentials for {domain}"),
    };

    let prompt_result = if terminal {
        if let Some(u) = &spec.help_url {
            eprintln!("Obtain your credential here: {u}");
        }
        sfae_core::browser::BrowserPromptResult::Values(terminal_prompt_fields(spec)?)
    } else {
        eprintln!(
            "Opening browser for credential collection. This is human-paced and may take an undefined amount of time; keep waiting until this command exits."
        );
        browser_prompt_with_optional_oauth(BrowserPromptCtx {
            domain,
            label: &display_label,
            credential_label: username,
            spec,
        })?
    };

    let values = match prompt_result {
        sfae_core::browser::BrowserPromptResult::Values(values) => values,
        sfae_core::browser::BrowserPromptResult::HostedOAuth {
            session_id,
            credential_id,
        } => {
            match credential_id {
                Some(id) => eprintln!("Credential stored: {id}"),
                None => eprintln!("OAuth session completed: {session_id}"),
            }
            return Ok(());
        }
    };

    let mut store = create_store();
    if store.supports_credential_sets() {
        let id = store.store_credential_set(sfae_core::store::CredentialSetInput {
            domain,
            label: username,
            values: &values,
        })?;
        eprintln!("Credential stored: {id}");
    } else {
        // Legacy fallback: store each field as a flat key.
        for (key, value) in &values {
            let flat_key = match username {
                Some(user) => format!("{domain}_{user}_{key}"),
                None => format!("{domain}_{key}"),
            };
            store.set(sfae_core::store::StoreEntry {
                key: &flat_key,
                value,
            })?;
            eprintln!("Credential stored: {flat_key}");
        }
    }

    Ok(())
}

struct BrowserPromptCtx<'a> {
    domain: &'a str,
    label: &'a str,
    credential_label: Option<&'a str>,
    spec: &'a PromptSpec,
}

fn browser_prompt_with_optional_oauth(
    ctx: BrowserPromptCtx<'_>,
) -> anyhow::Result<sfae_core::browser::BrowserPromptResult> {
    let BrowserPromptCtx {
        domain,
        label,
        credential_label,
        spec,
    } = ctx;
    let form_ctx = sfae_core::browser::FormContext {
        domain,
        label,
        credential_label,
        spec,
    };
    if !spec_has_oauth(spec) {
        return Ok(sfae_core::browser::browser_prompt_spec(
            form_ctx, None, None,
        )?);
    }

    if crate::store_factory::uses_remote_store() {
        let broker = sfae_core::oauth::BackendProxyHostedOAuthBroker::from_env()?;
        let mut manager = sfae_core::oauth::OAuthCredentialManager::new(&broker);
        validate_oauth_providers(spec, domain, &manager)?;
        return Ok(sfae_core::browser::browser_prompt_spec(
            form_ctx,
            Some(&mut manager),
            None,
        )?);
    }

    let broker = sfae_core::oauth::DirectHostedOAuthBroker::from_env()?;
    let mut manager = sfae_core::oauth::OAuthCredentialManager::new(&broker);
    validate_oauth_providers(spec, domain, &manager)?;
    let mut sink = |credential: sfae_core::oauth::HostedOAuthCredential| {
        let mut store = create_store();
        let id = store.store_structured_credential_set(
            sfae_core::store::StructuredCredentialSetInput {
                domain,
                label: credential_label,
                values: &credential.values,
                internal: Some(&credential.internal),
                metadata: Some(&credential.metadata),
            },
        )?;
        let forgotten = forget_superseded_oauth_credentials(OAuthCleanupCtx {
            store: &mut *store,
            domain,
            label: credential_label,
            current_id: &id,
            current_metadata: &credential.metadata,
        })?;
        if forgotten > 0 {
            eprintln!(
                "Forgot {forgotten} older credential set(s) for the same OAuth account without reading keychain secrets."
            );
        }
        Ok(id)
    };
    Ok(sfae_core::browser::browser_prompt_spec(
        form_ctx,
        Some(&mut manager),
        Some(&mut sink),
    )?)
}

// xtask: allow-multi-param - validates a prompt spec against a resolved domain and broker
fn validate_oauth_providers(
    spec: &PromptSpec,
    domain: &str,
    manager: &sfae_core::oauth::OAuthCredentialManager<'_>,
) -> anyhow::Result<()> {
    let registry = manager.provider_registry()?;
    for group in spec
        .groups
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|group| group.oauth.as_ref())
    {
        sfae_core::oauth::resolve_hosted_provider(sfae_core::oauth::HostedProviderResolve {
            domain,
            requested_provider: group.provider.as_deref(),
            registry: &registry,
        })?;
    }
    Ok(())
}

fn spec_has_oauth(spec: &PromptSpec) -> bool {
    spec.groups
        .as_ref()
        .is_some_and(|groups| groups.iter().any(|group| group.oauth.is_some()))
}

struct OAuthCleanupCtx<'a> {
    store: &'a mut dyn sfae_core::store::SecretStore,
    domain: &'a str,
    label: Option<&'a str>,
    current_id: &'a str,
    current_metadata: &'a HashMap<String, String>,
}

fn forget_superseded_oauth_credentials(
    ctx: OAuthCleanupCtx<'_>,
) -> Result<usize, sfae_core::error::SfaeError> {
    let OAuthCleanupCtx {
        store,
        domain,
        label,
        current_id,
        current_metadata,
    } = ctx;
    if !store.supports_credential_sets() {
        return Ok(0);
    }
    let Some(provider) = current_metadata.get(OAUTH_PROVIDER) else {
        return Ok(0);
    };
    let Some(account_key) = oauth_account_key(current_metadata) else {
        return Ok(0);
    };

    let mut forgotten = 0;
    for set in store.list_credential_sets(Some(domain))? {
        if set.id == current_id || set.label.as_deref() != label {
            continue;
        }
        if set.metadata.get(OAUTH_PROVIDER) != Some(provider) {
            continue;
        }
        if oauth_account_key(&set.metadata).as_deref() != Some(account_key.as_str()) {
            continue;
        }
        store.forget_credential_set(&set.id)?;
        forgotten += 1;
    }
    Ok(forgotten)
}

fn oauth_account_key(metadata: &HashMap<String, String>) -> Option<String> {
    metadata
        .get(OAUTH_PROVIDER_SUBJECT)
        .or_else(|| metadata.get(OAUTH_ACCOUNT_ID))
        .cloned()
}

fn terminal_prompt_fields(spec: &PromptSpec) -> anyhow::Result<HashMap<String, String>> {
    let tp = TerminalPrompt;
    let mut values = HashMap::new();

    // Collect common fields.
    if let Some(fields) = &spec.fields {
        for field in fields {
            if let Some(v) = prompt_field(PromptFieldCtx { prompt: &tp, field })? {
                values.insert(field.name.clone(), v);
            }
        }
    }

    // Handle groups: show selection menu, prompt selected group's fields.
    if let Some(groups) = &spec.groups
        && !groups.is_empty()
    {
        eprintln!("\nSelect credential type:");
        for (i, group) in groups.iter().enumerate() {
            eprintln!("  {}: {}", i + 1, group.label);
        }
        let choice = tp.prompt(&format!("Choice [1-{}]", groups.len()))?;
        let idx: usize = choice
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("invalid choice"))?
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("invalid choice"))?;
        let group = groups
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("invalid choice: {}", idx + 1))?;

        if group.oauth.is_some() {
            anyhow::bail!("OAuth authorization requires a browser — run without --terminal");
        }

        if let Some(fields) = &group.fields {
            for field in fields {
                if let Some(v) = prompt_field(PromptFieldCtx { prompt: &tp, field })? {
                    values.insert(field.name.clone(), v);
                }
            }
        }
    }

    Ok(values)
}

/// Input for `prompt_field`: the terminal prompter plus the field spec to prompt for.
struct PromptFieldCtx<'a> {
    prompt: &'a TerminalPrompt,
    field: &'a FieldSpec,
}

fn prompt_field(ctx: PromptFieldCtx<'_>) -> anyhow::Result<Option<String>> {
    let PromptFieldCtx { prompt, field } = ctx;
    let label = field.display_label();
    let optional_hint = if field.is_optional() {
        " (optional)"
    } else {
        ""
    };
    let value = if field.is_secret() {
        prompt.prompt_secret(&format!("Enter {label}{optional_hint}"))?
    } else {
        let msg = match &field.default {
            Some(d) => format!("{label}{optional_hint} [{d}]"),
            None => format!("{label}{optional_hint}"),
        };
        let v = prompt.prompt(&msg)?;
        if v.is_empty() {
            field.default.clone().unwrap_or_default()
        } else {
            v
        }
    };
    if value.is_empty() {
        if field.is_optional() {
            return Ok(None);
        }
        anyhow::bail!("credential value for {} cannot be empty", field.name);
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sfae_core::error::SfaeError;
    use sfae_core::store::{CredentialSetInfo, SecretStore, StoreEntry};

    struct IndexOnlyForgetStore {
        sets: Vec<CredentialSetInfo>,
        forgotten: Vec<String>,
    }

    impl SecretStore for IndexOnlyForgetStore {
        fn set(&mut self, _entry: StoreEntry<'_>) -> Result<(), SfaeError> {
            panic!("cleanup should not write secret blobs");
        }

        fn get(&self, _key: &str) -> Result<String, SfaeError> {
            panic!("cleanup should not read secret blobs");
        }

        fn delete(&mut self, _key: &str) -> Result<(), SfaeError> {
            panic!("cleanup should not delete secret blobs");
        }

        fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
            panic!("cleanup should not list legacy secret keys");
        }

        fn supports_credential_sets(&self) -> bool {
            true
        }

        fn list_credential_sets(
            &self,
            domain: Option<&str>,
        ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
            Ok(match domain {
                Some(domain) => self
                    .sets
                    .iter()
                    .filter(|set| set.domain == domain)
                    .cloned()
                    .collect(),
                None => self.sets.clone(),
            })
        }

        fn forget_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
            let found = self.sets.iter().any(|set| set.id == id);
            self.sets.retain(|set| set.id != id);
            if found {
                self.forgotten.push(id.to_string());
                Ok(())
            } else {
                Err(SfaeError::CredentialNotFound(id.to_string()))
            }
        }
    }

    #[test]
    fn forgets_same_oauth_account_without_secret_access() {
        let mut store = IndexOnlyForgetStore {
            sets: vec![
                oauth_set(TestSet {
                    id: "old",
                    ..Default::default()
                }),
                oauth_set(TestSet {
                    id: "other-user",
                    subject: Some("user-2"),
                    ..Default::default()
                }),
                oauth_set(TestSet {
                    id: "other-label",
                    label: Some("Personal"),
                    ..Default::default()
                }),
                oauth_set(TestSet {
                    id: "other-domain",
                    domain: "api.discord.com",
                    ..Default::default()
                }),
                oauth_set(TestSet {
                    id: "new",
                    ..Default::default()
                }),
            ],
            forgotten: vec![],
        };
        let metadata = oauth_metadata("user-1");

        let count = forget_superseded_oauth_credentials(OAuthCleanupCtx {
            store: &mut store,
            domain: "discord.com",
            label: Some("Work"),
            current_id: "new",
            current_metadata: &metadata,
        })
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(store.forgotten, vec!["old"]);
        assert!(!store.sets.iter().any(|set| set.id == "old"));
        assert!(store.sets.iter().any(|set| set.id == "new"));
        assert!(store.sets.iter().any(|set| set.id == "other-user"));
        assert!(store.sets.iter().any(|set| set.id == "other-label"));
        assert!(store.sets.iter().any(|set| set.id == "other-domain"));
    }

    #[test]
    fn does_not_forget_when_account_identity_is_not_provable() {
        let mut store = IndexOnlyForgetStore {
            sets: vec![oauth_set(TestSet {
                id: "old",
                label: None,
                ..Default::default()
            })],
            forgotten: vec![],
        };
        let mut metadata = HashMap::new();
        metadata.insert(OAUTH_PROVIDER.to_string(), "discord".to_string());

        let count = forget_superseded_oauth_credentials(OAuthCleanupCtx {
            store: &mut store,
            domain: "discord.com",
            label: None,
            current_id: "new",
            current_metadata: &metadata,
        })
        .unwrap();

        assert_eq!(count, 0);
        assert!(store.forgotten.is_empty());
        assert!(store.sets.iter().any(|set| set.id == "old"));
    }

    #[test]
    fn matches_future_account_id_metadata_fallback() {
        let mut store = IndexOnlyForgetStore {
            sets: vec![oauth_set(TestSet {
                id: "old",
                label: None,
                subject: None,
                account_id: Some("account-1"),
                ..Default::default()
            })],
            forgotten: vec![],
        };
        let mut metadata = HashMap::new();
        metadata.insert(OAUTH_PROVIDER.to_string(), "discord".to_string());
        metadata.insert(OAUTH_ACCOUNT_ID.to_string(), "account-1".to_string());

        let count = forget_superseded_oauth_credentials(OAuthCleanupCtx {
            store: &mut store,
            domain: "discord.com",
            label: None,
            current_id: "new",
            current_metadata: &metadata,
        })
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(store.forgotten, vec!["old"]);
    }

    #[derive(Clone, Copy)]
    struct TestSet<'a> {
        id: &'a str,
        domain: &'a str,
        label: Option<&'a str>,
        provider: &'a str,
        subject: Option<&'a str>,
        account_id: Option<&'a str>,
    }

    impl Default for TestSet<'_> {
        fn default() -> Self {
            Self {
                id: "set",
                domain: "discord.com",
                label: Some("Work"),
                provider: "discord",
                subject: Some("user-1"),
                account_id: None,
            }
        }
    }

    fn oauth_set(input: TestSet<'_>) -> CredentialSetInfo {
        let TestSet {
            id,
            domain,
            label,
            provider,
            subject,
            account_id,
        } = input;
        let mut metadata = HashMap::new();
        metadata.insert(OAUTH_PROVIDER.to_string(), provider.to_string());
        if let Some(subject) = subject {
            metadata.insert(OAUTH_PROVIDER_SUBJECT.to_string(), subject.to_string());
        }
        if let Some(account_id) = account_id {
            metadata.insert(OAUTH_ACCOUNT_ID.to_string(), account_id.to_string());
        }
        CredentialSetInfo {
            id: id.to_string(),
            domain: domain.to_string(),
            label: label.map(str::to_string),
            keys: vec!["OAUTH_ACCESS_TOKEN".to_string()],
            metadata,
        }
    }

    fn oauth_metadata(subject: &str) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert(OAUTH_PROVIDER.to_string(), "discord".to_string());
        metadata.insert(OAUTH_PROVIDER_SUBJECT.to_string(), subject.to_string());
        metadata
    }
}
