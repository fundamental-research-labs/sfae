//! `sfae prompt`: collect credentials from the user via the browser flow or terminal fallback.

use std::collections::HashMap;

use sfae_core::spec::{FieldSpec, PromptSpec};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;
use crate::store_factory::create_store;

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
        store.store_structured_credential_set(sfae_core::store::StructuredCredentialSetInput {
            domain,
            label: credential_label,
            values: &credential.values,
            internal: Some(&credential.internal),
            metadata: Some(&credential.metadata),
        })
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
