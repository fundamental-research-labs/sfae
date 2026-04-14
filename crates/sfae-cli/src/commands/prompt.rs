use std::collections::HashMap;

use sfae_core::spec::{FieldSpec, PromptSpec};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;
use crate::store_factory::{create_store, is_api_mode};

pub fn run(
    domain: &str,
    spec: &PromptSpec,
    username: Option<&str>,
    terminal: bool,
) -> anyhow::Result<()> {
    if is_api_mode() {
        anyhow::bail!(
            "Credential prompting is not available in API store mode. \
             Use the request_credential client tool to request credentials from the user."
        );
    }

    let display_label = match username {
        Some(user) => format!("Credentials for {user}@{domain}"),
        None => format!("Credentials for {domain}"),
    };

    let values = if terminal {
        if let Some(u) = &spec.url {
            eprintln!("Obtain your credential here: {u}");
        }
        terminal_prompt_fields(spec)?
    } else {
        sfae_core::browser::browser_prompt_spec(&display_label, spec)?
    };

    let mut store = create_store();
    if store.supports_credential_sets() {
        let id = store.store_credential_set(domain, username, &values)?;
        eprintln!("Credential stored: {id}");
    } else {
        // Legacy fallback: store each field as a flat key.
        for (key, value) in &values {
            let flat_key = match username {
                Some(user) => format!("{domain}_{user}_{key}"),
                None => format!("{domain}_{key}"),
            };
            store.set(&flat_key, value)?;
            eprintln!("Credential stored: {flat_key}");
        }
    }

    Ok(())
}

fn terminal_prompt_fields(spec: &PromptSpec) -> anyhow::Result<HashMap<String, String>> {
    let tp = TerminalPrompt;
    let mut values = HashMap::new();

    // Collect common fields.
    if let Some(fields) = &spec.fields {
        for field in fields {
            values.insert(field.name.clone(), prompt_field(&tp, field)?);
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
                values.insert(field.name.clone(), prompt_field(&tp, field)?);
            }
        }
    }

    Ok(values)
}

fn prompt_field(prompt: &TerminalPrompt, field: &FieldSpec) -> anyhow::Result<String> {
    let label = field.display_label();
    let value = if field.is_secret() {
        prompt.prompt_secret(&format!("Enter {label}"))?
    } else {
        let msg = match &field.default {
            Some(d) => format!("{label} [{d}]"),
            None => label.clone(),
        };
        let v = prompt.prompt(&msg)?;
        if v.is_empty() {
            field.default.clone().unwrap_or_default()
        } else {
            v
        }
    };
    if value.is_empty() {
        anyhow::bail!("credential value for {} cannot be empty", field.name);
    }
    Ok(value)
}
