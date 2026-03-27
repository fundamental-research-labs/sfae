use regex::Regex;

use sfae_core::credential::Credential;
use sfae_core::store::{KeyringStore, SecretStore};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;

/// Validate that a credential name matches `[a-zA-Z0-9_-]+`.
fn validate_name(name: &str) -> anyhow::Result<()> {
    let re = Regex::new(r"^[a-zA-Z0-9_-]+$").expect("valid regex");
    if !re.is_match(name) {
        anyhow::bail!(
            "invalid credential name '{name}': must match [a-zA-Z0-9_-]+"
        );
    }
    Ok(())
}

pub fn add(name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    let prompt = TerminalPrompt;
    let token = prompt.prompt_secret(&format!("Enter secret for '{name}'"))?;
    if token.is_empty() {
        anyhow::bail!("secret cannot be empty");
    }
    let credential = Credential::AccessToken { token };
    let mut store = KeyringStore::new();
    store.set(name, &credential)?;
    eprintln!("Credential '{name}' stored.");
    Ok(())
}

pub fn list() -> anyhow::Result<()> {
    let store = KeyringStore::new();
    let names = store.list()?;
    if names.is_empty() {
        eprintln!("No credentials stored.");
    } else {
        for name in names {
            println!("{name}");
        }
    }
    Ok(())
}

pub fn remove(name: &str) -> anyhow::Result<()> {
    let mut store = KeyringStore::new();
    store.delete(name)?;
    eprintln!("Credential '{name}' removed.");
    Ok(())
}
