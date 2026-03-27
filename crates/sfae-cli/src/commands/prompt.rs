use sfae_core::credential::{credential_key, CredentialType};
use sfae_core::store::{KeyringStore, SecretStore};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;

pub fn run(domain: &str, cred_type_str: &str, url: &str, username: Option<&str>) -> anyhow::Result<()> {
    let cred_type: CredentialType = cred_type_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let key = credential_key(domain, username, cred_type);
    let prompt = TerminalPrompt;

    let label = match username {
        Some(user) => format!("{cred_type} for {user}@{domain}"),
        None => format!("{cred_type} for {domain}"),
    };

    eprintln!("Obtain your credential here: {url}");
    let value = prompt.prompt_secret(&format!("Enter {label}"))?;
    if value.is_empty() {
        anyhow::bail!("credential value cannot be empty");
    }

    let mut store = KeyringStore::new();
    store.set(&key, &value)?;
    eprintln!("Credential stored: {key}");
    Ok(())
}
