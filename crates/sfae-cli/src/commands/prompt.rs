use sfae_core::credential::{CredentialType, credential_key};
use sfae_core::store::{KeyringStore, SecretStore};
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;

pub fn run(
    domain: &str,
    cred_type_str: &str,
    url: Option<&str>,
    username: Option<&str>,
    terminal: bool,
) -> anyhow::Result<()> {
    let cred_type: CredentialType = cred_type_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let key = credential_key(domain, username, cred_type);

    let label = match username {
        Some(user) => format!("{cred_type} for {user}@{domain}"),
        None => format!("{cred_type} for {domain}"),
    };

    let value = if terminal {
        if let Some(u) = url {
            eprintln!("Obtain your credential here: {u}");
        }
        let prompt = TerminalPrompt;
        let v = prompt.prompt_secret(&format!("Enter {label}"))?;
        if v.is_empty() {
            anyhow::bail!("credential value cannot be empty");
        }
        v
    } else {
        sfae_core::browser::browser_prompt(&label, url)?
    };

    let mut store = KeyringStore::new();
    store.set(&key, &value)?;
    eprintln!("Credential stored: {key}");
    Ok(())
}
