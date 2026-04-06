use sfae_core::browser::LocalServer;
use sfae_core::credential::{CredentialType, credential_key};
use sfae_core::oauth;
use sfae_core::ui::UserPrompt;

use crate::prompt::TerminalPrompt;
use crate::store_factory::{create_store, is_api_mode};

#[allow(clippy::too_many_arguments)]
pub fn run_oauth(
    domain: &str,
    cred_type_str: &str,
    username: Option<&str>,
    client_id: &str,
    auth_url: &str,
    token_url: &str,
    scope: Option<&str>,
    client_secret: Option<&str>,
    revocation_url: Option<&str>,
) -> anyhow::Result<()> {
    if is_api_mode() {
        anyhow::bail!(
            "OAuth prompting is not available in API store mode. \
             Use the request_oauth client tool to initiate an OAuth flow."
        );
    }
    // Validate credential type (the user asked for a specific type, e.g., ACCESS_TOKEN).
    let _cred_type: CredentialType = cred_type_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Determine effective revocation URL: explicit parameter wins, then stored metadata.
    let stored_metadata = oauth::get_oauth_metadata(domain, username)?;
    let effective_revocation_url = revocation_url.map(|s| s.to_string()).or_else(|| {
        stored_metadata
            .as_ref()
            .and_then(|m| m.revocation_url.clone())
    });

    // Revoke existing access token before starting a new OAuth flow, so the provider
    // is forced to issue a fresh token with the newly-requested scopes.
    if let Some(ref rev_url) = effective_revocation_url {
        let access_key = credential_key(domain, username, CredentialType::AccessToken);
        let store = create_store();
        if let Ok(existing_token) = store.get(&access_key) {
            match oauth::revoke_token(rev_url, &existing_token) {
                Ok(()) => eprintln!("Revoked existing access token for {domain}"),
                Err(e) => eprintln!("Warning: failed to revoke existing token: {e}"),
            }
        }
    }

    // Generate PKCE verifier and challenge.
    let verifier = oauth::generate_code_verifier();
    let challenge = oauth::compute_code_challenge(&verifier);
    let state = oauth::generate_state();

    // Start the local callback server.
    let server = LocalServer::new()?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", server.port());

    // Build the authorization URL and open the browser.
    let authorization_url = oauth::build_authorization_url(
        auth_url,
        client_id,
        &redirect_uri,
        &challenge,
        scope,
        &state,
    );
    server.open_browser(&authorization_url)?;

    eprintln!("Waiting for OAuth authorization in browser...");

    // Wait for the callback.
    let (code, returned_state) = sfae_core::browser::oauth_callback(&server)?;

    // Verify state matches.
    if returned_state != state {
        anyhow::bail!("OAuth state mismatch — possible CSRF attack");
    }

    // Exchange the authorization code for tokens.
    let token_response = oauth::exchange_code(
        token_url,
        &code,
        &redirect_uri,
        client_id,
        client_secret,
        &verifier,
    )?;

    // Store the access token.
    let mut store = create_store();

    let access_key = credential_key(domain, username, CredentialType::AccessToken);
    store.set(&access_key, &token_response.access_token)?;
    eprintln!("Credential stored: {access_key}");

    // Store refresh token if present.
    if let Some(ref refresh_token) = token_response.refresh_token {
        let refresh_key = credential_key(domain, username, CredentialType::RefreshToken);
        store.set(&refresh_key, refresh_token)?;
        eprintln!("Credential stored: {refresh_key}");
    }

    // Store client secret if present.
    if let Some(secret) = client_secret {
        let secret_key = credential_key(domain, username, CredentialType::ClientSecret);
        store.set(&secret_key, secret)?;
        eprintln!("Credential stored: {secret_key}");
    }

    // Save OAuth metadata for token refresh.
    oauth::save_oauth_metadata(
        domain,
        username,
        oauth::OAuthMetadata {
            token_url: token_url.to_string(),
            client_id: client_id.to_string(),
            revocation_url: effective_revocation_url,
        },
    )?;
    eprintln!("OAuth metadata saved for {domain}");

    Ok(())
}

pub fn run(
    domain: &str,
    cred_type_str: &str,
    url: Option<&str>,
    username: Option<&str>,
    terminal: bool,
) -> anyhow::Result<()> {
    if is_api_mode() {
        anyhow::bail!(
            "Credential prompting is not available in API store mode. \
             Use the request_credential client tool to request credentials from the user."
        );
    }

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

    let mut store = create_store();
    store.set(&key, &value)?;
    eprintln!("Credential stored: {key}");
    Ok(())
}
