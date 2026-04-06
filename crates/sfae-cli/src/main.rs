mod commands;
mod prompt;
mod store_factory;

use clap::{Parser, Subcommand};

/// sfae - safe credential manager and proxy allowing caller to access any online service
/// without ever seeing credentials
#[derive(Parser)]
#[command(name = "sfae", version, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List credential types available for a given domain (ACCESS_TOKEN, REFRESH_TOKEN, API_KEY, PASSWORD)
    Credentials {
        /// Domain to list credentials for (e.g. github.com)
        domain: String,
        /// Filter by username
        #[arg(long)]
        user: Option<String>,
    },
    /// Send HTTP request with placeholders (e.g. -ACCESS_TOKEN- will be replaced by actual access token)
    Request {
        /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        method: String,
        /// Request URL
        url: String,
        /// Request headers in "Key: Value" format
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body (may contain -TYPE- placeholders)
        #[arg(short = 'd', long = "data")]
        body: Option<String>,
        /// Domain for credential lookup (defaults to URL host)
        #[arg(long)]
        domain: Option<String>,
        /// Username for credential lookup
        #[arg(long)]
        user: Option<String>,
        /// Show resolved request with masked credentials, without sending
        #[arg(long)]
        dry_run: bool,
        /// Print request summary and response timing to stderr
        #[arg(long)]
        verbose: bool,
    },
    /// Prompt user for credentials
    #[cfg(feature = "keyring")]
    Prompt {
        /// Domain (e.g. github.com)
        domain: String,
        /// Credential type (ACCESS_TOKEN, REFRESH_TOKEN, API_KEY, PASSWORD)
        #[arg(name = "type")]
        cred_type: String,
        /// URL where the user can obtain the credential (e.g. settings page, OAuth login)
        #[arg(long)]
        url: Option<String>,
        /// Username (optional)
        #[arg(long)]
        user: Option<String>,
        /// Use terminal stdin instead of browser-based prompt
        #[arg(long, conflicts_with = "oauth")]
        terminal: bool,
        /// Use OAuth2 authorization code flow with PKCE
        #[arg(long)]
        oauth: bool,
        /// OAuth2 client ID (required with --oauth)
        #[arg(long, requires = "oauth")]
        client_id: Option<String>,
        /// OAuth2 authorization URL (required with --oauth)
        #[arg(long, requires = "oauth")]
        auth_url: Option<String>,
        /// OAuth2 token exchange URL (required with --oauth)
        #[arg(long, requires = "oauth")]
        token_url: Option<String>,
        /// OAuth2 scopes (comma-separated)
        #[arg(long, requires = "oauth")]
        scope: Option<String>,
        /// OAuth2 client secret (for confidential clients)
        #[arg(long, requires = "oauth")]
        client_secret: Option<String>,
        /// OAuth2 token revocation URL (optional, enables pre-flow revocation)
        #[arg(long, requires = "oauth")]
        revocation_url: Option<String>,
    },
    /// Delete credentials for a domain and user
    Delete {
        /// Domain (e.g. github.com)
        domain: String,
        /// Delete only this credential type
        #[arg(long, name = "type")]
        cred_type: Option<String>,
        /// Delete only credentials for this username
        #[arg(long)]
        user: Option<String>,
    },
    /// Delete all stored credentials
    Flush {
        /// Show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Credentials { domain, user } => {
            commands::credentials::run(&domain, user.as_deref())?;
        }
        Command::Request {
            method,
            url,
            headers,
            body,
            domain,
            user,
            dry_run,
            verbose,
        } => {
            commands::request::run(
                &method,
                &url,
                &headers,
                body.as_deref(),
                &commands::request::RequestOpts {
                    dry_run,
                    verbose,
                    domain: domain.as_deref(),
                    user: user.as_deref(),
                },
            )?;
        }
        #[cfg(feature = "keyring")]
        Command::Prompt {
            domain,
            cred_type,
            url,
            user,
            terminal,
            oauth,
            client_id,
            auth_url,
            token_url,
            scope,
            client_secret,
            revocation_url,
        } => {
            if oauth {
                let preset = sfae_core::oauth::get_provider_preset(&domain);

                let client_id =
                    client_id.or_else(|| preset.as_ref().map(|p| p.client_id.to_string()));
                let auth_url = auth_url.or_else(|| preset.as_ref().map(|p| p.auth_url.to_string()));
                let token_url =
                    token_url.or_else(|| preset.as_ref().map(|p| p.token_url.to_string()));
                let client_secret = client_secret.or_else(|| {
                    preset
                        .as_ref()
                        .and_then(|p| p.client_secret.map(|s| s.to_string()))
                });
                let revocation_url = revocation_url.or_else(|| {
                    preset
                        .as_ref()
                        .and_then(|p| p.revocation_url.map(|s| s.to_string()))
                });

                let Some(client_id) = client_id else {
                    anyhow::bail!(
                        "--client-id is required with --oauth (no built-in preset for this domain)"
                    );
                };
                let Some(auth_url) = auth_url else {
                    anyhow::bail!(
                        "--auth-url is required with --oauth (no built-in preset for this domain)"
                    );
                };
                let Some(token_url) = token_url else {
                    anyhow::bail!(
                        "--token-url is required with --oauth (no built-in preset for this domain)"
                    );
                };
                commands::prompt::run_oauth(
                    &domain,
                    &cred_type,
                    user.as_deref(),
                    &client_id,
                    &auth_url,
                    &token_url,
                    scope.as_deref(),
                    client_secret.as_deref(),
                    revocation_url.as_deref(),
                )?;
            } else {
                commands::prompt::run(
                    &domain,
                    &cred_type,
                    url.as_deref(),
                    user.as_deref(),
                    terminal,
                )?;
            }
        }
        Command::Delete {
            domain,
            cred_type,
            user,
        } => {
            commands::delete::run(&domain, cred_type.as_deref(), user.as_deref())?;
        }
        Command::Flush { dry_run } => {
            commands::flush::run(dry_run)?;
        }
    }
    Ok(())
}
