mod commands;
mod prompt;

use clap::{Parser, Subcommand};

/// sfae - safe credential manager and proxy allowing caller to access any online service
/// without ever seeing credentials
#[derive(Parser)]
#[command(name = "sfae", version)]
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
        #[arg(long)]
        terminal: bool,
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
        Command::Prompt {
            domain,
            cred_type,
            url,
            user,
            terminal,
        } => {
            commands::prompt::run(&domain, &cred_type, url.as_deref(), user.as_deref(), terminal)?;
        }
        Command::Delete {
            domain,
            cred_type,
            user,
        } => {
            commands::delete::run(&domain, cred_type.as_deref(), user.as_deref())?;
        }
    }
    Ok(())
}
