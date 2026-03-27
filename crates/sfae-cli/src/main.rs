mod commands;
mod prompt;

use clap::{Parser, Subcommand};

/// SFAE — Speak Friend, and Enter
///
/// Secrets management and API proxy for LLM agents.
#[derive(Parser)]
#[command(name = "sfae", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage stored credentials
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Manage service configurations
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Proxy an HTTP request, resolving {{sfae:name}} placeholders
    Proxy {
        /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        method: String,
        /// Request URL (may contain {{sfae:name}} placeholders)
        url: String,
        /// Request headers in "Key: Value" format
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body (may contain {{sfae:name}} placeholders)
        #[arg(short = 'd', long = "data")]
        body: Option<String>,
        /// Prepend service base URL to the request path
        #[arg(long)]
        service: Option<String>,
        /// Show resolved request with masked credentials, without sending
        #[arg(long)]
        dry_run: bool,
        /// Print request summary and response timing to stderr
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum CredentialAction {
    /// Store a new credential
    Add {
        /// Credential name (alphanumerics, underscores, hyphens)
        name: String,
    },
    /// List all stored credential names
    List,
    /// Remove a stored credential
    Remove {
        /// Credential name to remove
        name: String,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Register a new service
    Add {
        /// Unique service identifier
        id: String,
        /// Human-readable display name
        #[arg(long)]
        name: String,
        /// Base URL for the service API
        #[arg(long)]
        url: String,
    },
    /// List all registered services
    List,
    /// Show details of a single service
    Show {
        /// Service identifier
        id: String,
    },
    /// Remove a registered service
    Remove {
        /// Service identifier to remove
        id: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Credential { action } => match action {
            CredentialAction::Add { name } => commands::credential::add(&name)?,
            CredentialAction::List => commands::credential::list()?,
            CredentialAction::Remove { name } => commands::credential::remove(&name)?,
        },
        Command::Service { action } => match action {
            ServiceAction::Add { id, name, url } => {
                commands::service::add(&id, &name, &url)?;
            }
            ServiceAction::List => commands::service::list()?,
            ServiceAction::Show { id } => commands::service::show(&id)?,
            ServiceAction::Remove { id } => commands::service::remove(&id)?,
        },
        Command::Proxy {
            method,
            url,
            headers,
            body,
            service,
            dry_run,
            verbose,
        } => commands::proxy::run(&method, &url, &headers, body.as_deref(), service.as_deref(), dry_run, verbose)?,
    }
    Ok(())
}
