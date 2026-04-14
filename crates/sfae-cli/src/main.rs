mod commands;
mod prompt;
mod store_factory;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

/// sfae - safe credential manager and proxy allowing caller to access any online service
/// without ever seeing credentials
#[derive(Parser)]
#[command(version, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn bin_name() -> Option<&'static str> {
    std::env::args().next().and_then(|s| {
        std::path::Path::new(&s)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .map(|s| &*Box::leak(s.into_boxed_str()))
    })
}

#[cfg(feature = "keyring")]
const PROMPT_EXAMPLES: &str = r#"EXAMPLES:
  Single field (API key):
    sfae prompt github.com --spec '{
      "help_url": "https://github.com/settings/tokens",
      "fields": ["ACCESS_TOKEN"]
    }'

  Multi-field with defaults:
    sfae prompt clickhouse.example.com --spec '{
      "fields": [
        {"name": "HOST", "default": "https://ch.example.com:8443"},
        {"name": "USERNAME"},
        {"name": "PASSWORD"}
      ]
    }'

  Alternative groups (basic auth OR API key):
    sfae prompt api.example.com --spec '{
      "groups": [
        {"label": "Basic Auth", "fields": ["USERNAME", "PASSWORD"]},
        {"label": "API Key", "fields": ["API_KEY"]}
      ]
    }'

  OAuth (Google):
    sfae prompt googleapis.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}
      }]
    }'"#;

#[derive(Subcommand)]
enum Command {
    /// List credential sets (optionally filtered by domain)
    Credentials {
        /// Domain to filter by (e.g. github.com). Lists all if omitted.
        domain: Option<String>,
        /// Filter by label
        #[arg(long)]
        user: Option<String>,
    },
    /// Send HTTP request with {KEY} placeholders resolved from stored credentials
    Request {
        /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        method: String,
        /// Request URL
        url: String,
        /// Request headers in "Key: Value" format
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body (may contain {KEY} placeholders)
        #[arg(short = 'd', long = "data")]
        body: Option<String>,
        /// Domain for credential lookup (defaults to URL host)
        #[arg(long)]
        domain: Option<String>,
        /// Credential set UUID (direct lookup, skips domain resolution)
        #[arg(long)]
        cred: Option<String>,
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
    #[command(after_long_help = PROMPT_EXAMPLES)]
    Prompt {
        /// Domain (e.g. github.com)
        domain: String,
        /// Credential spec as JSON (see examples with --help)
        #[arg(long)]
        spec: String,
        /// Label for credential set storage (e.g. "Work", "Personal")
        #[arg(long)]
        user: Option<String>,
        /// Use terminal stdin instead of browser-based prompt
        #[arg(long)]
        terminal: bool,
    },
    /// Delete a credential set by UUID or legacy credentials by domain
    #[cfg(feature = "keyring")]
    Delete {
        /// Credential set UUID or domain (e.g. github.com)
        target: String,
        /// Delete only this credential type (legacy, not used with UUID)
        #[arg(long, name = "type")]
        cred_type: Option<String>,
        /// Delete only credentials for this username (legacy, not used with UUID)
        #[arg(long)]
        user: Option<String>,
    },
    /// Delete all stored credentials
    #[cfg(feature = "keyring")]
    Flush {
        /// Show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    if let Some(name) = bin_name() {
        cmd = cmd.name(name);
    }
    let cli = Cli::from_arg_matches(&cmd.get_matches())?;
    match cli.command {
        Command::Credentials { domain, user } => {
            commands::credentials::run(domain.as_deref(), user.as_deref())?;
        }
        Command::Request {
            method,
            url,
            headers,
            body,
            domain,
            cred,
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
                    cred_id: cred.as_deref(),
                },
            )?;
        }
        #[cfg(feature = "keyring")]
        Command::Prompt {
            domain,
            spec,
            user,
            terminal,
        } => {
            let prompt_spec: sfae_core::spec::PromptSpec = serde_json::from_str(&spec)
                .map_err(|e| anyhow::anyhow!("invalid --spec JSON: {e}"))?;
            prompt_spec.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
            commands::prompt::run(&domain, &prompt_spec, user.as_deref(), terminal)?;
        }
        #[cfg(feature = "keyring")]
        Command::Delete {
            target,
            cred_type,
            user,
        } => {
            commands::delete::run(&target, cred_type.as_deref(), user.as_deref())?;
        }
        #[cfg(feature = "keyring")]
        Command::Flush { dry_run } => {
            commands::flush::run(dry_run)?;
        }
    }
    Ok(())
}
