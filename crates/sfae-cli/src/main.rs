//! `sfae` CLI entry point: argument parsing and dispatch to per-command modules.

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

#[cfg(feature = "native-keychain")]
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

  Common fields + alternative groups:
    sfae prompt api.example.com --spec '{
      "help_url": "https://example.com/developers",
      "fields": [
        {"name": "URL", "label": "API Endpoint", "default": "https://api.example.com/v2"}
      ],
      "groups": [
        {"label": "Basic Auth", "fields": ["USERNAME", "PASSWORD"]},
        {"label": "API Key", "fields": [{"name": "API_KEY", "label": "Developer API Key"}]}
      ]
    }'

  Optional fields:
    sfae prompt api.example.com --spec '{
      "fields": [
        {"name": "API_KEY"},
        {"name": "PROJECT_ID", "optional": true}
      ]
    }'

  OAuth (Google):
    sfae prompt googleapis.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}
      }]
    }'

  OAuth (custom provider with explicit URLs):
    sfae prompt api.custom-saas.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {
          "auth_url": "https://login.custom-saas.com/oauth/authorize",
          "token_url": "https://login.custom-saas.com/oauth/token",
          "revocation_url": "https://login.custom-saas.com/oauth/revoke",
          "scope": "api.read api.write"
        }
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
    #[cfg(feature = "native-keychain")]
    #[command(after_help = PROMPT_EXAMPLES)]
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
    #[cfg(feature = "native-keychain")]
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
    #[cfg(feature = "native-keychain")]
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
            commands::credentials::run(commands::credentials::RunArgs {
                domain: domain.as_deref(),
                username: user.as_deref(),
            })?;
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
            let opts = commands::request::RequestOpts {
                dry_run,
                verbose,
                domain: domain.as_deref(),
                user: user.as_deref(),
                cred_id: cred.as_deref(),
            };
            commands::request::run(commands::request::RunArgs {
                method: &method,
                url: &url,
                headers: &headers,
                body: body.as_deref(),
                opts: &opts,
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Prompt {
            domain,
            spec,
            user,
            terminal,
        } => {
            let prompt_spec: sfae_core::spec::PromptSpec = serde_json::from_str(&spec)
                .map_err(|e| anyhow::anyhow!("invalid --spec JSON: {e}"))?;
            prompt_spec.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
            commands::prompt::run(commands::prompt::RunArgs {
                domain: &domain,
                spec: &prompt_spec,
                username: user.as_deref(),
                terminal,
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Delete {
            target,
            cred_type,
            user,
        } => {
            commands::delete::run(commands::delete::RunArgs {
                target: &target,
                cred_type_str: cred_type.as_deref(),
                username: user.as_deref(),
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Flush { dry_run } => {
            commands::flush::run(dry_run)?;
        }
    }
    Ok(())
}
