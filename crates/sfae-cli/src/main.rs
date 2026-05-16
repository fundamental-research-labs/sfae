//! `sfae` CLI entry point: argument parsing and dispatch to per-command modules.

mod commands;
#[cfg(feature = "native-keychain")]
mod prompt;
mod store_factory;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

#[cfg(feature = "native-keychain")]
const ROOT_AFTER_HELP: &str = r#"AGENT WORKFLOW:
  SFAE is a credential gateway for agents making HTTP requests to service APIs.
  It is not a service-specific CLI for GitHub, Google, Stripe, or any other provider, and it does not teach service APIs.
  1. Read the target service's official online API and authentication docs to choose endpoints, auth method, scopes, and credential fields.
  2. Run `sfae credentials <domain>` to see stored credential sets for the service. If a suitable set exists, no human action is needed.
  3. If credentials are missing, run `sfae prompt <domain> --spec '<JSON>'` to ask the human to provide or authorize them. Treat `sfae prompt` as a blocking human-interaction step: credential collection can take as long as the human needs, so wait until the command exits. Do not impose an agent-side timeout, kill/retry it while waiting, or ask the human to paste secrets into chat. If multiple auth methods are acceptable, put several alternatives in the spec with preferred methods first. Use `sfae prompt --help` to learn the spec format.
  4. Send HTTP requests with `sfae request ...` and `{KEY}` placeholders in headers, URLs, or bodies. HTTP is the only protocol currently supported. SFAE resolves placeholders without revealing secret values to the agent.

SECRETS:
  By default, credentials are stored in the local OS credential store: Passwords/login keychain on macOS. Hosted OAuth uses oauth.sfae.io for provider authorization and stores redeemed token material locally; it does not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or a running sfae-server. If `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` are set, this CLI uses the authenticated SFAE backend instead. The agent sees credential set IDs and field names, not secret values."#;

#[cfg(not(feature = "native-keychain"))]
const ROOT_AFTER_HELP: &str = r#"AGENT WORKFLOW:
  This client build uses a remote SFAE store. Set `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` before running commands.
  `credentials` lists remote credential sets, and `request` sends HTTP API requests with `{KEY}` placeholders resolved by the remote store.
  `prompt`, `delete`, and `flush` are not available in this build. Use the host integration's request_credential client tool when credentials are missing."#;

/// Credential gateway for LLM agents making HTTP API requests
#[derive(Parser)]
#[command(
    version,
    disable_help_subcommand = true,
    after_help = ROOT_AFTER_HELP
)]
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

const CREDENTIALS_AFTER_HELP: &str = r#"OUTPUT:
  Credential set stores print:
    <uuid>  <domain>  <label-or->  [KEY, ...]

  Use the UUID with `sfae request --cred <uuid>` when a domain has more than one credential set, or with `sfae delete <uuid>` to remove the set.
  The domain filter is exact. If requests to api.github.com use credentials stored for github.com, run `sfae credentials github.com`.
  `--label` filters by credential-set label in current stores. `--user` is accepted as a legacy alias.

EXAMPLES:
  List all stored credential sets:
    sfae credentials

  List credential sets for a service:
    sfae credentials github.com

  List the "Work" credential set for a service:
    sfae credentials github.com --label Work"#;

const REQUEST_AFTER_HELP: &str = r#"AGENT RULES:
  Use this command for HTTP API calls only. Read the target service's official API docs for methods, URLs, headers, bodies, and auth scheme.
  Put `{KEY}` placeholders only where credential values belong. SFAE resolves `{ALLCAPS_NAME}` from the stored credential blob without printing secrets.
  If a domain has multiple credential sets, pick a UUID from `sfae credentials <domain>` and pass `--cred <uuid>`, or select a label with `--label <label>`.
  Use `--dry-run` to verify placeholder resolution before sending; dry-run output masks resolved credentials.
  Hosted OAuth credentials use the same `{OAUTH_ACCESS_TOKEN}` placeholder as other credential fields.

PLACEHOLDERS:
  Use `{FIELD_NAME}` in the URL, headers, or body. Field names must match [A-Z][A-Z0-9_]* and come from the selected credential set.

CREDENTIAL LOOKUP:
  By default, the lookup domain is the URL host, with parent-domain fallback. For example, api.github.com can use credentials stored for github.com.
  `--cred <uuid>` loads credentials by UUID. Pass `--domain` too if the URL host cannot be parsed before placeholders are resolved.
  `--label` selects a credential-set label in current stores. `--user` is accepted as a legacy alias.

OUTPUT:
  Prints the response body to stdout. Use --verbose for status/timing on stderr and --dry-run to preview a masked request.

EXAMPLES:
  Bearer token request:
    sfae request GET "https://api.github.com/user" \
      -H "Authorization: Bearer {ACCESS_TOKEN}" \
      -H "User-Agent: sfae"

  JSON POST with an API key:
    sfae request POST "https://api.example.com/v1/items" \
      -H "Authorization: Bearer {API_KEY}" \
      -H "Content-Type: application/json" \
      -d '{"name":"example"}'

  Select a credential set by label:
    sfae request GET "https://api.github.com/user" \
      --label Work \
      -H "Authorization: Bearer {ACCESS_TOKEN}"

  Select a specific credential set:
    sfae request GET "https://api.github.com/user" \
      --cred 550e8400-e29b-41d4-a716-446655440000 \
      -H "Authorization: Bearer {ACCESS_TOKEN}"

  Preview without sending:
    sfae request GET "https://api.github.com/user" \
      -H "Authorization: Bearer {ACCESS_TOKEN}" \
      --dry-run"#;

#[cfg(feature = "native-keychain")]
const PROMPT_EXAMPLES: &str = r#"AGENT RULES:
  Build this JSON from the target service's official authentication docs.
  Use `help_url` for the human-facing page where credentials can be created or managed.
  Use this command only to collect or authorize credentials; use `sfae request` to send HTTP API requests.
  Never ask the human to paste secrets into chat.

WAITING BEHAVIOR:
  Treat this command as a blocking human-interaction step. Browser forms and OAuth consent are human-paced and may take an undefined amount of time while the human creates tokens, grants OAuth consent, or switches accounts.
  Wait until `sfae prompt` exits. Do not impose an agent-side timeout, kill/retry the command while it is still waiting, continue to `sfae request` before it prints a stored or connected credential message, or ask the human to paste secrets into chat.

SPEC FORMAT:
  {
    "help_url"?: string,
    "fields"?: Field[],
    "groups"?: Group[]
  }

  Field:
    "API_KEY"
    {"name": "API_KEY", "label": "API Key", "default": "...", "secret": true, "optional": false}

  Group:
    {"label": "API Key", "fields": ["API_KEY"]}
    {"label": "OAuth", "oauth": {"provider": "discord", "scopes": ["identify"]}}

  Field names must match [A-Z][A-Z0-9_]*. A field named API_KEY is used later as `{API_KEY}`.
  OAuth groups are hosted by SFAE's OAuth broker. Use `{OAUTH_ACCESS_TOKEN}` in `sfae request` after authorization. Do not put OAuth client IDs, client secrets, authorization URLs, token URLs, or provider secrets in the spec.

OAUTH:
  Hosted provider in this build: discord.
  Local hosted OAuth uses oauth.sfae.io directly and stores the resulting credential in the local OS credential store.
  Set `SFAE_OAUTH_BROKER_URL` only to override the hosted broker URL for testing.
  If `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` are set, OAuth uses the authenticated SFAE backend proxy path instead.
  --terminal supports field prompts only; OAuth requires browser mode.

EXAMPLES:
  Personal access token:
    sfae prompt github.com --spec '{
      "help_url": "https://github.com/settings/tokens",
      "fields": ["ACCESS_TOKEN"]
    }'

  API key:
    sfae prompt api.example.com --spec '{
      "help_url": "https://example.com/developers/api-keys",
      "fields": ["API_KEY"]
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

  OAuth (Discord):
    sfae prompt discord.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {"provider": "discord", "scopes": ["identify"]}
      }]
    }'"#;

#[cfg(feature = "native-keychain")]
const DELETE_AFTER_HELP: &str = r#"PREFERRED USE:
  Delete by UUID from `sfae credentials`. Domain deletion is for legacy flat credentials.
  `--type` accepts ACCESS_TOKEN, REFRESH_TOKEN, API_KEY, PASSWORD, USERNAME, or CLIENT_SECRET, and cannot be used with UUID deletion.
  `--label` filters legacy flat credentials by label/username. `--user` is accepted as a legacy alias.

EXAMPLES:
  Delete one credential set:
    sfae delete 550e8400-e29b-41d4-a716-446655440000

  Delete all legacy flat credentials for a domain:
    sfae delete github.com

  Delete one legacy flat credential type:
    sfae delete github.com --type ACCESS_TOKEN"#;

#[cfg(feature = "native-keychain")]
const FLUSH_AFTER_HELP: &str = r#"WARNING:
  Deletes every locally indexed credential from Passwords/login keychain on macOS or the local OS credential store on this machine. Prefer `sfae delete <uuid>` when removing one credential set.
  Use `sfae flush --dry-run` first.

EXAMPLES:
  Preview all entries that would be removed:
    sfae flush --dry-run

  Delete all stored credentials:
    sfae flush"#;

#[derive(Subcommand)]
enum Command {
    /// List credential sets stored for a target service domain
    #[command(after_help = CREDENTIALS_AFTER_HELP)]
    Credentials {
        /// Target service domain to filter by (e.g. github.com). Lists all if omitted.
        domain: Option<String>,
        /// Filter by credential-set label (e.g. "Work", "Personal")
        #[arg(long = "label", alias = "user", value_name = "LABEL")]
        label: Option<String>,
    },
    /// Send an HTTP request, resolving {KEY} placeholders from stored credentials
    #[command(after_help = REQUEST_AFTER_HELP)]
    Request {
        /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        method: String,
        /// Service API URL from the provider's official docs
        url: String,
        /// Request headers in "Key: Value" format; values may contain {KEY} placeholders
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body (may contain {KEY} placeholders)
        #[arg(short = 'd', long = "data")]
        body: Option<String>,
        /// Domain for credential lookup (defaults to URL host)
        #[arg(long)]
        domain: Option<String>,
        /// Credential set UUID; pass --domain too if the URL host cannot be parsed
        #[arg(long)]
        cred: Option<String>,
        /// Select credential-set label (e.g. "Work", "Personal")
        #[arg(long = "label", alias = "user", value_name = "LABEL")]
        label: Option<String>,
        /// Show resolved request with masked credentials, without sending
        #[arg(long)]
        dry_run: bool,
        /// Print request summary and response timing to stderr
        #[arg(long)]
        verbose: bool,
    },
    /// Collect or authorize missing credentials via browser form
    #[cfg(feature = "native-keychain")]
    #[command(after_help = PROMPT_EXAMPLES)]
    Prompt {
        /// Target service domain where credentials will be stored (e.g. github.com)
        domain: String,
        /// JSON describing credential fields/auth options; derive it from official service docs
        #[arg(long)]
        spec: String,
        /// Label for credential set storage (e.g. "Work", "Personal")
        #[arg(long = "label", alias = "user", value_name = "LABEL")]
        label: Option<String>,
        /// Use terminal stdin instead of browser-based prompt; for manual shell use, not agents
        #[arg(long)]
        terminal: bool,
    },
    /// Delete a credential set by UUID or legacy credentials by domain
    #[cfg(feature = "native-keychain")]
    #[command(after_help = DELETE_AFTER_HELP)]
    Delete {
        /// Credential set UUID or domain (e.g. github.com)
        target: String,
        /// Delete only this credential type (legacy, not used with UUID)
        #[arg(long = "type", value_name = "TYPE")]
        cred_type: Option<String>,
        /// Delete only credentials for this legacy label/username (not used with UUID)
        #[arg(long = "label", alias = "user", value_name = "LABEL")]
        label: Option<String>,
    },
    /// Delete all stored credentials
    #[cfg(feature = "native-keychain")]
    #[command(after_help = FLUSH_AFTER_HELP)]
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
        Command::Credentials { domain, label } => {
            commands::credentials::run(commands::credentials::RunArgs {
                domain: domain.as_deref(),
                username: label.as_deref(),
            })?;
        }
        Command::Request {
            method,
            url,
            headers,
            body,
            domain,
            cred,
            label,
            dry_run,
            verbose,
        } => {
            let opts = commands::request::RequestOpts {
                dry_run,
                verbose,
                domain: domain.as_deref(),
                user: label.as_deref(),
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
            label,
            terminal,
        } => {
            let prompt_spec: sfae_core::spec::PromptSpec = serde_json::from_str(&spec)
                .map_err(|e| anyhow::anyhow!("invalid --spec JSON: {e}"))?;
            prompt_spec.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
            commands::prompt::run(commands::prompt::RunArgs {
                domain: &domain,
                spec: &prompt_spec,
                username: label.as_deref(),
                terminal,
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Delete {
            target,
            cred_type,
            label,
        } => {
            commands::delete::run(commands::delete::RunArgs {
                target: &target,
                cred_type_str: cred_type.as_deref(),
                username: label.as_deref(),
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Flush { dry_run } => {
            commands::flush::run(dry_run)?;
        }
    }
    Ok(())
}
