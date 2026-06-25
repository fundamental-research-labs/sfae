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
  5. If a provider asks for a short-lived 2FA/MFA code during a workflow, run `sfae code <domain>` and submit the code it prints. This intentionally returns only that transient code to the agent; it is not stored."#;

#[cfg(not(feature = "native-keychain"))]
const ROOT_AFTER_HELP: &str = r#"AGENT WORKFLOW:
  SFAE is a credential gateway for agents making HTTP requests to service APIs.
  `credentials` lists credential sets, `request` sends HTTP API requests with `{KEY}` placeholders resolved by SFAE, and `code` can request a transient 2FA/MFA code through the local browser.
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

#[cfg(feature = "native-keychain")]
fn wants_prompt_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "prompt") && args.iter().any(|arg| arg == "--help" || arg == "-h")
}

#[cfg(feature = "native-keychain")]
fn prompt_after_help() -> String {
    let mut help = PROMPT_AFTER_HELP_BASE.to_string();
    if let Some(section) = oauth_provider_help_section() {
        help.push_str("\n\n");
        help.push_str(&section);
    }
    help
}

#[cfg(feature = "native-keychain")]
fn oauth_provider_help_section() -> Option<String> {
    use sfae_core::oauth::HostedOAuthBroker;

    let broker = sfae_core::oauth::DirectHostedOAuthBroker::from_env().ok()?;
    let mut providers = broker.provider_registry().ok()?.providers;
    if providers.is_empty() {
        return None;
    }

    providers.sort_by(|a, b| a.provider.cmp(&b.provider));
    let mut lines = vec!["SUPPORTED OAUTH PROVIDERS:".to_string()];
    for provider in providers {
        let mut domains = provider.domains;
        domains.sort();
        domains.dedup();
        if domains.is_empty() {
            lines.push(format!("  {}", provider.provider));
        } else {
            lines.push(format!(
                "  {} (domains: {})",
                provider.provider,
                domains.join(", ")
            ));
        }
    }
    Some(lines.join("\n"))
}

const CREDENTIALS_AFTER_HELP: &str = r#"OUTPUT:
  Credential set stores print:
    <uuid>  <domain>  <label-or->  [KEY, ...]

  Use the UUID with `sfae request --cred <uuid>` when a domain has more than one credential set, with `sfae show <uuid>` to inspect non-secret metadata, or with `sfae delete <uuid>` to remove the set.
  The domain filter is exact. If requests to api.github.com use credentials stored for github.com, run `sfae credentials github.com`.
  `--label` filters by credential-set label in current stores. `--user` is accepted as a legacy alias.

EXAMPLES:
  List all stored credential sets:
    sfae credentials

  List credential sets for a service:
    sfae credentials github.com

  List the "Work" credential set for a service:
    sfae credentials github.com --label Work"#;

const SHOW_AFTER_HELP: &str = r#"OUTPUT:
  Prints public credential-set index data and non-secret metadata such as OAuth scopes, provider, expiration, and display name.
  This command does not read credential values from the keychain-backed secret blob. Older credentials may show empty metadata until recreated or refreshed.

EXAMPLES:
  Show non-secret metadata for one credential set:
    sfae show 550e8400-e29b-41d4-a716-446655440000"#;

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

const CODE_AFTER_HELP: &str = r#"AGENT RULES:
  Use this command only for short-lived verification codes requested by an active login or API workflow.
  The submitted code is printed to stdout so the agent can complete the challenge. It is not stored in the OS credential store, remote credential store, logs, or a {KEY} placeholder.
  Never use this command for long-lived credentials. Use this build's credential prompt or host integration for API keys, passwords, tokens, or OAuth authorization.

OUTPUT:
  Stdout is exactly the submitted code plus a newline. Browser/status messages go to stderr.
  Cancel, timeout, or invalid configuration exits non-zero without printing a code.

VALIDATION:
  Default format is digits, with length 4-12 and a 300 second timeout.
  `--length N` enforces an exact length. Do not combine it with `--min-length` or `--max-length`.
  Formats: digits, alnum, text.

EXAMPLES:
  Request a 6-digit code:
    sfae code github.com --label Work --message "Enter the 6-digit GitHub authentication code." --length 6

  Request an alphanumeric code:
    sfae code example.com --format alnum --min-length 6 --max-length 10"#;

const INSTALL_SKILL_AFTER_HELP: &str = r#"AGENT-FIRST INSTALL:
  SFAE is meant to be used by agents, so the primary install path is the skill. The skill includes install.sh, which can install the sfae CLI later if an agent needs it and the command is missing.

TARGETS:
  Without target flags, installs the default project-local skill folders for Codex, Claude, and Grok.
  --codex installs .agents/skills/sfae, --claude installs .claude/skills/sfae, and --grok installs .grok/skills/sfae.
  --target accepts either one of those target names or a custom directory.

AUTO-REFRESH:
  Normal sfae commands silently refresh existing project-local sfae skill folders from the embedded copy. They do not create missing skill folders. Set SFAE_SKILL_AUTO_UPDATE=off to disable that refresh.

EXAMPLES:
  Install the Codex skill in this project:
    sfae install-skill --codex

  Install every default target and immediately install the CLI if needed:
    sfae install-skill --all --install-cli"#;

const UPDATE_AFTER_HELP: &str = r#"INSTALL METHOD:
  Updates delegate to the installation method that owns the current sfae binary.
  Homebrew installs run `brew update` then `brew upgrade sfae`.
  npm installs run `npm install -g @fundamental-research-labs/sfae@latest`.
  Direct installs download and run the direct installer for the current binary directory.

OVERRIDES:
  Set SFAE_INSTALL_METHOD or SFAE_UPDATE_METHOD to brew, npm, or direct when detection is ambiguous.
  SFAE_BREW_FORMULA, SFAE_NPM_PACKAGE, and SFAE_REPO override the default package sources."#;

#[cfg(feature = "native-keychain")]
const PROMPT_AFTER_HELP_BASE: &str = r#"AGENT RULES:
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
    {"label": "OAuth", "oauth": {"provider": "provider-name", "scopes": ["scope.read"]}}

  Field names must match [A-Z][A-Z0-9_]*. A field named API_KEY is used later as `{API_KEY}`.
  OAuth groups are hosted by SFAE's OAuth broker. Use `{OAUTH_ACCESS_TOKEN}` in `sfae request` after authorization. Do not put OAuth client IDs, client secrets, authorization URLs, token URLs, or provider secrets in the spec.

OAUTH:
  Use OAuth groups when the target service's official docs require OAuth authorization.
  Set `provider` to the OAuth provider name from the service docs. If omitted, SFAE can infer it when the prompt domain matches provider metadata.
  Hosted OAuth currently supports Discord (`discord.com`), Google APIs (`googleapis.com`), and GitHub (`github.com`) when reported by the broker.
  SFAE forwards requested OAuth scopes to the provider. Ask for any scope required by the user's task, but choose the narrowest set that can satisfy the request.
  SFAE or the provider may reject unknown, unavailable, or app-restricted scopes.
  --terminal supports field prompts only; OAuth requires browser mode.

SCOPE UPGRADES / RE-AUTHORIZATION:
  To request broader OAuth access, re-run `sfae prompt` with the same domain/label and a spec containing the full required scope set.
  Local OAuth re-authorization stores fresh credentials with a new UUID. When SFAE can prove the authorized provider account is the same as an existing set, it forgets older same-account credential entries from SFAE's index without reading or purging keychain secrets.
  If SFAE cannot prove the same account, or for non-OAuth credentials, older credential sets remain until you run `sfae delete <uuid>`.
  If multiple credential sets remain for a domain, list them with `sfae credentials <domain>` and pass `sfae request --cred <uuid>` or `--label <label>` to select the intended set.

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

  OAuth:
    sfae prompt service.example --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {"provider": "provider-name", "scopes": ["scope.read"]}
      }]
    }'

  Google OAuth for Google APIs:
    sfae prompt googleapis.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {
          "provider": "google",
          "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"]
        }
      }]
    }'

  GitHub OAuth:
    sfae prompt github.com --spec '{
      "groups": [{
        "label": "OAuth",
        "oauth": {
          "provider": "github",
          "scopes": ["read:user"]
        }
      }]
    }'"#;

#[cfg(feature = "native-keychain")]
const DELETE_AFTER_HELP: &str = r#"PREFERRED USE:
  Default UUID deletion attempts broker-mediated hosted OAuth revoke when local OAuth material is available, then forgets credentials from SFAE's public index so agents stop selecting them.
  It does not delete keychain secret material.
  Use --purge only for manual cleanup when you are prepared for keychain/password prompts.
  Delete by UUID from `sfae credentials`. Domain deletion is for legacy flat credentials.
  `--type` accepts ACCESS_TOKEN, REFRESH_TOKEN, API_KEY, PASSWORD, USERNAME, or CLIENT_SECRET, and cannot be used with UUID deletion.
  `--label` filters legacy flat credentials by label/username. `--user` is accepted as a legacy alias.

EXAMPLES:
  Forget one credential set without prompting:
    sfae delete 550e8400-e29b-41d4-a716-446655440000

  Forget all legacy flat credentials for a domain:
    sfae delete github.com

  Forget one legacy flat credential type:
    sfae delete github.com --type ACCESS_TOKEN

  Purge keychain material too (may prompt for password):
    sfae delete 550e8400-e29b-41d4-a716-446655440000 --purge"#;

#[cfg(feature = "native-keychain")]
const FLUSH_AFTER_HELP: &str = r#"WARNING:
  Deletes every credential indexed by SFAE on this machine. Prefer `sfae delete <uuid>` when removing one credential set.
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
    /// Show non-secret metadata for one credential set
    #[command(after_help = SHOW_AFTER_HELP)]
    Show {
        /// Credential set UUID from `sfae credentials`
        id: String,
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
    /// Request a transient 2FA/MFA code via browser form
    #[command(after_help = CODE_AFTER_HELP)]
    Code {
        /// Target service domain asking for the code (e.g. github.com)
        domain: String,
        /// Account or credential-set label shown to the human (e.g. "Work")
        #[arg(long = "label", alias = "user", value_name = "LABEL")]
        label: Option<String>,
        /// Human-facing instruction shown on the browser page
        #[arg(long)]
        message: Option<String>,
        /// Optional verification page link shown on the browser page
        #[arg(long = "help-url")]
        help_url: Option<String>,
        /// Accepted code format: digits, alnum, or text
        #[arg(long, default_value = "digits")]
        format: String,
        /// Exact code length; cannot be combined with --min-length or --max-length
        #[arg(long)]
        length: Option<usize>,
        /// Minimum code length when --length is not set
        #[arg(long = "min-length")]
        min_length: Option<usize>,
        /// Maximum code length when --length is not set
        #[arg(long = "max-length")]
        max_length: Option<usize>,
        /// Seconds to wait for the human before timing out
        #[arg(long, default_value_t = sfae_core::code::DEFAULT_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// Install the bundled agent skill into project-local agent skill folders
    #[command(name = "install-skill", after_help = INSTALL_SKILL_AFTER_HELP)]
    InstallSkill {
        /// Install .agents/skills/sfae
        #[arg(long)]
        codex: bool,
        /// Install .claude/skills/sfae
        #[arg(long)]
        claude: bool,
        /// Install .grok/skills/sfae
        #[arg(long)]
        grok: bool,
        /// Install every default target
        #[arg(long)]
        all: bool,
        /// Install one named target or custom skill directory
        #[arg(long = "target", value_name = "TARGET")]
        targets: Vec<String>,
        /// Use a skill folder name other than sfae for named targets
        #[arg(long, default_value = "sfae")]
        name: String,
        /// Run the bundled skill installer after writing the skill
        #[arg(long = "install-cli")]
        install_cli: bool,
    },
    /// Update the sfae CLI through its owning package manager or installer
    #[command(after_help = UPDATE_AFTER_HELP)]
    Update,
    /// Collect or authorize missing credentials via browser form
    #[cfg(feature = "native-keychain")]
    #[command(after_help = PROMPT_AFTER_HELP_BASE)]
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
    /// Forget a credential set by UUID or legacy credentials by domain
    #[cfg(feature = "native-keychain")]
    #[command(after_help = DELETE_AFTER_HELP)]
    Delete {
        /// Credential set UUID or domain (e.g. github.com)
        target: String,
        /// Also delete keychain secret material; hosted OAuth revoke is attempted for UUID deletes either way
        #[arg(long)]
        purge: bool,
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
    let args: Vec<String> = std::env::args().collect();
    commands::install_skill::auto_refresh_existing();
    let mut cmd = Cli::command();
    if let Some(name) = bin_name() {
        cmd = cmd.name(name);
    }
    #[cfg(feature = "native-keychain")]
    if wants_prompt_help(&args) {
        cmd = cmd.mut_subcommand("prompt", |subcmd| subcmd.after_help(prompt_after_help()));
    }
    let cli = Cli::from_arg_matches(&cmd.get_matches())?;
    match cli.command {
        Command::Credentials { domain, label } => {
            commands::credentials::run(commands::credentials::RunArgs {
                domain: domain.as_deref(),
                username: label.as_deref(),
            })?;
        }
        Command::Show { id } => {
            commands::show::run(commands::show::RunArgs { id: &id })?;
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
        Command::Code {
            domain,
            label,
            message,
            help_url,
            format,
            length,
            min_length,
            max_length,
            timeout,
        } => {
            commands::code::run(commands::code::RunArgs {
                domain: &domain,
                label: label.as_deref(),
                message: message.as_deref(),
                help_url: help_url.as_deref(),
                format: &format,
                length,
                min_length,
                max_length,
                timeout_secs: timeout,
            })?;
        }
        Command::InstallSkill {
            codex,
            claude,
            grok,
            all,
            targets,
            name,
            install_cli,
        } => {
            commands::install_skill::run(commands::install_skill::RunArgs {
                codex,
                claude,
                grok,
                all,
                custom_targets: targets,
                name,
                install_cli,
            })?;
        }
        Command::Update => {
            commands::update::run()?;
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
            purge,
            cred_type,
            label,
        } => {
            commands::delete::run(commands::delete::RunArgs {
                target: &target,
                cred_type_str: cred_type.as_deref(),
                username: label.as_deref(),
                purge,
            })?;
        }
        #[cfg(feature = "native-keychain")]
        Command::Flush { dry_run } => {
            commands::flush::run(dry_run)?;
        }
    }
    Ok(())
}
