---
name: sfae
description: Use the SFAE CLI when an agent needs to call external APIs or databases that require authentication, collect credentials from the human without seeing secrets, reuse stored credential sets, request short-lived verification codes, or make HTTP/Postgres requests with secret placeholders resolved outside chat.
---

# SFAE API Credentials

## Principles

- Use `sfae` for authenticated external API calls and database queries instead of handling raw secrets directly.
- Read the target service's official API and authentication docs before choosing endpoints, auth methods, scopes, or credential field names.
- Never ask the human to paste credentials into chat.
- Check for existing credentials before prompting the human.
- Treat credential collection as human-paced. When `sfae prompt` is running, wait until it exits successfully before continuing.
- Do not pass `--terminal`; agents usually do not have the required stdin workflow.
- Use `{KEY}` placeholders in requests. SFAE resolves placeholders from the credential store at execution time without revealing values.

## CLI Availability

Use `sfae` from `PATH` when available.

If `sfae` is not available and this skill folder contains `install.sh`, run that
script to install the CLI. The support installer tries Homebrew first, then npm,
then the direct release installer:

```bash
sh ./install.sh
```

In this repository, build it if needed:

```bash
cargo build --bin sfae --release
```

Then run `./target/release/sfae` directly, or use the repository-local `./sfae` symlink when it exists.

## Core Workflow

Check stored credentials for the API domain:

```bash
sfae credentials github.com
```

If the needed credential is missing, prompt the human with a JSON spec:

```bash
sfae prompt github.com --spec '{
  "help_url": "https://github.com/settings/tokens",
  "fields": ["ACCESS_TOKEN"]
}'
```

After the prompt exits with a stored or connected credential message, send the HTTP request with placeholders:

```bash
sfae request GET "https://api.github.com/user" \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -H "User-Agent: sfae"
```

For Postgres, store fields such as `HOST`, `PORT`, `DATABASE`, `USERNAME`, and `PASSWORD`, then put the SQL in `--data` and use `--protocol postgres`:

```bash
sfae request --protocol postgres QUERY "postgres://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}" \
  --domain db.example.com \
  -d "select current_user"
```

## Prompt Specs

Use `fields` for credentials that are always shown:

```json
{
  "help_url": "https://example.com/developers",
  "fields": [
    {"name": "HOST", "label": "Server URL", "default": "https://api.example.com"},
    {"name": "USERNAME"},
    {"name": "PASSWORD"}
  ]
}
```

Field rules:

- `name` must match `[A-Z][A-Z0-9_]*`; reference it later as `{NAME}`.
- `label` defaults to a humanized version of `name`.
- `secret` defaults to true unless the name looks public, such as `USERNAME`, `HOST`, `PORT`, `URL`, or `EMAIL`.
- `default` pre-fills the browser form.
- `optional` defaults to false; blank optional fields are omitted.

Use `groups` when the human should choose one authentication method:

```bash
sfae prompt api.example.com --spec '{
  "fields": [
    {"name": "URL", "label": "API Endpoint", "default": "https://api.example.com/v2"}
  ],
  "groups": [
    {"label": "Basic Auth", "fields": ["USERNAME", "PASSWORD"]},
    {"label": "API Key", "fields": ["API_KEY"]}
  ]
}'
```

Top-level `fields` remain visible with every group.

## Placeholders And Selection

Use any stored credential key as a placeholder in URLs, headers, bodies, or Postgres SQL text:

- `{ACCESS_TOKEN}` for personal access tokens
- `{API_KEY}` for API keys
- `{USERNAME}` and `{PASSWORD}` for basic auth-style credentials
- `{HOST}`, `{PORT}`, `{DATABASE}`, or other service-specific fields
- `{OAUTH_ACCESS_TOKEN}` for hosted OAuth credentials

When a domain has one credential set, SFAE selects it automatically. When a domain has multiple sets, choose one with `--cred <uuid>` or `--label <label>`:

```bash
sfae request GET "https://api.github.com/user" \
  --cred 550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer {ACCESS_TOKEN}"
```

Get UUIDs and visible field names with `sfae credentials <domain>`.

## Hosted OAuth

Use hosted OAuth only for providers supported by SFAE. Do not put OAuth client IDs, client secrets, authorization URLs, token URLs, provider codes, or provider tokens in prompt specs.

Discord OAuth example:

```bash
sfae prompt discord.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"provider": "discord", "scopes": ["identify"]}
  }]
}'
```

Then make requests with `{OAUTH_ACCESS_TOKEN}`:

```bash
sfae request GET "https://discord.com/api/v10/users/@me" \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

To request broader OAuth access, re-run `sfae prompt` with the same domain and label plus the full required scope set. If multiple credential sets remain, select one explicitly with `--cred` or `--label`.

GitHub OAuth example:

```bash
sfae prompt github.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"provider": "github", "scopes": ["read:user"]}
  }]
}'
```

## Verification Codes

Use `sfae code` only for active, short-lived MFA or verification challenges that the agent must submit immediately:

```bash
sfae code github.com \
  --label Work \
  --message "Enter the 6-digit GitHub authentication code." \
  --length 6
```

`sfae code` prints the submitted code to stdout and does not store it. Do not use it for long-lived credentials.

## Maintenance Commands

- `sfae update` updates the CLI through the installation method that owns it.
- `sfae install-skill --codex` installs or refreshes the bundled skill in a project.
- `sfae show <uuid>` inspects public metadata for a credential set.
- `sfae delete <uuid>` forgets one credential set from SFAE's index.
- `sfae delete <uuid> --purge` may trigger OS credential-store prompts; use only when that is acceptable.
- `sfae flush --dry-run` previews a full local wipe.
- `sfae request --dry-run ...` previews a resolved request without sending it.
- `sfae request --verbose ...` helps debug request behavior without exposing secret values.
