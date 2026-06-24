# SFAE - Speak Friend, and Enter

## Using external APIs

When you need to call an external API that requires authentication, use the `sfae` CLI instead of calling the API directly. This keeps credentials secure — you never see or handle raw secrets. SFAE is not a service-specific CLI; read the target service's official online API and authentication docs to choose endpoints, auth method, scopes, and credential fields.

The `sfae` binary is at `./target/release/sfae` (build with `cargo build --bin sfae --release` if missing).

### Workflow

1. **Check for existing credentials:**
   ```
   sfae credentials <domain>
   ```
   Example: `sfae credentials github.com`
   
   Lists credential sets with ID, label, and field names. Use the UUID to target a specific set.

2. **If the needed credential is missing, prompt the human to provide it:**
   ```
   sfae prompt <domain> --spec '<JSON>'
   ```

   The `--spec` flag takes a JSON object describing what credentials to collect. This opens a web page in the human's browser with a form. The command is a blocking human-interaction step: wait indefinitely until it exits. Credential collection may take as long as the human needs to create a token, grant OAuth consent, or switch accounts. Do not cancel it, impose a timeout, or continue to `sfae request` until it exits successfully after printing a stored or connected credential message.

   **Simple example** (personal access token):
   ```
   sfae prompt github.com --spec '{"help_url": "https://github.com/settings/tokens", "fields": ["ACCESS_TOKEN"]}'
   ```

   **Multi-field example** (database connection):
   ```
   sfae prompt clickhouse.example.com --spec '{
     "fields": [
       {"name": "HOST", "default": "https://ch.example.com:8443"},
       {"name": "USERNAME"},
       {"name": "PASSWORD"}
     ]
   }'
   ```

   **Do not** pass `--terminal` — that mode requires stdin access which you don't have.

   ### Spec format

   ```
   {
     "help_url"?: string,  // help link shown on the page (not a form field)
     "fields"?: Field[],   // common fields — always visible
     "groups"?: Group[]    // alternative groups — user picks one
   }
   ```

   **Fields** can be a string shorthand (`"ACCESS_TOKEN"`) or an object:
   ```
   {"name": "HOST", "label": "Server URL", "default": "https://...", "secret": false, "optional": true}
   ```
   - `name` must match `[A-Z][A-Z0-9_]*` so it can be referenced later as `{NAME}`
   - `label` defaults to a humanized version of the name (e.g. `ACCESS_TOKEN` → "Access Token")
   - `secret` auto-detects: true unless name contains USERNAME, HOST, PORT, URL, or EMAIL
   - `default` pre-fills the input
   - `optional` defaults to false; optional fields may be left empty and are omitted from the stored credential set when blank

   **Groups** let the user choose between alternatives (e.g. "Basic Auth" vs "API Key"):
   ```
   sfae prompt api.example.com --spec '{
     "groups": [
       {"label": "Basic Auth", "fields": ["USERNAME", "PASSWORD"]},
       {"label": "API Key", "fields": ["API_KEY"]}
     ]
   }'
   ```
   Common `fields` at the top level are always visible; only the active group's fields are submitted.

   **Common fields + alternative groups** (endpoint always visible, auth method toggleable):
   ```
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
   ```

3. **Make the API request using `{KEY}` placeholders:**
   ```
   sfae request <METHOD> <URL> -H "Header: {KEY}"
   ```
   Example: `sfae request GET "https://api.github.com/user" -H "Authorization: Bearer {ACCESS_TOKEN}" -H "User-Agent: sfae"`

4. **If an active workflow asks for a short-lived 2FA/MFA code, request it from the human:**
   ```
   sfae code <domain> [--label <LABEL>] [--message <TEXT>] [--length <N>]
   ```

   Example: `sfae code github.com --label Work --message "Enter the 6-digit GitHub authentication code." --length 6`

   `sfae code` opens a browser page, waits for the human, then prints only the submitted code to stdout. Use it only for one-time verification challenges that the agent must submit immediately. Unlike `sfae prompt`, this intentionally reveals the short-lived code to the agent and does not store it in the credential store or expose it as a `{KEY}` placeholder.

### Placeholder syntax

Use `{KEY}` in URLs, headers, or request bodies. Any `{ALLCAPS_NAME}` pattern is resolved from the stored credential blob. Common keys:

- `{ACCESS_TOKEN}` — PAT-style access tokens
- `{API_KEY}` — API keys
- `{PASSWORD}` — passwords
- `{USERNAME}` — usernames
- `{HOST}`, `{PORT}`, `{DATABASE}` — connection fields (ClickHouse, Postgres, etc.)
- `{OAUTH_ACCESS_TOKEN}` — OAuth bearer tokens (see OAuth section below)

There is no fixed list — any field stored in the credential blob can be used as a placeholder. SFAE resolves them from the local OS credential store, including Passwords/login keychain on macOS, at request time. You never see the actual values.

### Multi-credential support

A domain can have multiple credential sets (e.g., "Work GitHub" and "Personal GitHub"). Each set has a UUID.

- If a domain has exactly one credential set, it's used automatically.
- If a domain has multiple sets, use `--cred <uuid>` to select one:
  ```
  sfae request GET "https://api.github.com/user" --cred 550e8400-... -H "Authorization: Bearer {ACCESS_TOKEN}"
  ```
- Get UUIDs via `sfae credentials <domain>`.

### Hosted OAuth flow (Discord)

For APIs that use SFAE-hosted OAuth instead of static tokens, use an OAuth group in the spec. Hosted OAuth requires `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` so the SFAE backend can derive the current user and call `oauth.sfae.io`.

1. **Set up the OAuth credential:**

   Discord is the first hosted provider:
   ```
   sfae prompt discord.com --spec '{
     "groups": [{"label": "OAuth", "oauth": {"provider": "discord", "scopes": ["identify"]}}]
   }'
   ```

   The spec must not include OAuth `client_id`, `client_secret`, `auth_url`, `token_url`, provider codes, or provider tokens. If no hosted provider exists for the service, use the service's API-key/PAT/basic-auth flow or add hosted provider support first.

   **OAuth + API key alternative** — let the user choose:
   ```
   sfae prompt discord.com --spec '{
     "groups": [
       {"label": "API Key", "fields": ["API_KEY"]},
       {"label": "OAuth", "oauth": {"provider": "discord", "scopes": ["identify"]}}
     ]
   }'
   ```

   OAuth app credentials are managed only by `sfae-oauth-server` — never in the spec, browser, agent, or client-side code.

   This opens the provider's consent page in the human's browser. After they authorize, the hosted broker materializes an SFAE credential containing `OAUTH_ACCESS_TOKEN` and related broker-managed metadata.

   To upgrade OAuth scopes, re-run `sfae prompt` with the same domain/label and a spec containing the full required scope set. Local OAuth re-authorization stores fresh credentials with a new UUID; when SFAE can prove the authorized provider account is the same, it forgets older same-account entries from its index without reading or purging keychain secrets. If SFAE cannot prove the same account, or for non-OAuth credentials, older sets remain until `sfae delete <uuid>`.

2. **Make requests normally** — use `{OAUTH_ACCESS_TOKEN}` as the placeholder:
   ```
   sfae request GET "https://discord.com/api/v10/users/@me" \
     -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
   ```

3. **Refresh/revoke are broker responsibilities.** Do not implement provider refresh or revoke in client-side code.

**OAuth key convention:** All OAuth-related keys use the `OAUTH_` prefix to distinguish from PAT-style credentials. `client_id` and `client_secret` are per-app SFAE configuration, not per-user — they are NOT stored in the credential blob.

**Domain matching:** Store credentials under the API's base domain. Subdomain fallback works automatically.

### JSON blob storage

All credential fields are stored as a single JSON blob per credential set. Each set has:
- **UUID** — unique identifier (primary key)
- **domain** — the API domain
- **label** — optional human-friendly name (e.g., "Work", "Personal", "Staging")
- **keys** — list of field names in the blob (visible without decrypting)
- **value** — the JSON blob containing all key-value pairs

### Deleting credentials

```
sfae delete <uuid>
```

Forget a credential set from SFAE's index by UUID without reading keychain secrets. Get UUIDs via `sfae credentials`. Use `sfae delete <uuid> --purge` only when keychain/password prompts are acceptable.

### Important

- Never ask the human to paste credentials directly into the conversation
- Always use `sfae credentials` first to avoid re-prompting for credentials that are already stored
- When running `sfae prompt`, wait indefinitely until the process exits successfully; credential collection is human-paced and may take an undefined amount of time
- Use `sfae code` only for active short-lived 2FA/MFA challenges; do not use it for long-lived credentials
- Use `--verbose` flag if you need to debug a request
- Use `--dry-run` to preview the resolved request without sending it
