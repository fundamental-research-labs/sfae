# SFAE - Speak Friend, and Enter

## Using external APIs

When you need to call an external API that requires authentication, use the `sfae` CLI instead of calling the API directly. This keeps credentials secure — you never see or handle raw secrets.

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

   The `--spec` flag takes a JSON object describing what credentials to collect. This opens a web page in the human's browser with a form. The command blocks until the human submits the form, then stores all fields as a JSON blob in the OS keychain and returns the UUID.

   **Simple example** (single API key):
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
   {"name": "HOST", "label": "Server URL", "default": "https://...", "secret": false}
   ```
   - `label` defaults to a humanized version of the name (e.g. `ACCESS_TOKEN` → "Access Token")
   - `secret` auto-detects: true unless name contains USERNAME, HOST, PORT, URL, or EMAIL
   - `default` pre-fills the input

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

### Placeholder syntax

Use `{KEY}` in URLs, headers, or request bodies. Any `{ALLCAPS_NAME}` pattern is resolved from the stored credential blob. Common keys:

- `{ACCESS_TOKEN}` — PAT-style access tokens
- `{API_KEY}` — API keys
- `{PASSWORD}` — passwords
- `{USERNAME}` — usernames
- `{HOST}`, `{PORT}`, `{DATABASE}` — connection fields (ClickHouse, Postgres, etc.)
- `{OAUTH_ACCESS_TOKEN}` — OAuth bearer tokens (see OAuth section below)

There is no fixed list — any field stored in the credential blob can be used as a placeholder. SFAE resolves them from the OS keychain at request time. You never see the actual values.

### Multi-credential support

A domain can have multiple credential sets (e.g., "Work GitHub" and "Personal GitHub"). Each set has a UUID.

- If a domain has exactly one credential set, it's used automatically.
- If a domain has multiple sets, use `--cred <uuid>` to select one:
  ```
  sfae request GET "https://api.github.com/user" --cred 550e8400-... -H "Authorization: Bearer {ACCESS_TOKEN}"
  ```
- Get UUIDs via `sfae credentials <domain>`.

### OAuth flow (for Google, GitHub Apps, etc.)

For APIs that use OAuth 2.0 instead of static tokens, use an OAuth group in the spec:

1. **Set up the OAuth credential:**

   **Known providers (Google):** sfae has built-in OAuth presets — just specify the domain and scope:
   ```
   sfae prompt googleapis.com --spec '{
     "groups": [{"label": "OAuth", "oauth": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}}]
   }'
   ```

   Built-in presets: `googleapis.com` (covers all Google API subdomains). SFAE fills in `auth_url`/`token_url` automatically.

   **Other providers:** pass OAuth URLs explicitly in the spec:
   ```
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
   }'
   ```

   For unknown providers, `auth_url` and `token_url` are required. `revocation_url` is optional.

   **OAuth + API key alternative** — let the user choose:
   ```
   sfae prompt googleapis.com --spec '{
     "groups": [
       {"label": "API Key", "fields": ["API_KEY"]},
       {"label": "OAuth", "oauth": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}}
     ]
   }'
   ```

   OAuth app credentials (`client_id`, `client_secret`) are managed by SFAE internally — never in the spec.

   This opens the provider's consent page in the human's browser. After they authorize, sfae stores `OAUTH_ACCESS_TOKEN`, `OAUTH_REFRESH_TOKEN`, `OAUTH_TOKEN_URL`, and `OAUTH_REVOCATION_URL` (if provided) in the credential set.

2. **Make requests normally** — use `{OAUTH_ACCESS_TOKEN}` as the placeholder:
   ```
   sfae request GET "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1" \
     -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
   ```

3. **Token refresh is automatic.** If a request gets a 401, sfae reads `OAUTH_TOKEN_URL` from the blob and `client_id`/`client_secret` from server env config, refreshes the token, and retries — no action needed from you.

**OAuth key convention:** All OAuth-related keys use the `OAUTH_` prefix to distinguish from PAT-style credentials. `client_id` and `client_secret` are per-app (from server env), not per-user — they are NOT stored in the credential blob.

**Domain matching:** Store credentials under the API's base domain (e.g., `googleapis.com`), not the auth provider domain (e.g., `google.com`). Subdomain fallback works automatically — a credential stored for `googleapis.com` resolves for `www.googleapis.com`, `gmail.googleapis.com`, etc.

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

Delete a credential set by its UUID. Get UUIDs via `sfae credentials`.

### Important

- Never ask the human to paste credentials directly into the conversation
- Always use `sfae credentials` first to avoid re-prompting for credentials that are already stored
- Use `--verbose` flag if you need to debug a request
- Use `--dry-run` to preview the resolved request without sending it
