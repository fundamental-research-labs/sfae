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

2. **If the needed credential is missing, prompt the human to provide it:**
   ```
   sfae prompt <domain> <TYPE> [--url <URL_WHERE_HUMAN_CAN_GET_CREDENTIAL>]
   ```
   Example: `sfae prompt github.com ACCESS_TOKEN --url "https://github.com/settings/tokens"`

   This opens a web page in the human's browser with a form to enter the credential. The `--url` value is shown as a helpful link on that page. The command blocks until the human submits the form, then stores the credential securely in the OS keychain.

   **Do not** pass `--terminal` — that mode requires stdin access which you don't have.

3. **Make the API request using placeholders:**
   ```
   sfae request <METHOD> <URL> -H "Header: -TYPE-"
   ```
   Example: `sfae request GET "https://api.github.com/user" -H "Authorization: Bearer -ACCESS_TOKEN-" -H "User-Agent: sfae"`

### Placeholder syntax

Use `-TYPE-` in URLs, headers, or request bodies. Available types:
- `-ACCESS_TOKEN-`
- `-API_KEY-`
- `-PASSWORD-`
- `-REFRESH_TOKEN-`

SFAE resolves these from the OS keychain at request time. You never see the actual values.

### OAuth flow (for Google, GitHub Apps, etc.)

For APIs that use OAuth 2.0 instead of static tokens:

1. **Set up the OAuth credential:**

   **Known providers (Google):** sfae has built-in OAuth presets — just specify the domain and scope:
   ```
   sfae prompt <domain> ACCESS_TOKEN --oauth --scope "<SPACE_SEPARATED_SCOPES>"
   ```

   Example (Google Gmail):
   ```
   sfae prompt googleapis.com ACCESS_TOKEN --oauth \
     --scope "https://www.googleapis.com/auth/gmail.readonly"
   ```

   Built-in presets: `googleapis.com` (covers all Google API subdomains).

   **Other providers:** pass all OAuth parameters explicitly:
   ```
   sfae prompt <domain> ACCESS_TOKEN --oauth \
     --client-id "<CLIENT_ID>" \
     --auth-url "<AUTHORIZATION_URL>" \
     --token-url "<TOKEN_URL>" \
     --scope "<SPACE_SEPARATED_SCOPES>" \
     --client-secret "<CLIENT_SECRET>"
   ```

   Explicit flags override built-in preset values. `--client-secret` is optional for public OAuth clients.

   This opens the provider's consent page in the human's browser. After they authorize, sfae stores the access token, refresh token, and OAuth metadata automatically.

2. **Make requests normally** — use `-ACCESS_TOKEN-` as with any credential:
   ```
   sfae request GET "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1" \
     -H "Authorization: Bearer -ACCESS_TOKEN-"
   ```

3. **Token refresh is automatic.** If a request gets a 401, sfae uses the stored refresh token to obtain a new access token and retries — no action needed from you.

**Domain matching:** Store credentials under the API's base domain (e.g., `googleapis.com`), not the auth provider domain (e.g., `google.com`). Subdomain fallback works automatically — a credential stored for `googleapis.com` resolves for `www.googleapis.com`, `gmail.googleapis.com`, etc.

### Important

- Never ask the human to paste credentials directly into the conversation
- Always use `sfae credentials` first to avoid re-prompting for credentials that are already stored
- Use `--verbose` flag if you need to debug a request
- Use `--dry-run` to preview the resolved request without sending it
