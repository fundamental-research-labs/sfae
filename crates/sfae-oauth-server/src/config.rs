//! Runtime configuration loaded from environment variables for the OAuth service.

use std::collections::HashSet;

use url::Url;

const TEST_PROVIDER_URLS_ENV: &str = "SFAE_OAUTH_ALLOW_TEST_PROVIDER_URLS";

/// Environment-derived service configuration.
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) database_url: String,
    pub(crate) internal_auth_secret: String,
    pub(crate) token_encryption_key: String,
    pub(crate) discord_client_id: String,
    pub(crate) discord_client_secret: String,
    pub(crate) discord_authorize_url: Url,
    pub(crate) discord_token_url: Url,
    pub(crate) discord_token_revoke_url: Url,
    pub(crate) discord_userinfo_url: Url,
    pub(crate) base_url: Url,
    pub(crate) allowed_return_origins: HashSet<String>,
    pub(crate) port: u16,
}

impl Config {
    /// Read and validate the service configuration from process env.
    pub(crate) fn from_env() -> Self {
        let database_url = required_env("DATABASE_URL");
        let internal_auth_secret = required_env("SFAE_INTERNAL_AUTH_SECRET");
        let token_encryption_key = required_env("SFAE_OAUTH_TOKEN_ENCRYPTION_KEY");
        let discord_client_id = required_env("DISCORD_CLIENT_ID");
        let discord_client_secret = required_env("DISCORD_CLIENT_SECRET");
        let discord_authorize_url = provider_url(
            "DISCORD_AUTHORIZE_URL",
            "https://discord.com/oauth2/authorize",
        );
        let discord_token_url =
            provider_url("DISCORD_TOKEN_URL", "https://discord.com/api/oauth2/token");
        let discord_token_revoke_url = provider_url(
            "DISCORD_TOKEN_REVOKE_URL",
            "https://discord.com/api/oauth2/token/revoke",
        );
        let discord_userinfo_url = provider_url(
            "DISCORD_USERINFO_URL",
            "https://discord.com/api/v10/users/@me",
        );
        let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3100".into());
        let base_url = Url::parse(base_url.trim_end_matches('/')).expect("BASE_URL must be a URL");
        let port = std::env::var("SFAE_SERVER_PORT")
            .unwrap_or_else(|_| "3100".into())
            .parse()
            .expect("SFAE_SERVER_PORT must be a valid u16");

        let mut allowed_return_origins = HashSet::new();
        allowed_return_origins.insert(origin(&base_url));
        for raw in std::env::var("ALLOWED_RETURN_ORIGINS")
            .unwrap_or_default()
            .split(',')
        {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let url = Url::parse(trimmed).expect("ALLOWED_RETURN_ORIGINS entries must be URLs");
            allowed_return_origins.insert(origin(&url));
        }

        Self {
            database_url,
            internal_auth_secret,
            token_encryption_key,
            discord_client_id,
            discord_client_secret,
            discord_authorize_url,
            discord_token_url,
            discord_token_revoke_url,
            discord_userinfo_url,
            base_url,
            allowed_return_origins,
            port,
        }
    }

    /// Build the registered Discord callback URL from BASE_URL.
    pub(crate) fn discord_redirect_uri(&self) -> String {
        self.base_url
            .join("/v1/callback/discord")
            .expect("valid callback path")
            .to_string()
    }

    /// Build the default human-visible completion page URL.
    pub(crate) fn default_return_url(&self) -> String {
        self.base_url
            .join("/v1/done")
            .expect("valid done path")
            .to_string()
    }

    /// Check whether a browser return URL is in the configured origin allowlist.
    pub(crate) fn return_url_allowed(&self, raw: &str) -> bool {
        Url::parse(raw)
            .map(|url| self.allowed_return_origins.contains(&origin(&url)))
            .unwrap_or(false)
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

// xtask: allow-multi-param - env var name plus production default URL
fn provider_url(name: &str, default: &str) -> Url {
    let Ok(raw) = std::env::var(name) else {
        return Url::parse(default).expect("static provider URL must be valid");
    };
    let url =
        Url::parse(raw.trim_end_matches('/')).unwrap_or_else(|_| panic!("{name} must be a URL"));
    if test_provider_urls_allowed() && provider_test_url_allowed(&url) {
        return url;
    }
    panic!("{name} overrides are test-only; set {TEST_PROVIDER_URLS_ENV}=1 and use a loopback URL");
}

fn test_provider_urls_allowed() -> bool {
    std::env::var(TEST_PROVIDER_URLS_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn provider_test_url_allowed(url: &Url) -> bool {
    let loopback = matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("localhost") | Some("::1")
    );
    loopback && matches!(url.scheme(), "http" | "https")
}

fn origin(url: &Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}
