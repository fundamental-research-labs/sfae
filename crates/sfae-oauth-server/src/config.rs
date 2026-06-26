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
    pub(crate) google_client_id: String,
    pub(crate) google_client_secret: String,
    pub(crate) google_authorize_url: Url,
    pub(crate) google_token_url: Url,
    pub(crate) google_revoke_url: Url,
    pub(crate) google_userinfo_url: Url,
    pub(crate) github_client_id: String,
    pub(crate) github_client_secret: String,
    pub(crate) github_authorize_url: Url,
    pub(crate) github_token_url: Url,
    pub(crate) github_api_url: Url,
    pub(crate) github_userinfo_url: Url,
    pub(crate) dropbox_client_id: String,
    pub(crate) dropbox_client_secret: String,
    pub(crate) dropbox_authorize_url: Url,
    pub(crate) dropbox_token_url: Url,
    pub(crate) dropbox_revoke_url: Url,
    pub(crate) dropbox_current_account_url: Url,
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
        let google_client_id = required_env("GOOGLE_CLIENT_ID");
        let google_client_secret = required_env("GOOGLE_CLIENT_SECRET");
        let google_authorize_url = provider_url(
            "GOOGLE_AUTHORIZE_URL",
            "https://accounts.google.com/o/oauth2/v2/auth",
        );
        let google_token_url =
            provider_url("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token");
        let google_revoke_url =
            provider_url("GOOGLE_REVOKE_URL", "https://oauth2.googleapis.com/revoke");
        let google_userinfo_url = provider_url(
            "GOOGLE_USERINFO_URL",
            "https://openidconnect.googleapis.com/v1/userinfo",
        );
        let github_client_id = required_env("GITHUB_CLIENT_ID");
        let github_client_secret = required_env("GITHUB_CLIENT_SECRET");
        let github_authorize_url = provider_url(
            "GITHUB_AUTHORIZE_URL",
            "https://github.com/login/oauth/authorize",
        );
        let github_token_url = provider_url(
            "GITHUB_TOKEN_URL",
            "https://github.com/login/oauth/access_token",
        );
        let github_api_url = provider_url("SFAE_GITHUB_API_URL", "https://api.github.com");
        let github_userinfo_url =
            provider_url("GITHUB_USERINFO_URL", "https://api.github.com/user");
        let dropbox_client_id = required_env("DROPBOX_CLIENT_ID");
        let dropbox_client_secret = required_env("DROPBOX_CLIENT_SECRET");
        let dropbox_authorize_url = provider_url(
            "DROPBOX_AUTHORIZE_URL",
            "https://www.dropbox.com/oauth2/authorize",
        );
        let dropbox_token_url =
            provider_url("DROPBOX_TOKEN_URL", "https://api.dropbox.com/oauth2/token");
        let dropbox_revoke_url = provider_url(
            "DROPBOX_REVOKE_URL",
            "https://api.dropboxapi.com/2/auth/token/revoke",
        );
        let dropbox_current_account_url = provider_url(
            "DROPBOX_CURRENT_ACCOUNT_URL",
            "https://api.dropboxapi.com/2/users/get_current_account",
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
            google_client_id,
            google_client_secret,
            google_authorize_url,
            google_token_url,
            google_revoke_url,
            google_userinfo_url,
            github_client_id,
            github_client_secret,
            github_authorize_url,
            github_token_url,
            github_api_url,
            github_userinfo_url,
            dropbox_client_id,
            dropbox_client_secret,
            dropbox_authorize_url,
            dropbox_token_url,
            dropbox_revoke_url,
            dropbox_current_account_url,
            base_url,
            allowed_return_origins,
            port,
        }
    }

    /// Build the registered Discord callback URL from BASE_URL.
    pub(crate) fn discord_redirect_uri(&self) -> String {
        self.generic_redirect_uri()
    }

    /// Build the provider-neutral OAuth callback URL from BASE_URL.
    pub(crate) fn generic_redirect_uri(&self) -> String {
        self.base_url
            .join("/oauth/callback")
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

    /// Build GitHub's OAuth grant deletion endpoint from the configured API base URL.
    pub(crate) fn github_grant_url(&self) -> Url {
        self.github_api_url
            .join(&format!("/applications/{}/grant", self.github_client_id))
            .expect("valid GitHub grant path")
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
