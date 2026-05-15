//! Discord OAuth provider descriptor, token exchange, and identity lookup.

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use url::Url;

use crate::config::Config;

const AUTH_URL: &str = "https://discord.com/oauth2/authorize";
pub(crate) const TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
pub(crate) const REVOCATION_URL: &str = "https://discord.com/api/oauth2/token/revoke";
const USERINFO_URL: &str = "https://discord.com/api/v10/users/@me";
const ALLOWED_SCOPES: &[&str] = &["identify", "email", "guilds"];

/// Validated Discord OAuth session inputs.
pub(crate) struct DiscordSession {
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_url: String,
}

/// Discord OAuth token response fields used by SFAE.
#[derive(Deserialize)]
pub(crate) struct DiscordToken {
    pub(crate) access_token: String,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
    #[serde(default)]
    pub(crate) token_type: Option<String>,
    #[serde(default)]
    pub(crate) scope: Option<String>,
    #[serde(default)]
    pub(crate) expires_in: Option<i64>,
}

impl DiscordToken {
    /// Compute the absolute access-token expiry when Discord returns `expires_in`.
    pub(crate) fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_in
            .map(|seconds| Utc::now() + Duration::seconds(seconds))
    }

    /// Return provider scopes as a sorted vector.
    pub(crate) fn scopes(&self, requested: &[String]) -> Vec<String> {
        let mut scopes = self
            .scope
            .as_deref()
            .map(split_scopes)
            .unwrap_or_else(|| requested.to_vec());
        scopes.sort();
        scopes.dedup();
        scopes
    }
}

/// Discord `/users/@me` profile fields used for account linking.
#[derive(Deserialize)]
pub(crate) struct DiscordUser {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) global_name: Option<String>,
    #[serde(default)]
    pub(crate) email: Option<String>,
}

impl DiscordUser {
    /// Prefer Discord display name and fall back to username.
    pub(crate) fn display_name(&self) -> Option<String> {
        self.global_name.clone().or_else(|| self.username.clone())
    }
}

/// Build a validated Discord authorization URL for the browser.
pub(crate) fn build_authorization(args: DiscordAuthorize<'_>) -> Result<DiscordSession, String> {
    let DiscordAuthorize {
        config,
        state,
        requested_scopes,
    } = args;
    let scopes = normalize_scopes(requested_scopes)?;
    let redirect_uri = config.discord_redirect_uri();
    let mut url = Url::parse(AUTH_URL).expect("Discord auth URL is static and valid");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.discord_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", state)
        .append_pair("prompt", "consent");
    Ok(DiscordSession {
        scopes,
        authorization_url: url.to_string(),
    })
}

/// Inputs for building the Discord authorize URL.
pub(crate) struct DiscordAuthorize<'a> {
    pub(crate) config: &'a Config,
    pub(crate) state: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Exchange an authorization code for Discord tokens.
pub(crate) async fn exchange_code(args: DiscordTokenRequest<'_>) -> Result<DiscordToken, String> {
    let DiscordTokenRequest { http, config, code } = args;
    let redirect_uri = config.discord_redirect_uri();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &config.discord_client_id),
        ("client_secret", &config.discord_client_secret),
    ];
    let response = http
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("discord token request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!("Discord token exchange rejected: {status} {body}");
        return Err(format!("discord_token_status_{status}"));
    }
    response
        .json::<DiscordToken>()
        .await
        .map_err(|e| format!("discord token response parse failed: {e}"))
}

/// Inputs for a Discord token exchange.
pub(crate) struct DiscordTokenRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) code: &'a str,
}

/// Fetch the Discord account profile for a bearer access token.
pub(crate) async fn fetch_user(args: DiscordUserRequest<'_>) -> Result<DiscordUser, String> {
    let DiscordUserRequest { http, access_token } = args;
    let response = http
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("discord user request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(format!("discord_user_status_{status}"));
    }
    response
        .json::<DiscordUser>()
        .await
        .map_err(|e| format!("discord user response parse failed: {e}"))
}

/// Inputs for loading Discord user identity.
pub(crate) struct DiscordUserRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) access_token: &'a str,
}

fn normalize_scopes(requested: &[String]) -> Result<Vec<String>, String> {
    let mut scopes = if requested.is_empty() {
        vec!["identify".to_string()]
    } else {
        requested.to_vec()
    };
    for scope in &scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(format!("unsupported Discord scope: {scope}"));
        }
    }
    if !scopes.iter().any(|s| s == "identify") {
        scopes.push("identify".to_string());
    }
    scopes.sort();
    scopes.dedup();
    Ok(scopes)
}

fn split_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}
