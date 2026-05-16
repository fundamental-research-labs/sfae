//! Discord OAuth provider descriptor, token exchange, and identity lookup.

use crate::config::Config;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

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
    let mut url = config.discord_authorize_url.clone();
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
        .post(config.discord_token_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("discord token request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Discord token exchange rejected: {status}");
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

/// Refresh a Discord access token with a refresh token.
pub(crate) async fn refresh_token(args: DiscordRefreshRequest<'_>) -> Result<DiscordToken, String> {
    let DiscordRefreshRequest {
        http,
        config,
        refresh_token,
    } = args;
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let response = http
        .post(config.discord_token_url.clone())
        .basic_auth(
            &config.discord_client_id,
            Some(&config.discord_client_secret),
        )
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("discord refresh request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Discord token refresh rejected: {status}");
        return Err(format!("discord_refresh_status_{status}"));
    }
    response
        .json::<DiscordToken>()
        .await
        .map_err(|e| format!("discord refresh response parse failed: {e}"))
}

/// Inputs for a Discord token refresh.
pub(crate) struct DiscordRefreshRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) refresh_token: &'a str,
}

/// Revoke a Discord access or refresh token.
pub(crate) async fn revoke_token(args: DiscordRevokeRequest<'_>) -> Result<(), String> {
    let DiscordRevokeRequest {
        http,
        config,
        token,
        token_type_hint,
    } = args;
    let params = [("token", token), ("token_type_hint", token_type_hint)];
    let response = http
        .post(config.discord_token_revoke_url.clone())
        .basic_auth(
            &config.discord_client_id,
            Some(&config.discord_client_secret),
        )
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("discord revoke request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Discord token revoke rejected: {status}");
        return Err(format!("discord_revoke_status_{status}"));
    }
    Ok(())
}

/// Inputs for a Discord token revocation.
pub(crate) struct DiscordRevokeRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) token: &'a str,
    pub(crate) token_type_hint: &'a str,
}

/// Fetch the Discord account profile for a bearer access token.
pub(crate) async fn fetch_user(args: DiscordUserRequest<'_>) -> Result<DiscordUser, String> {
    let DiscordUserRequest {
        http,
        config,
        access_token,
    } = args;
    let response = http
        .get(config.discord_userinfo_url.clone())
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
    pub(crate) config: &'a Config,
    pub(crate) access_token: &'a str,
}

fn normalize_scopes(requested: &[String]) -> Result<Vec<String>, String> {
    let mut scopes: Vec<String> = requested
        .iter()
        .flat_map(|scope| scope.split_whitespace())
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    if !scopes.iter().any(|s| s == "identify") {
        scopes.push("identify".to_string());
    }
    scopes.sort();
    scopes.dedup();
    for scope in &scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(format!("unsupported Discord scope: {scope}"));
        }
    }
    Ok(scopes)
}

fn split_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use url::Url;

    fn test_config() -> Config {
        Config {
            database_url: "postgres://localhost/sfae_test".to_string(),
            internal_auth_secret: "internal".to_string(),
            token_encryption_key: "token-key".to_string(),
            discord_client_id: "client-id".to_string(),
            discord_client_secret: "client-secret".to_string(),
            discord_authorize_url: Url::parse("https://discord.com/oauth2/authorize").unwrap(),
            discord_token_url: Url::parse("https://discord.com/api/oauth2/token").unwrap(),
            discord_token_revoke_url: Url::parse("https://discord.com/api/oauth2/token/revoke")
                .unwrap(),
            discord_userinfo_url: Url::parse("https://discord.com/api/v10/users/@me").unwrap(),
            base_url: Url::parse("https://oauth.sfae.io").unwrap(),
            allowed_return_origins: HashSet::new(),
            port: 3100,
        }
    }

    #[test]
    fn default_scope_is_identify() {
        assert_eq!(normalize_scopes(&[]).unwrap(), vec!["identify"]);
    }

    #[test]
    fn scopes_are_sorted_deduped_and_include_identify() {
        let scopes = normalize_scopes(&[
            "guilds".to_string(),
            "email".to_string(),
            "guilds".to_string(),
        ])
        .unwrap();
        assert_eq!(scopes, vec!["email", "guilds", "identify"]);
    }

    #[test]
    fn unsupported_scope_is_rejected() {
        let err = normalize_scopes(&["messages.read".to_string()]).unwrap_err();
        assert_eq!(err, "unsupported Discord scope: messages.read");
    }

    #[test]
    fn scope_entries_are_split_and_empty_entries_ignored() {
        let scopes = normalize_scopes(&["guilds email".to_string(), " ".to_string()]).unwrap();
        assert_eq!(scopes, vec!["email", "guilds", "identify"]);
    }

    #[test]
    fn authorization_url_contains_only_valid_provider_parameters() {
        let session = build_authorization(DiscordAuthorize {
            config: &test_config(),
            state: "state-value",
            requested_scopes: &["email".to_string()],
        })
        .unwrap();
        let url = Url::parse(&session.authorization_url).unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            "https://discord.com/oauth2/authorize"
        );
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "client-id");
        assert_eq!(
            pairs["redirect_uri"],
            "https://oauth.sfae.io/v1/callback/discord"
        );
        assert_eq!(pairs["scope"], "email identify");
        assert_eq!(pairs["state"], "state-value");
        assert_eq!(pairs["prompt"], "consent");
        let keys: std::collections::BTreeSet<_> = pairs.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "client_id",
                "prompt",
                "redirect_uri",
                "response_type",
                "scope",
                "state"
            ])
        );
    }

    #[test]
    fn token_scopes_prefer_provider_response() {
        let token = DiscordToken {
            access_token: "access".to_string(),
            refresh_token: None,
            token_type: Some("Bearer".to_string()),
            scope: Some("guilds identify guilds".to_string()),
            expires_in: None,
        };
        assert_eq!(
            token.scopes(&["email".to_string()]),
            vec!["guilds", "identify"]
        );
    }
}
