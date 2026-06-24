//! Google OAuth provider descriptor, token exchange, revocation, and UserInfo lookup.

use crate::config::Config;
use crate::provider::{ProviderToken, ProviderUser};
use chrono::{Duration, Utc};
use serde::Deserialize;

/// Google OAuth session inputs.
pub(crate) struct GoogleSession {
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_url: String,
}

/// Google OAuth token response fields used by SFAE.
#[derive(Deserialize)]
pub(crate) struct GoogleToken {
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

impl GoogleToken {
    /// Convert Google token material into the provider-neutral broker shape.
    pub(crate) fn into_provider_token(self, requested: &[String]) -> ProviderToken {
        let scopes = self
            .scope
            .as_deref()
            .map(split_scopes)
            .unwrap_or_else(|| normalize_scopes(requested));
        self.into_provider_token_with_scopes(scopes)
    }

    /// Convert Google refresh token material without inventing scopes when Google omits them.
    pub(crate) fn into_refreshed_provider_token(self) -> ProviderToken {
        let scopes = self.scope.as_deref().map(split_scopes).unwrap_or_default();
        self.into_provider_token_with_scopes(scopes)
    }

    fn into_provider_token_with_scopes(self, scopes: Vec<String>) -> ProviderToken {
        let expires_at = self
            .expires_in
            .map(|seconds| Utc::now() + Duration::seconds(seconds));
        ProviderToken {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            token_type: self.token_type,
            scopes,
            expires_at,
        }
    }
}

/// Google OpenID Connect UserInfo fields used for account linking.
#[derive(Deserialize)]
pub(crate) struct GoogleUser {
    pub(crate) sub: String,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) email: Option<String>,
}

impl GoogleUser {
    /// Prefer Google profile name and fall back to email.
    pub(crate) fn display_name(&self) -> Option<String> {
        self.name.clone().or_else(|| self.email.clone())
    }

    /// Convert Google UserInfo into the provider-neutral broker shape.
    pub(crate) fn into_provider_user(self) -> ProviderUser {
        let display_name = self.display_name();
        ProviderUser {
            subject: self.sub,
            display_name,
            email: self.email,
        }
    }
}

/// Build a Google authorization URL for the browser.
pub(crate) fn build_authorization(args: GoogleAuthorize<'_>) -> Result<GoogleSession, String> {
    let GoogleAuthorize {
        config,
        state,
        requested_scopes,
    } = args;
    let scopes = normalize_scopes(requested_scopes);
    let redirect_uri = config.generic_redirect_uri();
    let mut url = config.google_authorize_url.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.google_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", state)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("include_granted_scopes", "true");
    Ok(GoogleSession {
        scopes,
        authorization_url: url.to_string(),
    })
}

/// Inputs for building the Google authorize URL.
pub(crate) struct GoogleAuthorize<'a> {
    pub(crate) config: &'a Config,
    pub(crate) state: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Exchange an authorization code for Google tokens.
pub(crate) async fn exchange_code(args: GoogleTokenRequest<'_>) -> Result<GoogleToken, String> {
    let GoogleTokenRequest { http, config, code } = args;
    let redirect_uri = config.generic_redirect_uri();
    let params = [
        ("code", code),
        ("client_id", &config.google_client_id),
        ("client_secret", &config.google_client_secret),
        ("redirect_uri", &redirect_uri),
        ("grant_type", "authorization_code"),
    ];
    let response = http
        .post(config.google_token_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider token request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Google token exchange rejected: {status}");
        return Err(format!("provider_token_status_{status}"));
    }
    response
        .json::<GoogleToken>()
        .await
        .map_err(|e| format!("provider token response parse failed: {e}"))
}

/// Inputs for a Google token exchange.
pub(crate) struct GoogleTokenRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) code: &'a str,
}

/// Refresh a Google access token with a refresh token.
pub(crate) async fn refresh_token(args: GoogleRefreshRequest<'_>) -> Result<GoogleToken, String> {
    let GoogleRefreshRequest {
        http,
        config,
        refresh_token,
    } = args;
    let params = [
        ("client_id", config.google_client_id.as_str()),
        ("client_secret", config.google_client_secret.as_str()),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];
    let response = http
        .post(config.google_token_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider refresh request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Google token refresh rejected: {status}");
        return Err(format!("provider_refresh_status_{status}"));
    }
    response
        .json::<GoogleToken>()
        .await
        .map_err(|e| format!("provider refresh response parse failed: {e}"))
}

/// Inputs for a Google token refresh.
pub(crate) struct GoogleRefreshRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) refresh_token: &'a str,
}

/// Revoke a Google access or refresh token.
pub(crate) async fn revoke_token(args: GoogleRevokeRequest<'_>) -> Result<(), String> {
    let GoogleRevokeRequest {
        http,
        config,
        token,
    } = args;
    let params = [("token", token)];
    let response = http
        .post(config.google_revoke_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider revoke request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Google token revoke rejected: {status}");
        return Err(format!("provider_revoke_status_{status}"));
    }
    Ok(())
}

/// Inputs for a Google token revocation.
pub(crate) struct GoogleRevokeRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) token: &'a str,
}

/// Fetch Google UserInfo for a bearer access token.
pub(crate) async fn fetch_user(args: GoogleUserRequest<'_>) -> Result<GoogleUser, String> {
    let GoogleUserRequest {
        http,
        config,
        access_token,
    } = args;
    let response = http
        .get(config.google_userinfo_url.clone())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("provider identity request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(format!("provider_identity_status_{status}"));
    }
    response
        .json::<GoogleUser>()
        .await
        .map_err(|e| format!("provider identity response parse failed: {e}"))
}

/// Inputs for loading Google user identity.
pub(crate) struct GoogleUserRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) access_token: &'a str,
}

fn normalize_scopes(requested: &[String]) -> Vec<String> {
    let mut scopes: Vec<String> = requested
        .iter()
        .flat_map(|scope| scope.split_whitespace())
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    for required in ["openid", "email", "profile"] {
        if !scopes.iter().any(|scope| scope == required) {
            scopes.push(required.to_string());
        }
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn split_scopes(raw: &str) -> Vec<String> {
    let mut scopes: Vec<String> = raw
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use url::Url;

    fn test_config() -> Config {
        Config {
            database_url: "postgres://localhost/sfae_test".to_string(),
            internal_auth_secret: "internal".to_string(),
            token_encryption_key: "token-key".to_string(),
            discord_client_id: "discord-client-id".to_string(),
            discord_client_secret: "discord-client-secret".to_string(),
            discord_authorize_url: Url::parse("https://discord.com/oauth2/authorize").unwrap(),
            discord_token_url: Url::parse("https://discord.com/api/oauth2/token").unwrap(),
            discord_token_revoke_url: Url::parse("https://discord.com/api/oauth2/token/revoke")
                .unwrap(),
            discord_userinfo_url: Url::parse("https://discord.com/api/v10/users/@me").unwrap(),
            google_client_id: "google-client-id".to_string(),
            google_client_secret: "google-client-secret".to_string(),
            google_authorize_url: Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .unwrap(),
            google_token_url: Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            google_revoke_url: Url::parse("https://oauth2.googleapis.com/revoke").unwrap(),
            google_userinfo_url: Url::parse("https://openidconnect.googleapis.com/v1/userinfo")
                .unwrap(),
            base_url: Url::parse("https://oauth.sfae.io").unwrap(),
            allowed_return_origins: HashSet::new(),
            port: 3100,
        }
    }

    #[test]
    fn scopes_are_sorted_deduped_split_and_include_linking_scopes() {
        let scopes = normalize_scopes(&[
            "https://www.googleapis.com/auth/drive.metadata.readonly email".to_string(),
            "profile".to_string(),
            " ".to_string(),
        ]);

        assert_eq!(
            scopes,
            vec![
                "email",
                "https://www.googleapis.com/auth/drive.metadata.readonly",
                "openid",
                "profile"
            ]
        );
    }

    #[test]
    fn authorization_url_contains_only_valid_google_parameters() {
        let session = build_authorization(GoogleAuthorize {
            config: &test_config(),
            state: "state-value",
            requested_scopes: &[
                "https://www.googleapis.com/auth/drive.metadata.readonly".to_string()
            ],
        })
        .unwrap();
        let url = Url::parse(&session.authorization_url).unwrap();
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut keys: Vec<_> = pairs.keys().map(String::as_str).collect();
        keys.sort();

        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "google-client-id");
        assert_eq!(
            pairs["redirect_uri"],
            "https://oauth.sfae.io/oauth/callback"
        );
        assert_eq!(
            pairs["scope"],
            "email https://www.googleapis.com/auth/drive.metadata.readonly openid profile"
        );
        assert_eq!(pairs["state"], "state-value");
        assert_eq!(pairs["access_type"], "offline");
        assert_eq!(pairs["prompt"], "consent");
        assert_eq!(pairs["include_granted_scopes"], "true");
        assert_eq!(
            keys,
            vec![
                "access_type",
                "client_id",
                "include_granted_scopes",
                "prompt",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
            ]
        );
    }

    #[test]
    fn token_response_uses_returned_scopes_and_expiry() {
        let token = GoogleToken {
            access_token: "access".to_string(),
            refresh_token: Some("refresh".to_string()),
            token_type: Some("Bearer".to_string()),
            scope: Some("profile email profile".to_string()),
            expires_in: Some(60),
        }
        .into_provider_token(&["https://www.googleapis.com/auth/gmail.readonly".to_string()]);

        assert_eq!(token.access_token, "access");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh"));
        assert_eq!(token.token_type.as_deref(), Some("Bearer"));
        assert_eq!(token.scopes, vec!["email", "profile"]);
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn token_response_falls_back_to_normalized_requested_scopes() {
        let token = GoogleToken {
            access_token: "access".to_string(),
            refresh_token: None,
            token_type: None,
            scope: None,
            expires_in: None,
        }
        .into_provider_token(&["https://www.googleapis.com/auth/gmail.readonly".to_string()]);

        assert_eq!(
            token.scopes,
            vec![
                "email",
                "https://www.googleapis.com/auth/gmail.readonly",
                "openid",
                "profile"
            ]
        );
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn refresh_token_response_without_scope_does_not_synthesize_linking_scopes() {
        let token = GoogleToken {
            access_token: "access".to_string(),
            refresh_token: None,
            token_type: Some("Bearer".to_string()),
            scope: None,
            expires_in: Some(60),
        }
        .into_refreshed_provider_token();

        assert!(token.scopes.is_empty());
        assert_eq!(token.access_token, "access");
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn userinfo_display_name_falls_back_to_email() {
        let named = GoogleUser {
            sub: "google-sub".to_string(),
            name: Some("Google User".to_string()),
            email: Some("user@example.com".to_string()),
        };
        assert_eq!(named.display_name().as_deref(), Some("Google User"));

        let email_only = GoogleUser {
            sub: "google-sub".to_string(),
            name: None,
            email: Some("user@example.com".to_string()),
        };
        assert_eq!(
            email_only.display_name().as_deref(),
            Some("user@example.com")
        );
    }
}
