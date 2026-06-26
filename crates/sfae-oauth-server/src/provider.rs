//! Provider-neutral OAuth dispatch for the hosted broker.

use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::{discord, dropbox, github, google};

const DISCORD_DOMAINS: &[&str] = &["discord.com"];
const GOOGLE_DOMAINS: &[&str] = &["googleapis.com"];
const GITHUB_DOMAINS: &[&str] = &["github.com"];
const DROPBOX_DOMAINS: &[&str] = &["dropboxapi.com"];
const PROVIDERS: &[ProviderMetadata] = &[
    ProviderMetadata {
        provider: "discord",
        domains: DISCORD_DOMAINS,
    },
    ProviderMetadata {
        provider: "google",
        domains: GOOGLE_DOMAINS,
    },
    ProviderMetadata {
        provider: "github",
        domains: GITHUB_DOMAINS,
    },
    ProviderMetadata {
        provider: "dropbox",
        domains: DROPBOX_DOMAINS,
    },
];

/// Public metadata for one hosted OAuth provider.
pub(crate) struct ProviderMetadata {
    pub(crate) provider: &'static str,
    pub(crate) domains: &'static [&'static str],
}

/// Browser authorization material produced by a provider.
pub(crate) struct ProviderAuthorization {
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_url: String,
}

/// Provider access-token material normalized for broker storage.
pub(crate) struct ProviderToken {
    pub(crate) access_token: String,
    pub(crate) refresh_token: Option<String>,
    pub(crate) token_type: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
}

/// Provider account identity normalized for SFAE account linking.
pub(crate) struct ProviderUser {
    pub(crate) subject: String,
    pub(crate) display_name: Option<String>,
    pub(crate) email: Option<String>,
}

/// Inputs for building a provider authorization URL.
pub(crate) struct BuildAuthorization<'a> {
    pub(crate) provider: &'a str,
    pub(crate) config: &'a Config,
    pub(crate) state: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Inputs for exchanging an authorization code.
pub(crate) struct ExchangeCode<'a> {
    pub(crate) provider: &'a str,
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) code: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Inputs for refreshing an access token.
pub(crate) struct RefreshToken<'a> {
    pub(crate) provider: &'a str,
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) refresh_token: &'a str,
}

/// Inputs for revoking provider token material.
pub(crate) struct RevokeToken<'a> {
    pub(crate) provider: &'a str,
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) access_token: Option<&'a str>,
    pub(crate) refresh_token: Option<&'a str>,
}

/// Inputs for fetching provider account identity.
pub(crate) struct FetchUser<'a> {
    pub(crate) provider: &'a str,
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) access_token: &'a str,
}

#[derive(Clone, Copy)]
enum Provider {
    Discord,
    Google,
    GitHub,
    Dropbox,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Dropbox => "dropbox",
        }
    }

    fn default_domain(self) -> &'static str {
        match self {
            Self::Discord => "discord.com",
            Self::Google => "googleapis.com",
            Self::GitHub => "github.com",
            Self::Dropbox => "dropboxapi.com",
        }
    }
}

/// Return the stable provider registry exposed to clients.
pub(crate) fn provider_metadata() -> &'static [ProviderMetadata] {
    PROVIDERS
}

/// Return the canonical provider name when supported.
pub(crate) fn canonical_provider_name(provider: &str) -> Option<&'static str> {
    provider_by_name(provider).map(Provider::name)
}

/// Return the default credential domain for a supported provider.
pub(crate) fn default_domain(provider: &str) -> Option<&'static str> {
    provider_by_name(provider).map(Provider::default_domain)
}

/// Build a provider authorization URL.
pub(crate) fn build_authorization(
    args: BuildAuthorization<'_>,
) -> Result<ProviderAuthorization, String> {
    let BuildAuthorization {
        provider,
        config,
        state,
        requested_scopes,
    } = args;
    match require_provider(provider)? {
        Provider::Discord => {
            let session = discord::build_authorization(discord::DiscordAuthorize {
                config,
                state,
                requested_scopes,
            })?;
            Ok(ProviderAuthorization {
                scopes: session.scopes,
                authorization_url: session.authorization_url,
            })
        }
        Provider::Google => {
            let session = google::build_authorization(google::GoogleAuthorize {
                config,
                state,
                requested_scopes,
            })?;
            Ok(ProviderAuthorization {
                scopes: session.scopes,
                authorization_url: session.authorization_url,
            })
        }
        Provider::GitHub => {
            let session = github::build_authorization(github::GitHubAuthorize {
                config,
                state,
                requested_scopes,
            })?;
            Ok(ProviderAuthorization {
                scopes: session.scopes,
                authorization_url: session.authorization_url,
            })
        }
        Provider::Dropbox => {
            let session = dropbox::build_authorization(dropbox::DropboxAuthorize {
                config,
                state,
                requested_scopes,
            })?;
            Ok(ProviderAuthorization {
                scopes: session.scopes,
                authorization_url: session.authorization_url,
            })
        }
    }
}

/// Exchange an authorization code for normalized provider token material.
pub(crate) async fn exchange_code(args: ExchangeCode<'_>) -> Result<ProviderToken, String> {
    let ExchangeCode {
        provider,
        http,
        config,
        code,
        requested_scopes,
    } = args;
    match require_provider(provider)? {
        Provider::Discord => {
            let token =
                discord::exchange_code(discord::DiscordTokenRequest { http, config, code }).await?;
            Ok(token.into_provider_token(requested_scopes))
        }
        Provider::Google => {
            let token =
                google::exchange_code(google::GoogleTokenRequest { http, config, code }).await?;
            Ok(token.into_provider_token(requested_scopes))
        }
        Provider::GitHub => {
            let token =
                github::exchange_code(github::GitHubTokenRequest { http, config, code }).await?;
            Ok(token.into_provider_token(requested_scopes))
        }
        Provider::Dropbox => {
            let token =
                dropbox::exchange_code(dropbox::DropboxTokenRequest { http, config, code }).await?;
            Ok(token.into_provider_token(requested_scopes))
        }
    }
}

/// Refresh an access token through the provider.
pub(crate) async fn refresh_token(args: RefreshToken<'_>) -> Result<ProviderToken, String> {
    let RefreshToken {
        provider,
        http,
        config,
        refresh_token,
    } = args;
    match require_provider(provider)? {
        Provider::Discord => {
            let token = discord::refresh_token(discord::DiscordRefreshRequest {
                http,
                config,
                refresh_token,
            })
            .await?;
            Ok(token.into_provider_token(&[]))
        }
        Provider::Google => {
            let token = google::refresh_token(google::GoogleRefreshRequest {
                http,
                config,
                refresh_token,
            })
            .await?;
            Ok(token.into_refreshed_provider_token())
        }
        Provider::GitHub => Err("provider_refresh_unsupported".to_string()),
        Provider::Dropbox => {
            let token = dropbox::refresh_token(dropbox::DropboxRefreshRequest {
                http,
                config,
                refresh_token,
            })
            .await?;
            Ok(token.into_refreshed_provider_token())
        }
    }
}

/// Revoke provider token material.
pub(crate) async fn revoke_token(args: RevokeToken<'_>) -> Result<(), String> {
    let RevokeToken {
        provider,
        http,
        config,
        access_token,
        refresh_token,
    } = args;
    match require_provider(provider)? {
        Provider::Discord => {
            let (token, token_type_hint) = refresh_token
                .filter(|token| !token.is_empty())
                .map(|token| (token, "refresh_token"))
                .or_else(|| {
                    access_token
                        .filter(|token| !token.is_empty())
                        .map(|token| (token, "access_token"))
                })
                .ok_or_else(|| "provider_revoke_token_required".to_string())?;
            discord::revoke_token(discord::DiscordRevokeRequest {
                http,
                config,
                token,
                token_type_hint,
            })
            .await
        }
        Provider::Google => {
            let token = refresh_token
                .filter(|token| !token.is_empty())
                .or_else(|| access_token.filter(|token| !token.is_empty()))
                .ok_or_else(|| "provider_revoke_token_required".to_string())?;
            google::revoke_token(google::GoogleRevokeRequest {
                http,
                config,
                token,
            })
            .await
        }
        Provider::GitHub => {
            let token = access_token
                .filter(|token| !token.is_empty())
                .ok_or_else(|| "provider_revoke_access_token_required".to_string())?;
            github::revoke_token(github::GitHubRevokeRequest {
                http,
                config,
                token,
            })
            .await
        }
        Provider::Dropbox => {
            dropbox::revoke_token(dropbox::DropboxRevokeRequest {
                http,
                config,
                access_token,
                refresh_token,
            })
            .await
        }
    }
}

/// Fetch normalized provider user identity.
pub(crate) async fn fetch_user(args: FetchUser<'_>) -> Result<ProviderUser, String> {
    let FetchUser {
        provider,
        http,
        config,
        access_token,
    } = args;
    match require_provider(provider)? {
        Provider::Discord => {
            let user = discord::fetch_user(discord::DiscordUserRequest {
                http,
                config,
                access_token,
            })
            .await?;
            Ok(user.into_provider_user())
        }
        Provider::Google => {
            let user = google::fetch_user(google::GoogleUserRequest {
                http,
                config,
                access_token,
            })
            .await?;
            Ok(user.into_provider_user())
        }
        Provider::GitHub => {
            let user = github::fetch_user(github::GitHubUserRequest {
                http,
                config,
                access_token,
            })
            .await?;
            Ok(user.into_provider_user())
        }
        Provider::Dropbox => {
            let user = dropbox::fetch_user(dropbox::DropboxUserRequest {
                http,
                config,
                access_token,
            })
            .await?;
            Ok(user.into_provider_user())
        }
    }
}

fn require_provider(provider: &str) -> Result<Provider, String> {
    provider_by_name(provider).ok_or_else(|| format!("unsupported OAuth provider \"{provider}\""))
}

fn provider_by_name(provider: &str) -> Option<Provider> {
    match provider {
        "discord" => Some(Provider::Discord),
        "google" => Some(Provider::Google),
        "github" => Some(Provider::GitHub),
        "dropbox" => Some(Provider::Dropbox),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_includes_supported_providers() {
        let registry: Vec<_> = provider_metadata()
            .iter()
            .map(|provider| (provider.provider, provider.domains.to_vec()))
            .collect();

        assert_eq!(
            registry,
            vec![
                ("discord", vec!["discord.com"]),
                ("google", vec!["googleapis.com"]),
                ("github", vec!["github.com"]),
                ("dropbox", vec!["dropboxapi.com"])
            ]
        );
    }

    #[test]
    fn default_domains_are_provider_specific() {
        assert_eq!(default_domain("discord"), Some("discord.com"));
        assert_eq!(default_domain("google"), Some("googleapis.com"));
        assert_eq!(default_domain("github"), Some("github.com"));
        assert_eq!(default_domain("dropbox"), Some("dropboxapi.com"));
        assert_eq!(default_domain("unknown"), None);
    }
}
