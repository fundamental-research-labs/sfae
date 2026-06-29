//! Dropbox OAuth provider descriptor, token exchange, revocation, and account lookup.

use crate::config::Config;
use crate::provider::{ProviderToken, ProviderUser};
use chrono::{Duration, Utc};
use serde::Deserialize;

/// Dropbox OAuth session inputs.
pub(crate) struct DropboxSession {
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_url: String,
}

/// Dropbox OAuth token response fields used by SFAE.
#[derive(Deserialize)]
pub(crate) struct DropboxToken {
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

impl DropboxToken {
    /// Convert Dropbox token material into the provider-neutral broker shape.
    pub(crate) fn into_provider_token(self, requested: &[String]) -> ProviderToken {
        let scopes = self
            .scope
            .as_deref()
            .map(split_scopes)
            .unwrap_or_else(|| normalize_scopes(requested));
        self.into_provider_token_with_scopes(scopes)
    }

    /// Convert a Dropbox refresh response without inventing omitted fields.
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

/// Dropbox `/2/users/get_current_account` fields used for account linking.
#[derive(Deserialize)]
pub(crate) struct DropboxUser {
    pub(crate) account_id: String,
    #[serde(default)]
    pub(crate) name: Option<DropboxName>,
    #[serde(default)]
    pub(crate) email: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DropboxName {
    #[serde(default)]
    pub(crate) display_name: Option<String>,
}

impl DropboxUser {
    /// Return Dropbox's display name when the account response includes it.
    pub(crate) fn display_name(&self) -> Option<String> {
        self.name
            .as_ref()
            .and_then(|name| name.display_name.clone())
    }

    /// Convert Dropbox account data into the provider-neutral broker shape.
    pub(crate) fn into_provider_user(self) -> ProviderUser {
        let display_name = self.display_name();
        ProviderUser {
            subject: self.account_id,
            display_name,
            email: self.email,
        }
    }
}

/// Build a Dropbox authorization URL for the browser.
pub(crate) fn build_authorization(args: DropboxAuthorize<'_>) -> Result<DropboxSession, String> {
    let DropboxAuthorize {
        config,
        state,
        requested_scopes,
    } = args;
    let scopes = normalize_scopes(requested_scopes);
    let redirect_uri = config.generic_redirect_uri();
    let mut url = config.dropbox_authorize_url.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.dropbox_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", state)
        .append_pair("token_access_type", "offline");
    Ok(DropboxSession {
        scopes,
        authorization_url: url.to_string(),
    })
}

/// Inputs for building the Dropbox authorize URL.
pub(crate) struct DropboxAuthorize<'a> {
    pub(crate) config: &'a Config,
    pub(crate) state: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Exchange an authorization code for Dropbox tokens.
pub(crate) async fn exchange_code(args: DropboxTokenRequest<'_>) -> Result<DropboxToken, String> {
    let DropboxTokenRequest { http, config, code } = args;
    let redirect_uri = config.generic_redirect_uri();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", &config.dropbox_client_id),
        ("client_secret", &config.dropbox_client_secret),
        ("redirect_uri", &redirect_uri),
    ];
    let response = http
        .post(config.dropbox_token_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider token request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Dropbox token exchange rejected: {status}");
        return Err(format!("provider_token_status_{status}"));
    }
    response
        .json::<DropboxToken>()
        .await
        .map_err(|e| format!("provider token response parse failed: {e}"))
}

/// Inputs for a Dropbox token exchange.
pub(crate) struct DropboxTokenRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) code: &'a str,
}

/// Refresh a Dropbox access token with a refresh token.
pub(crate) async fn refresh_token(args: DropboxRefreshRequest<'_>) -> Result<DropboxToken, String> {
    let DropboxRefreshRequest {
        http,
        config,
        refresh_token,
    } = args;
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", config.dropbox_client_id.as_str()),
        ("client_secret", config.dropbox_client_secret.as_str()),
    ];
    let response = http
        .post(config.dropbox_token_url.clone())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider refresh request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Dropbox token refresh rejected: {status}");
        return Err(format!("provider_refresh_status_{status}"));
    }
    response
        .json::<DropboxToken>()
        .await
        .map_err(|e| format!("provider refresh response parse failed: {e}"))
}

/// Inputs for a Dropbox token refresh.
pub(crate) struct DropboxRefreshRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) refresh_token: &'a str,
}

/// Revoke Dropbox token material. Dropbox revocation is bearer-token based.
pub(crate) async fn revoke_token(args: DropboxRevokeRequest<'_>) -> Result<(), String> {
    let DropboxRevokeRequest {
        http,
        config,
        access_token,
        refresh_token: refresh_token_material,
    } = args;

    if let Some(access_token) = access_token.filter(|token| !token.is_empty()) {
        let result = revoke_access_token(DropboxAccessRevoke {
            http,
            config,
            access_token,
        })
        .await;
        if result.is_ok() || refresh_token_material.is_none() {
            return result;
        }
    }

    let Some(refresh_token_value) = refresh_token_material.filter(|token| !token.is_empty()) else {
        return Err("provider_revoke_access_token_required".to_string());
    };
    let refreshed = refresh_token(DropboxRefreshRequest {
        http,
        config,
        refresh_token: refresh_token_value,
    })
    .await?;
    revoke_access_token(DropboxAccessRevoke {
        http,
        config,
        access_token: &refreshed.access_token,
    })
    .await
}

/// Inputs for Dropbox token revocation.
pub(crate) struct DropboxRevokeRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) access_token: Option<&'a str>,
    pub(crate) refresh_token: Option<&'a str>,
}

struct DropboxAccessRevoke<'a> {
    http: &'a reqwest::Client,
    config: &'a Config,
    access_token: &'a str,
}

async fn revoke_access_token(args: DropboxAccessRevoke<'_>) -> Result<(), String> {
    let DropboxAccessRevoke {
        http,
        config,
        access_token,
    } = args;
    let response = http
        .post(config.dropbox_revoke_url.clone())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("Dropbox token revoke request failed: {e}");
            "provider_revoke_request_failed".to_string()
        })?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("Dropbox token revoke rejected: {status}");
        return Err(format!("provider_revoke_status_{}", status.as_u16()));
    }
    Ok(())
}

/// Fetch the Dropbox account profile for a bearer access token.
pub(crate) async fn fetch_user(args: DropboxUserRequest<'_>) -> Result<DropboxUser, String> {
    let DropboxUserRequest {
        http,
        config,
        access_token,
    } = args;
    let response = http
        .post(config.dropbox_current_account_url.clone())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("provider identity request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(format!("provider_identity_status_{status}"));
    }
    response
        .json::<DropboxUser>()
        .await
        .map_err(|e| format!("provider identity response parse failed: {e}"))
}

/// Inputs for loading Dropbox user identity.
pub(crate) struct DropboxUserRequest<'a> {
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
    if !scopes.iter().any(|scope| scope == "account_info.read") {
        scopes.push("account_info.read".to_string());
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

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
            github_client_id: "github-client-id".to_string(),
            github_client_secret: "github-client-secret".to_string(),
            github_authorize_url: Url::parse("https://github.com/login/oauth/authorize").unwrap(),
            github_token_url: Url::parse("https://github.com/login/oauth/access_token").unwrap(),
            github_api_url: Url::parse("https://api.github.com").unwrap(),
            github_userinfo_url: Url::parse("https://api.github.com/user").unwrap(),
            dropbox_client_id: "dropbox-client-id".to_string(),
            dropbox_client_secret: "dropbox-client-secret".to_string(),
            dropbox_authorize_url: Url::parse("https://www.dropbox.com/oauth2/authorize").unwrap(),
            dropbox_token_url: Url::parse("https://api.dropbox.com/oauth2/token").unwrap(),
            dropbox_revoke_url: Url::parse("https://api.dropboxapi.com/2/auth/token/revoke")
                .unwrap(),
            dropbox_current_account_url: Url::parse(
                "https://api.dropboxapi.com/2/users/get_current_account",
            )
            .unwrap(),
            base_url: Url::parse("https://oauth.sfae.io").unwrap(),
            allowed_return_origins: HashSet::new(),
            port: 3100,
        }
    }

    #[test]
    fn scopes_are_sorted_deduped_split_and_include_account_info() {
        let scopes = normalize_scopes(&[
            "files.metadata.read files.content.read".to_string(),
            "files.metadata.read".to_string(),
            " ".to_string(),
        ]);

        assert_eq!(
            scopes,
            vec![
                "account_info.read",
                "files.content.read",
                "files.metadata.read"
            ]
        );
    }

    #[test]
    fn authorization_url_contains_only_valid_dropbox_parameters() {
        let session = build_authorization(DropboxAuthorize {
            config: &test_config(),
            state: "state-value",
            requested_scopes: &["files.metadata.read".to_string()],
        })
        .unwrap();
        let url = Url::parse(&session.authorization_url).unwrap();
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut keys: Vec<_> = pairs.keys().map(String::as_str).collect();
        keys.sort();

        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            "https://www.dropbox.com/oauth2/authorize"
        );
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "dropbox-client-id");
        assert_eq!(
            pairs["redirect_uri"],
            "https://oauth.sfae.io/oauth/callback"
        );
        assert_eq!(pairs["scope"], "account_info.read files.metadata.read");
        assert_eq!(pairs["state"], "state-value");
        assert_eq!(pairs["token_access_type"], "offline");
        assert_eq!(
            keys,
            vec![
                "client_id",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
                "token_access_type"
            ]
        );
    }

    #[test]
    fn token_response_uses_returned_scopes_and_expiry() {
        let token = DropboxToken {
            access_token: "access".to_string(),
            refresh_token: Some("refresh".to_string()),
            token_type: Some("bearer".to_string()),
            scope: Some("files.metadata.read account_info.read files.metadata.read".to_string()),
            expires_in: Some(60),
        }
        .into_provider_token(&["files.content.read".to_string()]);

        assert_eq!(token.access_token, "access");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh"));
        assert_eq!(token.token_type.as_deref(), Some("bearer"));
        assert_eq!(
            token.scopes,
            vec!["account_info.read", "files.metadata.read"]
        );
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn token_response_falls_back_to_normalized_requested_scopes() {
        let token = DropboxToken {
            access_token: "access".to_string(),
            refresh_token: None,
            token_type: None,
            scope: None,
            expires_in: None,
        }
        .into_provider_token(&["files.metadata.read".to_string()]);

        assert_eq!(
            token.scopes,
            vec!["account_info.read", "files.metadata.read"]
        );
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn refresh_response_without_scope_does_not_synthesize_linking_scope() {
        let token = DropboxToken {
            access_token: "access".to_string(),
            refresh_token: None,
            token_type: Some("bearer".to_string()),
            scope: None,
            expires_in: Some(60),
        }
        .into_refreshed_provider_token();

        assert_eq!(token.access_token, "access");
        assert!(token.refresh_token.is_none());
        assert!(token.scopes.is_empty());
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn current_account_maps_subject_display_name_and_email() {
        let user = DropboxUser {
            account_id: "dbid:account".to_string(),
            name: Some(DropboxName {
                display_name: Some("Dropbox User".to_string()),
            }),
            email: Some("user@example.com".to_string()),
        }
        .into_provider_user();

        assert_eq!(user.subject, "dbid:account");
        assert_eq!(user.display_name.as_deref(), Some("Dropbox User"));
        assert_eq!(user.email.as_deref(), Some("user@example.com"));
    }

    #[tokio::test]
    async fn token_exchange_refresh_identity_and_bearer_revoke_use_dropbox_semantics() {
        let server = MockHttpServer::start(vec![
            MockResponse::json(
                r#"{"access_token":"access","refresh_token":"refresh","token_type":"bearer","scope":"account_info.read files.metadata.read","expires_in":3600}"#,
            ),
            MockResponse::json(
                r#"{"access_token":"refreshed","token_type":"bearer","expires_in":1800}"#,
            ),
            MockResponse::json(
                r#"{"account_id":"dbid:account","name":{"display_name":"Dropbox User"},"email":"user@example.com"}"#,
            ),
            MockResponse::json(r#"{}"#),
        ]);
        let mut config = test_config();
        config.dropbox_token_url = Url::parse(&format!("{}/token", server.base_url)).unwrap();
        config.dropbox_current_account_url =
            Url::parse(&format!("{}/current_account", server.base_url)).unwrap();
        config.dropbox_revoke_url = Url::parse(&format!("{}/revoke", server.base_url)).unwrap();
        let http = reqwest::Client::new();

        let token = exchange_code(DropboxTokenRequest {
            http: &http,
            config: &config,
            code: "code-value",
        })
        .await
        .unwrap()
        .into_provider_token(&["files.metadata.read".to_string()]);
        assert_eq!(token.access_token, "access");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh"));

        let refreshed = refresh_token(DropboxRefreshRequest {
            http: &http,
            config: &config,
            refresh_token: "refresh",
        })
        .await
        .unwrap()
        .into_refreshed_provider_token();
        assert_eq!(refreshed.access_token, "refreshed");
        assert!(refreshed.refresh_token.is_none());

        let user = fetch_user(DropboxUserRequest {
            http: &http,
            config: &config,
            access_token: "access",
        })
        .await
        .unwrap()
        .into_provider_user();
        assert_eq!(user.subject, "dbid:account");
        assert_eq!(user.display_name.as_deref(), Some("Dropbox User"));
        assert_eq!(user.email.as_deref(), Some("user@example.com"));

        revoke_token(DropboxRevokeRequest {
            http: &http,
            config: &config,
            access_token: Some("access"),
            refresh_token: Some("refresh"),
        })
        .await
        .unwrap();

        let requests = server.finish();
        let exchange_body = parse_urlencoded(&requests[0].body);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].target, "/token");
        assert_eq!(exchange_body["grant_type"], "authorization_code");
        assert_eq!(exchange_body["code"], "code-value");
        assert_eq!(exchange_body["client_id"], "dropbox-client-id");
        assert_eq!(exchange_body["client_secret"], "dropbox-client-secret");
        assert_eq!(
            exchange_body["redirect_uri"],
            "https://oauth.sfae.io/oauth/callback"
        );

        let refresh_body = parse_urlencoded(&requests[1].body);
        assert_eq!(refresh_body["grant_type"], "refresh_token");
        assert_eq!(refresh_body["refresh_token"], "refresh");
        assert_eq!(refresh_body["client_id"], "dropbox-client-id");
        assert_eq!(refresh_body["client_secret"], "dropbox-client-secret");

        assert_eq!(requests[2].method, "POST");
        assert_eq!(requests[2].target, "/current_account");
        assert_eq!(requests[2].header("authorization"), Some("Bearer access"));

        assert_eq!(requests[3].method, "POST");
        assert_eq!(requests[3].target, "/revoke");
        assert_eq!(requests[3].header("authorization"), Some("Bearer access"));
        assert!(requests[3].body.is_empty());
    }

    #[tokio::test]
    async fn revoke_refreshes_and_retries_when_dropbox_rejects_access_token() {
        let server = MockHttpServer::start(vec![
            MockResponse {
                status: 401,
                body: r#"{}"#.to_string(),
            },
            MockResponse::json(r#"{"access_token":"fresh-access","token_type":"bearer"}"#),
            MockResponse::json(r#"{}"#),
        ]);
        let mut config = test_config();
        config.dropbox_token_url = Url::parse(&format!("{}/token", server.base_url)).unwrap();
        config.dropbox_revoke_url = Url::parse(&format!("{}/revoke", server.base_url)).unwrap();
        let http = reqwest::Client::new();

        revoke_token(DropboxRevokeRequest {
            http: &http,
            config: &config,
            access_token: Some("stale-access"),
            refresh_token: Some("refresh"),
        })
        .await
        .unwrap();

        let requests = server.finish();
        assert_eq!(requests[0].target, "/revoke");
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer stale-access")
        );
        let refresh_body = parse_urlencoded(&requests[1].body);
        assert_eq!(requests[1].target, "/token");
        assert_eq!(refresh_body["grant_type"], "refresh_token");
        assert_eq!(refresh_body["refresh_token"], "refresh");
        assert_eq!(requests[2].target, "/revoke");
        assert_eq!(
            requests[2].header("authorization"),
            Some("Bearer fresh-access")
        );
    }

    struct MockResponse {
        status: u16,
        body: String,
    }

    impl MockResponse {
        fn json(body: &str) -> Self {
            Self {
                status: 200,
                body: body.to_string(),
            }
        }
    }

    struct CapturedRequest {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .get(&name.to_ascii_lowercase())
                .map(String::as_str)
        }
    }

    struct MockHttpServer {
        base_url: String,
        requests: mpsc::Receiver<CapturedRequest>,
        handle: thread::JoinHandle<()>,
    }

    impl MockHttpServer {
        fn start(responses: Vec<MockResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let (tx, rx) = mpsc::channel();
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = read_request(&mut stream);
                    tx.send(request).unwrap();
                    write_response(ResponseWrite {
                        stream: &mut stream,
                        response,
                    });
                }
            });
            Self {
                base_url,
                requests: rx,
                handle,
            }
        }

        fn finish(self) -> Vec<CapturedRequest> {
            self.handle.join().unwrap();
            self.requests.try_iter().collect()
        }
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        let header_end = loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "connection closed before headers");
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos;
            }
        };
        let headers_raw = String::from_utf8(raw[..header_end].to_vec()).unwrap();
        let mut lines = headers_raw.split("\r\n");
        let request_line = lines.next().unwrap();
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap().to_string();
        let target = request_parts.next().unwrap().to_string();
        let headers: HashMap<String, String> = lines
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect();
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let body_start = header_end + 4;
        while raw.len() < body_start + content_length {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "connection closed before body");
            raw.extend_from_slice(&buf[..n]);
        }
        let body =
            String::from_utf8(raw[body_start..body_start + content_length].to_vec()).unwrap();

        CapturedRequest {
            method,
            target,
            headers,
            body,
        }
    }

    struct ResponseWrite<'a> {
        stream: &'a mut TcpStream,
        response: MockResponse,
    }

    fn write_response(args: ResponseWrite<'_>) {
        let ResponseWrite { stream, response } = args;
        let status = response.status;
        let body = response.body;
        let reason = if status == 200 { "OK" } else { "Status" };
        let headers = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
    }

    fn parse_urlencoded(raw: &str) -> HashMap<String, String> {
        url::form_urlencoded::parse(raw.as_bytes())
            .into_owned()
            .collect()
    }
}
