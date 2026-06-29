//! GitHub OAuth provider descriptor, token exchange, revocation, and user lookup.

use crate::config::Config;
use crate::provider::{ProviderToken, ProviderUser};
use serde::Deserialize;

/// GitHub OAuth session inputs.
pub(crate) struct GitHubSession {
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_url: String,
}

/// GitHub OAuth token response fields used by SFAE.
#[derive(Deserialize)]
pub(crate) struct GitHubToken {
    pub(crate) access_token: String,
    #[serde(default)]
    pub(crate) token_type: Option<String>,
    #[serde(default)]
    pub(crate) scope: Option<String>,
}

impl GitHubToken {
    /// Convert GitHub token material into the provider-neutral broker shape.
    pub(crate) fn into_provider_token(self, requested: &[String]) -> ProviderToken {
        let scopes = self
            .scope
            .as_deref()
            .map(split_scopes)
            .unwrap_or_else(|| normalize_scopes(requested));
        ProviderToken {
            access_token: self.access_token,
            refresh_token: None,
            token_type: self.token_type,
            scopes,
            expires_at: None,
        }
    }
}

/// GitHub `/user` profile fields used for account linking.
#[derive(Deserialize)]
pub(crate) struct GitHubUser {
    pub(crate) id: u64,
    pub(crate) login: String,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) email: Option<String>,
}

impl GitHubUser {
    /// Prefer GitHub profile name and fall back to login.
    pub(crate) fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.login.clone())
    }

    /// Convert GitHub profile data into the provider-neutral broker shape.
    pub(crate) fn into_provider_user(self) -> ProviderUser {
        ProviderUser {
            subject: self.id.to_string(),
            display_name: Some(self.display_name()),
            email: self.email,
        }
    }
}

/// Build a GitHub authorization URL for the browser.
pub(crate) fn build_authorization(args: GitHubAuthorize<'_>) -> Result<GitHubSession, String> {
    let GitHubAuthorize {
        config,
        state,
        requested_scopes,
    } = args;
    let scopes = normalize_scopes(requested_scopes);
    let redirect_uri = config.generic_redirect_uri();
    let mut url = config.github_authorize_url.clone();
    url.query_pairs_mut()
        .append_pair("client_id", &config.github_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", state);
    if !scopes.is_empty() {
        url.query_pairs_mut()
            .append_pair("scope", &scopes.join(" "));
    }
    Ok(GitHubSession {
        scopes,
        authorization_url: url.to_string(),
    })
}

/// Inputs for building the GitHub authorize URL.
pub(crate) struct GitHubAuthorize<'a> {
    pub(crate) config: &'a Config,
    pub(crate) state: &'a str,
    pub(crate) requested_scopes: &'a [String],
}

/// Exchange an authorization code for a GitHub token.
pub(crate) async fn exchange_code(args: GitHubTokenRequest<'_>) -> Result<GitHubToken, String> {
    let GitHubTokenRequest { http, config, code } = args;
    let redirect_uri = config.generic_redirect_uri();
    let params = [
        ("client_id", config.github_client_id.as_str()),
        ("client_secret", config.github_client_secret.as_str()),
        ("code", code),
        ("redirect_uri", &redirect_uri),
    ];
    let response = http
        .post(config.github_token_url.clone())
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("provider token request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("GitHub token exchange rejected: {status}");
        return Err(format!("provider_token_status_{status}"));
    }
    response
        .json::<GitHubToken>()
        .await
        .map_err(|e| format!("provider token response parse failed: {e}"))
}

/// Inputs for a GitHub token exchange.
pub(crate) struct GitHubTokenRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) code: &'a str,
}

/// Revoke a GitHub OAuth grant.
pub(crate) async fn revoke_token(args: GitHubRevokeRequest<'_>) -> Result<(), String> {
    let GitHubRevokeRequest {
        http,
        config,
        token,
    } = args;
    let params = [("access_token", token)];
    let response = http
        .delete(config.github_grant_url())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "sfae-oauth")
        .basic_auth(&config.github_client_id, Some(&config.github_client_secret))
        .json(&params_map(&params))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("GitHub token revoke request failed: {e}");
            "provider_revoke_request_failed".to_string()
        })?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!("GitHub token revoke rejected: {status}");
        return Err(format!("provider_revoke_status_{}", status.as_u16()));
    }
    Ok(())
}

/// Inputs for GitHub token revocation.
pub(crate) struct GitHubRevokeRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) config: &'a Config,
    pub(crate) token: &'a str,
}

/// Fetch the GitHub account profile for a bearer access token.
pub(crate) async fn fetch_user(args: GitHubUserRequest<'_>) -> Result<GitHubUser, String> {
    let GitHubUserRequest {
        http,
        config,
        access_token,
    } = args;
    let response = http
        .get(config.github_userinfo_url.clone())
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "sfae-oauth")
        .send()
        .await
        .map_err(|e| format!("provider identity request failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(format!("provider_identity_status_{status}"));
    }
    response
        .json::<GitHubUser>()
        .await
        .map_err(|e| format!("provider identity response parse failed: {e}"))
}

/// Inputs for loading GitHub user identity.
pub(crate) struct GitHubUserRequest<'a> {
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
    scopes.sort();
    scopes.dedup();
    scopes
}

fn split_scopes(raw: &str) -> Vec<String> {
    let mut scopes: Vec<String> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

fn params_map(params: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    params
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
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
    fn scopes_are_sorted_deduped_split_and_allow_empty_default() {
        let scopes = normalize_scopes(&[
            "repo read:user".to_string(),
            "user:email".to_string(),
            "repo".to_string(),
            " ".to_string(),
        ]);

        assert_eq!(scopes, vec!["read:user", "repo", "user:email"]);
        assert!(normalize_scopes(&[]).is_empty());
    }

    #[test]
    fn authorization_url_contains_only_valid_github_parameters() {
        let session = build_authorization(GitHubAuthorize {
            config: &test_config(),
            state: "state-value",
            requested_scopes: &["repo read:user".to_string()],
        })
        .unwrap();
        let url = Url::parse(&session.authorization_url).unwrap();
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut keys: Vec<_> = pairs.keys().map(String::as_str).collect();
        keys.sort();

        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(pairs["client_id"], "github-client-id");
        assert_eq!(
            pairs["redirect_uri"],
            "https://oauth.sfae.io/oauth/callback"
        );
        assert_eq!(pairs["scope"], "read:user repo");
        assert_eq!(pairs["state"], "state-value");
        assert_eq!(keys, vec!["client_id", "redirect_uri", "scope", "state"]);
    }

    #[test]
    fn token_response_uses_comma_or_space_separated_returned_scopes() {
        let token = GitHubToken {
            access_token: "access".to_string(),
            token_type: Some("bearer".to_string()),
            scope: Some("repo,user:email read:user,repo".to_string()),
        }
        .into_provider_token(&["admin:org".to_string()]);

        assert_eq!(token.access_token, "access");
        assert!(token.refresh_token.is_none());
        assert_eq!(token.token_type.as_deref(), Some("bearer"));
        assert_eq!(token.scopes, vec!["read:user", "repo", "user:email"]);
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn token_response_falls_back_to_requested_scopes() {
        let token = GitHubToken {
            access_token: "access".to_string(),
            token_type: None,
            scope: None,
        }
        .into_provider_token(&["repo read:user".to_string()]);

        assert_eq!(token.scopes, vec!["read:user", "repo"]);
    }

    #[test]
    fn user_display_name_falls_back_to_login() {
        let named = GitHubUser {
            id: 42,
            login: "octocat".to_string(),
            name: Some("The Octocat".to_string()),
            email: None,
        };
        assert_eq!(named.display_name(), "The Octocat");

        let login_only = GitHubUser {
            id: 42,
            login: "octocat".to_string(),
            name: None,
            email: None,
        };
        assert_eq!(login_only.display_name(), "octocat");
    }

    #[tokio::test]
    async fn revoke_uses_github_grant_endpoint_headers_auth_body_and_status() {
        let server = MockHttpServer::start(vec![
            MockResponse {
                status: 204,
                body: String::new(),
            },
            MockResponse {
                status: 401,
                body: r#"{"message":"bad credentials"}"#.to_string(),
            },
        ]);
        let mut config = test_config();
        config.github_api_url = Url::parse(&server.base_url).unwrap();
        let http = reqwest::Client::new();

        revoke_token(GitHubRevokeRequest {
            http: &http,
            config: &config,
            token: "access-token",
        })
        .await
        .unwrap();
        let err = revoke_token(GitHubRevokeRequest {
            http: &http,
            config: &config,
            token: "rejected-token",
        })
        .await
        .unwrap_err();
        assert_eq!(err, "provider_revoke_status_401");

        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        let expected_auth = format!(
            "Basic {}",
            STANDARD.encode("github-client-id:github-client-secret")
        );
        for request in &requests {
            assert_eq!(request.method, "DELETE");
            assert_eq!(request.target, "/applications/github-client-id/grant");
            assert_eq!(
                request.header("accept"),
                Some("application/vnd.github+json")
            );
            assert_eq!(request.header("x-github-api-version"), Some("2022-11-28"));
            assert_eq!(request.header("user-agent"), Some("sfae-oauth"));
            assert_eq!(
                request.header("authorization"),
                Some(expected_auth.as_str())
            );
        }
        let first_body: HashMap<String, String> = serde_json::from_str(&requests[0].body).unwrap();
        let second_body: HashMap<String, String> = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(first_body["access_token"], "access-token");
        assert_eq!(second_body["access_token"], "rejected-token");
    }

    struct MockResponse {
        status: u16,
        body: String,
    }

    struct CapturedRequest {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).map(String::as_str)
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
                    write_response(&mut stream, response);
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
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0, "connection closed before headers");
            raw.extend_from_slice(&buf[..read]);
            if let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
        let content_length = content_length_from_headers(&header_text);
        while raw.len() < header_end + content_length {
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0, "connection closed before body");
            raw.extend_from_slice(&buf[..read]);
        }

        let mut lines = header_text.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or_default().to_string();
        let target = request_parts.next().unwrap_or_default().to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        let body =
            String::from_utf8_lossy(&raw[header_end..header_end + content_length]).to_string();
        CapturedRequest {
            method,
            target,
            headers,
            body,
        }
    }

    fn content_length_from_headers(headers: &str) -> usize {
        headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0)
    }

    // xtask: allow-multi-param - test helper pairs stream with response data
    fn write_response(stream: &mut TcpStream, response: MockResponse) {
        let reason = match response.status {
            204 => "No Content",
            401 => "Unauthorized",
            _ => "Status",
        };
        let http = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status,
            reason,
            response.body.len(),
            response.body
        );
        stream.write_all(http.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}
