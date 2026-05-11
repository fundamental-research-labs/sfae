//! `sfae request`: send an HTTP request with `{KEY}` placeholders resolved against stored credentials.
//!
//! Includes the OAuth refresh-and-retry path used when the upstream returns 401.

use std::time::Instant;

use sfae_core::credential::{CredentialKey, CredentialType, credential_key};
use sfae_core::error::SfaeError;
use sfae_core::oauth;
use sfae_core::proxy::{
    CredentialLookup, ProxyRequest, ProxyResponse, extract_host, find_dynamic_placeholders,
};
use sfae_core::store::SecretStore;

use crate::store_factory::{create_store, is_api_mode};

pub struct RequestOpts<'a> {
    pub dry_run: bool,
    pub verbose: bool,
    pub domain: Option<&'a str>,
    pub user: Option<&'a str>,
    pub cred_id: Option<&'a str>,
}

/// All inputs for `run`: HTTP method/URL/headers/body + runtime options.
pub struct RunArgs<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [String],
    pub body: Option<&'a str>,
    pub opts: &'a RequestOpts<'a>,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        method,
        url,
        headers,
        body,
        opts,
    } = args;

    let domain = match opts.domain {
        Some(d) => d.to_string(),
        None => extract_host(url)
            .ok_or_else(|| anyhow::anyhow!("cannot extract host from URL; use --domain"))?,
    };

    let parsed_headers: Vec<(String, String)> = headers
        .iter()
        .map(|h| {
            let (key, value) = h.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("invalid header format, expected 'Key: Value': {h}")
            })?;
            Ok((key.trim().to_string(), value.trim().to_string()))
        })
        .collect::<anyhow::Result<_>>()?;

    let request = ProxyRequest {
        method: method.to_uppercase(),
        url: url.to_string(),
        headers: parsed_headers,
        body: body.map(String::from),
    };

    if opts.verbose {
        eprintln!("> {} {}", request.method, mask_placeholders(&request.url));
        for (k, v) in &request.headers {
            eprintln!("> {k}: {}", mask_placeholders(v));
        }
        if request.body.is_some() {
            eprintln!("> [body present]");
        }
        eprintln!();
    }

    let mut store = create_store();

    if opts.dry_run {
        let lookup = CredentialLookup {
            store: &*store,
            domain: &domain,
            username: opts.user,
            cred_id: opts.cred_id,
        };
        let masked_url = lookup.mask(&request.url)?;
        println!("{} {}", request.method, masked_url);
        for (k, v) in &request.headers {
            let masked_v = lookup.mask(v)?;
            println!("{k}: {masked_v}");
        }
        if let Some(b) = &request.body {
            let masked_body = lookup.mask(b)?;
            println!();
            println!("{masked_body}");
        }
        return Ok(());
    }

    let start = Instant::now();
    let response = CredentialLookup {
        store: &*store,
        domain: &domain,
        username: opts.user,
        cred_id: opts.cred_id,
    }
    .execute(&request)?;
    let elapsed = start.elapsed();

    if opts.verbose {
        eprintln!("< {} ({:.1?})", response.status, elapsed);
    }

    let response = if response.status == 401 && request_has_access_token_placeholder(&request) {
        RetryCtx {
            request: &request,
            store: &mut *store,
            domain: &domain,
            username: opts.user,
            cred_id: opts.cred_id,
            verbose: opts.verbose,
            original_response: response,
        }
        .try_refresh_and_retry()?
    } else {
        response
    };

    print!("{}", response.body);
    Ok(())
}

/// Check whether any part of the request contains an `{OAUTH_ACCESS_TOKEN}` placeholder.
fn request_has_access_token_placeholder(request: &ProxyRequest) -> bool {
    let target = "OAUTH_ACCESS_TOKEN";
    if find_dynamic_placeholders(&request.url).contains(&target.to_string()) {
        return true;
    }
    for (_, v) in &request.headers {
        if find_dynamic_placeholders(v).contains(&target.to_string()) {
            return true;
        }
    }
    if let Some(b) = &request.body
        && find_dynamic_placeholders(b).contains(&target.to_string())
    {
        return true;
    }
    false
}

/// Context for a 401-retry flow: everything needed to refresh a token and re-send.
struct RetryCtx<'a> {
    request: &'a ProxyRequest,
    store: &'a mut dyn SecretStore,
    domain: &'a str,
    username: Option<&'a str>,
    cred_id: Option<&'a str>,
    verbose: bool,
    original_response: ProxyResponse,
}

impl<'a> RetryCtx<'a> {
    /// Attempt to refresh the access token and retry the request.
    ///
    /// Returns the original response if any precondition is missing or the refresh fails.
    fn try_refresh_and_retry(self) -> anyhow::Result<ProxyResponse> {
        if is_api_mode() {
            self.try_refresh_and_retry_api()
        } else {
            self.try_refresh_and_retry_local()
        }
    }

    /// Local mode: read OAuth metadata from disk and refresh via the provider directly.
    fn try_refresh_and_retry_local(self) -> anyhow::Result<ProxyResponse> {
        let RetryCtx {
            request,
            store,
            domain,
            username,
            cred_id,
            verbose,
            original_response,
        } = self;

        // Check: OAuth metadata exists for this domain.
        let metadata_key = oauth::MetadataKey { domain, username };
        let metadata = match metadata_key.get()? {
            Some(m) => m,
            None => return Ok(original_response),
        };

        // Check: a refresh token is stored for this domain.
        let refresh_token = match (CredentialLookup {
            store: &*store,
            domain,
            username,
            cred_id,
        })
        .get_by_type(CredentialType::RefreshToken)
        {
            Ok(t) => t,
            Err(SfaeError::CredentialNotFound(_)) => return Ok(original_response),
            Err(e) => return Err(e.into()),
        };

        if verbose {
            eprintln!("< 401 (refresh token available, attempting refresh...)");
        }

        // Look up the client secret (may be absent for public clients).
        let client_secret = match (CredentialLookup {
            store: &*store,
            domain,
            username,
            cred_id,
        })
        .get_by_type(CredentialType::ClientSecret)
        {
            Ok(s) => Some(s),
            Err(SfaeError::CredentialNotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };

        // Attempt the refresh.
        let token_response = match (oauth::TokenRequest {
            token_url: &metadata.token_url,
            client_id: &metadata.client_id,
            client_secret: client_secret.as_deref(),
            grant: oauth::Grant::RefreshToken {
                refresh_token: &refresh_token,
            },
        })
        .send()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Token refresh failed for {domain}: {e}");
                return Ok(original_response);
            }
        };

        // Update the access token in the store.
        let access_key = credential_key(CredentialKey {
            domain,
            username,
            cred_type: CredentialType::AccessToken,
        });
        store.set(sfae_core::store::StoreEntry {
            key: &access_key,
            value: &token_response.access_token,
        })?;

        // If the provider rotated the refresh token, update it too.
        if let Some(new_refresh) = &token_response.refresh_token {
            let refresh_key = credential_key(CredentialKey {
                domain,
                username,
                cred_type: CredentialType::RefreshToken,
            });
            store.set(sfae_core::store::StoreEntry {
                key: &refresh_key,
                value: new_refresh,
            })?;
        }

        if verbose {
            eprintln!("< Token refreshed successfully, retrying request...");
        }

        // Retry the request once.
        let start = Instant::now();
        let retry_response = CredentialLookup {
            store: &*store,
            domain,
            username,
            cred_id,
        }
        .execute(request)?;
        let elapsed = start.elapsed();

        if verbose {
            eprintln!("< {} ({:.1?})", retry_response.status, elapsed);
        }

        Ok(retry_response)
    }

    /// API mode refresh: call sfae-server's /credentials/refresh endpoint, then retry.
    ///
    /// The server reads OAuth metadata and refresh tokens from the DB, calls the provider,
    /// and updates the tokens — all server-side. The CLI just needs to retry after.
    fn try_refresh_and_retry_api(self) -> anyhow::Result<ProxyResponse> {
        let RetryCtx {
            request,
            store,
            domain,
            username,
            cred_id,
            verbose,
            original_response,
        } = self;

        let base_url = std::env::var("SFAE_STORE_URL").unwrap();
        let token = std::env::var("SFAE_STORE_TOKEN").unwrap_or_default();

        if verbose {
            eprintln!("< 401 (API mode, requesting server-side refresh...)");
        }

        let url = format!("{}/credentials/refresh", base_url.trim_end_matches('/'));
        let body = serde_json::json!({ "domain": domain }).to_string();

        let agent = sfae_core::http::make_agent();

        let req = ureq::http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| anyhow::anyhow!("Failed to build refresh request: {e}"))?;

        let response = match agent.run(req) {
            Ok(resp) => resp,
            Err(ureq::Error::StatusCode(code)) => {
                if verbose {
                    eprintln!("< Refresh request returned {code}, returning original 401");
                }
                return Ok(original_response);
            }
            Err(e) => {
                if verbose {
                    eprintln!("< Refresh request failed: {e}");
                }
                return Ok(original_response);
            }
        };

        let status = response.status().as_u16();
        if status != 200 {
            if verbose {
                eprintln!("< Server-side refresh returned {status}, returning original 401");
            }
            return Ok(original_response);
        }

        if verbose {
            eprintln!("< Token refreshed successfully via server, retrying request...");
        }

        // Retry — credentials re-resolved from API store with fresh tokens.
        let start = Instant::now();
        let retry_response = CredentialLookup {
            store: &*store,
            domain,
            username,
            cred_id,
        }
        .execute(request)?;
        let elapsed = start.elapsed();

        if verbose {
            eprintln!("< {} ({:.1?})", retry_response.status, elapsed);
        }

        Ok(retry_response)
    }
}

fn mask_placeholders(text: &str) -> String {
    let mut result = text.to_string();
    for key in find_dynamic_placeholders(text) {
        result = result.replace(&format!("{{{key}}}"), "***");
    }
    result
}
