use std::time::Instant;

use sfae_core::credential::{CredentialType, credential_key};
use sfae_core::error::SfaeError;
use sfae_core::oauth;
use sfae_core::proxy::{self, ProxyRequest, ProxyResponse, extract_host, find_placeholders};
use sfae_core::store::SecretStore;

use crate::store_factory::{create_store, is_api_mode};

pub struct RequestOpts<'a> {
    pub dry_run: bool,
    pub verbose: bool,
    pub domain: Option<&'a str>,
    pub user: Option<&'a str>,
}

pub fn run(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    opts: &RequestOpts,
) -> anyhow::Result<()> {
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
        let masked_url = proxy::resolve_and_mask(&request.url, &*store, &domain, opts.user)?;
        println!("{} {}", request.method, masked_url);
        for (k, v) in &request.headers {
            let masked_v = proxy::resolve_and_mask(v, &*store, &domain, opts.user)?;
            println!("{k}: {masked_v}");
        }
        if let Some(b) = &request.body {
            let masked_body = proxy::resolve_and_mask(b, &*store, &domain, opts.user)?;
            println!();
            println!("{masked_body}");
        }
        return Ok(());
    }

    let start = Instant::now();
    let response = proxy::execute(&request, &*store, &domain, opts.user)?;
    let elapsed = start.elapsed();

    if opts.verbose {
        eprintln!("< {} ({:.1?})", response.status, elapsed);
    }

    let response = if response.status == 401 && request_has_access_token_placeholder(&request) {
        try_refresh_and_retry(
            &request,
            &mut *store,
            &domain,
            opts.user,
            opts.verbose,
            response,
        )?
    } else {
        response
    };

    print!("{}", response.body);
    Ok(())
}

/// Check whether any part of the request contains an `-ACCESS_TOKEN-` placeholder.
fn request_has_access_token_placeholder(request: &ProxyRequest) -> bool {
    if find_placeholders(&request.url).contains(&CredentialType::AccessToken) {
        return true;
    }
    for (_, v) in &request.headers {
        if find_placeholders(v).contains(&CredentialType::AccessToken) {
            return true;
        }
    }
    if let Some(b) = &request.body
        && find_placeholders(b).contains(&CredentialType::AccessToken)
    {
        return true;
    }
    false
}

/// Attempt to refresh the access token and retry the request.
///
/// Returns the original response if any precondition is missing or the refresh fails.
fn try_refresh_and_retry(
    request: &ProxyRequest,
    store: &mut dyn SecretStore,
    domain: &str,
    username: Option<&str>,
    verbose: bool,
    original_response: ProxyResponse,
) -> anyhow::Result<ProxyResponse> {
    if is_api_mode() {
        return try_refresh_and_retry_api(
            request,
            store,
            domain,
            username,
            verbose,
            original_response,
        );
    }

    // Local mode: read OAuth metadata from disk and refresh locally.

    // Check: OAuth metadata exists for this domain.
    let metadata = match oauth::get_oauth_metadata(domain, username)? {
        Some(m) => m,
        None => return Ok(original_response),
    };

    // Check: a refresh token is stored for this domain.
    let refresh_token = match proxy::get_credential_with_fallback(
        store,
        domain,
        username,
        CredentialType::RefreshToken,
    ) {
        Ok(t) => t,
        Err(SfaeError::CredentialNotFound(_)) => return Ok(original_response),
        Err(e) => return Err(e.into()),
    };

    if verbose {
        eprintln!("< 401 (refresh token available, attempting refresh...)");
    }

    // Look up the client secret (may be absent for public clients).
    let client_secret = match proxy::get_credential_with_fallback(
        store,
        domain,
        username,
        CredentialType::ClientSecret,
    ) {
        Ok(s) => Some(s),
        Err(SfaeError::CredentialNotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };

    // Attempt the refresh.
    let token_response = match oauth::refresh_access_token(
        &metadata.token_url,
        &refresh_token,
        &metadata.client_id,
        client_secret.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Token refresh failed for {domain}: {e}");
            return Ok(original_response);
        }
    };

    // Update the access token in the store.
    let access_key = credential_key(domain, username, CredentialType::AccessToken);
    store.set(&access_key, &token_response.access_token)?;

    // If the provider rotated the refresh token, update it too.
    if let Some(new_refresh) = &token_response.refresh_token {
        let refresh_key = credential_key(domain, username, CredentialType::RefreshToken);
        store.set(&refresh_key, new_refresh)?;
    }

    if verbose {
        eprintln!("< Token refreshed successfully, retrying request...");
    }

    // Retry the request once.
    let start = Instant::now();
    let retry_response = proxy::execute(request, store, domain, username)?;
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
fn try_refresh_and_retry_api(
    request: &ProxyRequest,
    store: &dyn SecretStore,
    domain: &str,
    username: Option<&str>,
    verbose: bool,
    original_response: ProxyResponse,
) -> anyhow::Result<ProxyResponse> {
    let base_url = std::env::var("SFAE_STORE_URL").unwrap();
    let token = std::env::var("SFAE_STORE_TOKEN").unwrap_or_default();

    if verbose {
        eprintln!("< 401 (API mode, requesting server-side refresh...)");
    }

    let url = format!("{}/credentials/refresh", base_url.trim_end_matches('/'));
    let body = serde_json::json!({ "domain": domain }).to_string();

    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(agent);

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
    let retry_response = proxy::execute(request, store, domain, username)?;
    let elapsed = start.elapsed();

    if verbose {
        eprintln!("< {} ({:.1?})", retry_response.status, elapsed);
    }

    Ok(retry_response)
}

fn mask_placeholders(text: &str) -> String {
    let mut result = text.to_string();
    for pattern in &[
        "-ACCESS_TOKEN-",
        "-REFRESH_TOKEN-",
        "-API_KEY-",
        "-PASSWORD-",
    ] {
        result = result.replace(pattern, "***");
    }
    result
}
