//! `sfae request`: send an HTTP request with `{KEY}` placeholders resolved against stored credentials.
//!
//! Includes the OAuth refresh-and-retry path used when the upstream returns 401.

use std::time::Instant;

use sfae_core::proxy::{
    CredentialLookup, PlaceholderMap, ProxyRequest, ProxyResponse, extract_host,
    find_dynamic_placeholders,
};
use sfae_core::store::{
    CredentialSetData, CredentialSetInfo, SecretStore, StructuredCredentialSetUpdate,
    parse_structured_credential_set,
};

use crate::store_factory::{create_store, uses_remote_store};

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
        let credentials = lookup.fetch()?;
        let placeholders = PlaceholderMap(&credentials);
        let masked_url = placeholders.mask(&request.url)?;
        println!("{} {}", request.method, masked_url);
        for (k, v) in &request.headers {
            let masked_v = placeholders.mask(v)?;
            println!("{k}: {masked_v}");
        }
        if let Some(b) = &request.body {
            let masked_body = placeholders.mask(b)?;
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
        if uses_remote_store() {
            self.try_refresh_and_retry_remote()
        } else {
            self.try_refresh_and_retry_local()
        }
    }

    /// Local-store refresh: read internal refresh material, call oauth.sfae.io, update, retry.
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

        let resolved = match fetch_credential_set(FetchCredentialSetCtx {
            store: &*store,
            domain,
            username,
            cred_id,
        }) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                if verbose {
                    eprintln!("< 401 (no local credential set found for OAuth refresh)");
                }
                return Ok(original_response);
            }
            Err(e) => {
                if verbose {
                    eprintln!("< 401 (could not inspect local credential set: {e})");
                }
                return Ok(original_response);
            }
        };

        let Some(provider) = resolved.data.metadata.get("OAUTH_PROVIDER") else {
            if verbose {
                eprintln!("< 401 (credential set is not hosted OAuth)");
            }
            return Ok(original_response);
        };
        if provider != "discord" {
            if verbose {
                eprintln!("< 401 (hosted OAuth provider '{provider}' cannot be refreshed)");
            }
            return Ok(original_response);
        }
        let Some(refresh_token) = resolved.data.internal.get("OAUTH_REFRESH_TOKEN") else {
            if verbose {
                eprintln!("< 401 (local OAuth credential has no internal refresh token)");
            }
            return Ok(original_response);
        };
        let Some(broker_credential_id) = resolved.data.metadata.get("OAUTH_BROKER_CREDENTIAL_ID")
        else {
            if verbose {
                eprintln!("< 401 (local OAuth credential has no broker credential id)");
            }
            return Ok(original_response);
        };
        let Some(broker_credential_secret) =
            resolved.data.internal.get("OAUTH_BROKER_CREDENTIAL_SECRET")
        else {
            if verbose {
                eprintln!("< 401 (local OAuth credential has no broker credential secret)");
            }
            return Ok(original_response);
        };

        if verbose {
            eprintln!("< 401 (refreshing hosted OAuth credential through broker...)");
        }
        let broker = match sfae_core::oauth::DirectHostedOAuthBroker::from_env() {
            Ok(broker) => broker,
            Err(e) => {
                if verbose {
                    eprintln!("< OAuth broker configuration failed: {e}");
                }
                return Ok(original_response);
            }
        };
        let manager = sfae_core::oauth::OAuthCredentialManager::new(&broker);
        let refreshed = match manager.refresh_credential(sfae_core::oauth::HostedOAuthRefresh {
            provider,
            broker_credential_id,
            broker_credential_secret,
            refresh_token,
        }) {
            Ok(credential) => credential,
            Err(e) => {
                if verbose {
                    eprintln!("< OAuth refresh failed: {e}");
                }
                return Ok(original_response);
            }
        };

        if let Err(e) = store.update_structured_credential_set(StructuredCredentialSetUpdate {
            id: &resolved.info.id,
            values: Some(&refreshed.values),
            internal: Some(&refreshed.internal),
            metadata: Some(&refreshed.metadata),
        }) {
            if verbose {
                eprintln!("< Failed to update refreshed credential: {e}");
            }
            return Ok(original_response);
        }

        if verbose {
            eprintln!("< Token refreshed locally, retrying request...");
        }
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

    /// Remote-store refresh: call sfae-server's /credentials/refresh endpoint, then retry.
    fn try_refresh_and_retry_remote(self) -> anyhow::Result<ProxyResponse> {
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
            eprintln!("< 401 (requesting server-side refresh from remote store...)");
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

struct SelectedCredentialSet {
    info: CredentialSetInfo,
    data: CredentialSetData,
}

struct FetchCredentialSetCtx<'a> {
    store: &'a dyn SecretStore,
    domain: &'a str,
    username: Option<&'a str>,
    cred_id: Option<&'a str>,
}

fn fetch_credential_set(
    ctx: FetchCredentialSetCtx<'_>,
) -> anyhow::Result<Option<SelectedCredentialSet>> {
    let FetchCredentialSetCtx {
        store,
        domain,
        username,
        cred_id,
    } = ctx;
    if !store.supports_credential_sets() {
        return Ok(None);
    }
    if let Some(id) = cred_id {
        let blob = store.get(id)?;
        let info = store
            .list_credential_sets(None)?
            .into_iter()
            .find(|set| set.id == id)
            .unwrap_or_else(|| CredentialSetInfo {
                id: id.to_string(),
                domain: domain.to_string(),
                label: username.map(str::to_string),
                keys: vec![],
                metadata: std::collections::HashMap::new(),
            });
        return Ok(Some(SelectedCredentialSet {
            info,
            data: parse_structured_credential_set(&blob)?,
        }));
    }

    for d in walk_parent_domains(domain) {
        if let Some(resolved) = find_credential_set_for_domain(FindCredentialSetCtx {
            store,
            domain: &d,
            username,
        })? {
            return Ok(Some(resolved));
        }
    }
    Ok(None)
}

struct FindCredentialSetCtx<'a> {
    store: &'a dyn SecretStore,
    domain: &'a str,
    username: Option<&'a str>,
}

fn find_credential_set_for_domain(
    ctx: FindCredentialSetCtx<'_>,
) -> anyhow::Result<Option<SelectedCredentialSet>> {
    let FindCredentialSetCtx {
        store,
        domain,
        username,
    } = ctx;
    let sets = store.list_credential_sets(Some(domain))?;
    if sets.is_empty() {
        return Ok(None);
    }
    let filtered: Vec<_> = if let Some(user) = username {
        sets.into_iter()
            .filter(|s| s.label.as_deref() == Some(user))
            .collect()
    } else {
        sets
    };
    if filtered.is_empty() {
        return Ok(None);
    }
    if filtered.len() > 1 {
        let set_list: Vec<String> = filtered
            .iter()
            .map(|s| format!("  {} ({})", s.id, s.label.as_deref().unwrap_or("no label")))
            .collect();
        anyhow::bail!(
            "multiple credential sets for domain '{}'. Use --cred <id> to select:\n{}",
            domain,
            set_list.join("\n")
        );
    }

    let blob = store.get(&filtered[0].id)?;
    Ok(Some(SelectedCredentialSet {
        info: filtered[0].clone(),
        data: parse_structured_credential_set(&blob)?,
    }))
}

fn walk_parent_domains(domain: &str) -> Vec<String> {
    let mut result = vec![domain.to_string()];
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent: Vec<&str> = parts[i..].to_vec();
        if parent.len() < 2 {
            break;
        }
        result.push(parent.join("."));
    }
    result
}

fn mask_placeholders(text: &str) -> String {
    let mut result = text.to_string();
    for key in find_dynamic_placeholders(text) {
        result = result.replace(&format!("{{{key}}}"), "***");
    }
    result
}
