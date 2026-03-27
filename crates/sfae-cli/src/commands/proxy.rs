use std::time::Instant;

use sfae_core::proxy::{self, ProxyRequest};
use sfae_core::service::ServiceRegistry;
use sfae_core::store::KeyringStore;

pub fn run(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    service: Option<&str>,
    dry_run: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    // Resolve full URL, prepending service base_url if --service is given.
    let full_url = if let Some(service_id) = service {
        let config = ServiceRegistry::get(service_id)?;
        let base = config.base_url.trim_end_matches('/');
        let path = url.trim_start_matches('/');
        format!("{base}/{path}")
    } else {
        url.to_string()
    };

    // Parse header strings ("Key: Value").
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
        url: full_url,
        headers: parsed_headers,
        body: body.map(String::from),
    };

    if verbose {
        eprintln!("> {} {}", request.method, mask_placeholders(&request.url));
        for (k, v) in &request.headers {
            eprintln!("> {k}: {}", mask_placeholders(v));
        }
        if request.body.is_some() {
            eprintln!("> [body present]");
        }
        eprintln!();
    }

    let store = KeyringStore::new();

    if dry_run {
        // Resolve and mask — validates credentials exist, shows masked output.
        let masked_url = proxy::resolve_and_mask(&request.url, &store)?;
        println!("{} {}", request.method, masked_url);
        for (k, v) in &request.headers {
            let masked_v = proxy::resolve_and_mask(v, &store)?;
            println!("{k}: {masked_v}");
        }
        if let Some(b) = &request.body {
            let masked_body = proxy::resolve_and_mask(b, &store)?;
            println!();
            println!("{masked_body}");
        }
        return Ok(());
    }

    let start = Instant::now();
    let response = proxy::execute(&request, &store)?;
    let elapsed = start.elapsed();

    if verbose {
        eprintln!("< {} ({:.1?})", response.status, elapsed);
    }

    // Output response body to stdout for agent consumption.
    print!("{}", response.body);
    Ok(())
}

/// Replace secret values in placeholder positions with `***` for safe display.
fn mask_placeholders(text: &str) -> String {
    let re = regex::Regex::new(r"\{\{sfae:[a-zA-Z0-9_-]+\}\}").expect("valid regex");
    re.replace_all(text, "***").to_string()
}
