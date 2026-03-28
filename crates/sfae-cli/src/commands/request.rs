use std::time::Instant;

use sfae_core::proxy::{self, ProxyRequest, extract_host};
use sfae_core::store::KeyringStore;

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

    let store = KeyringStore::new();

    if opts.dry_run {
        let masked_url = proxy::resolve_and_mask(&request.url, &store, &domain, opts.user)?;
        println!("{} {}", request.method, masked_url);
        for (k, v) in &request.headers {
            let masked_v = proxy::resolve_and_mask(v, &store, &domain, opts.user)?;
            println!("{k}: {masked_v}");
        }
        if let Some(b) = &request.body {
            let masked_body = proxy::resolve_and_mask(b, &store, &domain, opts.user)?;
            println!();
            println!("{masked_body}");
        }
        return Ok(());
    }

    let start = Instant::now();
    let response = proxy::execute(&request, &store, &domain, opts.user)?;
    let elapsed = start.elapsed();

    if opts.verbose {
        eprintln!("< {} ({:.1?})", response.status, elapsed);
    }

    print!("{}", response.body);
    Ok(())
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
