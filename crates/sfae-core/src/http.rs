//! Centralized HTTP agent construction with proxy and custom CA support.

/// Build a ureq Agent that respects HTTP_PROXY/HTTPS_PROXY env vars.
/// If PROXY_CA_CERT is set, configures TLS to trust the proxy CA for MITM.
pub fn make_agent() -> ureq::Agent {
    make_agent_with_proxy(true)
}

/// Build a ureq Agent for a target URL, bypassing proxies for loopback targets.
pub fn make_agent_for_url(raw_url: &str) -> ureq::Agent {
    make_agent_with_proxy(!is_loopback_url(raw_url))
}

fn make_agent_with_proxy(use_proxy: bool) -> ureq::Agent {
    let mut config = ureq::Agent::config_builder().http_status_as_error(false);
    if use_proxy && let Some(proxy) = ureq::Proxy::try_from_env() {
        config = config.proxy(Some(proxy));
    }
    if let Some(tls) = build_tls_config() {
        config = config.tls_config(tls);
    }
    ureq::Agent::new_with_config(config.build())
}

fn is_loopback_url(raw_url: &str) -> bool {
    let Ok(uri) = raw_url.parse::<ureq::http::Uri>() else {
        return false;
    };
    matches!(
        uri.host(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    )
}

/// If PROXY_CA_CERT points to a PEM file, build a TlsConfig that trusts
/// the proxy CA. In MITM mode all certs are signed by the proxy CA, so
/// webpki roots are not needed — the proxy verifies upstream certs.
/// Returns None if PROXY_CA_CERT is unset (normal operation, webpki roots used).
fn build_tls_config() -> Option<ureq::tls::TlsConfig> {
    let ca_path = std::env::var("PROXY_CA_CERT").ok()?;
    let pem = std::fs::read(&ca_path).ok()?;
    let cert = ureq::tls::Certificate::from_pem(&pem).ok()?;

    Some(
        ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(vec![
                cert,
            ])))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::is_loopback_url;

    #[test]
    fn loopback_url_detection_accepts_local_targets() {
        assert!(is_loopback_url("http://127.0.0.1:3100"));
        assert!(is_loopback_url("http://localhost:3100"));
        assert!(is_loopback_url("http://[::1]:3100"));
    }

    #[test]
    fn loopback_url_detection_rejects_remote_targets() {
        assert!(!is_loopback_url("https://oauth.sfae.io"));
        assert!(!is_loopback_url("http://192.168.1.10:3100"));
        assert!(!is_loopback_url("not a url"));
    }
}
