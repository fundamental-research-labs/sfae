/// Build a ureq Agent that respects HTTP_PROXY/HTTPS_PROXY env vars.
/// If PROXY_CA_CERT is set, configures TLS to trust the proxy CA for MITM.
pub fn make_agent() -> ureq::Agent {
    let mut config = ureq::Agent::config_builder().http_status_as_error(false);
    if let Some(proxy) = ureq::Proxy::try_from_env() {
        config = config.proxy(Some(proxy));
    }
    if let Some(tls) = build_tls_config() {
        config = config.tls_config(tls);
    }
    ureq::Agent::new_with_config(config.build())
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
            .root_certs(ureq::tls::RootCerts::Specific(
                std::sync::Arc::new(vec![cert]),
            ))
            .build(),
    )
}
