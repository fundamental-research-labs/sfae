//! Centralized HTTP agent construction with proxy support.

/// Build a ureq Agent that respects HTTP_PROXY/HTTPS_PROXY env vars.
pub fn make_agent() -> ureq::Agent {
    let mut config = ureq::Agent::config_builder().http_status_as_error(false);
    if let Some(proxy) = ureq::Proxy::try_from_env() {
        config = config.proxy(Some(proxy));
    }
    ureq::Agent::new_with_config(config.build())
}
