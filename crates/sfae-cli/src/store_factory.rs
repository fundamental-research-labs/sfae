use sfae_core::api_store::ApiStore;
use sfae_core::store::SecretStore;

/// Create the appropriate SecretStore based on environment.
/// If SFAE_STORE_URL is set, use ApiStore (HTTP-backed).
/// Otherwise, use KeyringStore (OS keychain).
pub fn create_store() -> Box<dyn SecretStore> {
    if let Some(store) = ApiStore::from_env() {
        return Box::new(store);
    }

    #[cfg(feature = "keyring")]
    {
        Box::new(sfae_core::store::KeyringStore::new())
    }

    #[cfg(not(feature = "keyring"))]
    {
        panic!(
            "No credential store available — missing env vars. \
             Set SFAE_STORE_URL and SFAE_STORE_TOKEN for API store mode, \
             or build with the keyring feature for OS keychain mode."
        );
    }
}

/// Returns true if running in client mode (API store backed by sfae-server).
pub fn is_api_mode() -> bool {
    std::env::var("SFAE_STORE_URL").is_ok()
}
