//! Create the `SecretStore` backend used by the CLI.

use sfae_core::api_store::ApiStore;
use sfae_core::store::SecretStore;

/// Store backend selected from this process environment and build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreBackend {
    Remote,
    #[cfg(feature = "native-keychain")]
    NativeKeychain,
    #[cfg(not(feature = "native-keychain"))]
    Unavailable,
}

/// Create the appropriate SecretStore for this build.
pub fn create_store() -> Box<dyn SecretStore> {
    if let Some(store) = ApiStore::from_env() {
        return Box::new(store);
    }

    #[cfg(feature = "native-keychain")]
    {
        Box::new(sfae_core::store::KeyringStore::new())
    }

    #[cfg(not(feature = "native-keychain"))]
    {
        panic!("No credential store available. Set SFAE_STORE_URL and SFAE_STORE_TOKEN.");
    }
}

/// Returns true for remote-store client builds.
pub fn uses_remote_store() -> bool {
    std::env::var("SFAE_STORE_URL").is_ok()
}

/// Return the backend SFAE would use without constructing it.
pub fn selected_backend() -> StoreBackend {
    if uses_remote_store() {
        return StoreBackend::Remote;
    }

    #[cfg(feature = "native-keychain")]
    {
        StoreBackend::NativeKeychain
    }

    #[cfg(not(feature = "native-keychain"))]
    {
        StoreBackend::Unavailable
    }
}
