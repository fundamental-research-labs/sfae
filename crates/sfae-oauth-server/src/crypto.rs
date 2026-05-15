//! State hashing and token encryption helpers used by the hosted OAuth service.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::Rng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;

/// HMAC-SHA256 state hashing so raw OAuth state never needs to be stored.
#[derive(Clone)]
pub(crate) struct StateHasher {
    key: Vec<u8>,
}

impl StateHasher {
    /// Create a state hasher from a high-entropy runtime secret.
    pub(crate) fn new(secret: &str) -> Self {
        Self {
            key: secret.as_bytes().to_vec(),
        }
    }

    /// Compute a stable URL-safe hash for a raw OAuth state value.
    pub(crate) fn hash(&self, state: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(state.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

/// AES-256-GCM token encryption wrapper.
#[derive(Clone)]
pub(crate) struct TokenCipher {
    key: LessSafeKey,
}

impl TokenCipher {
    /// Build a cipher from the base64 32-byte deployment secret.
    pub(crate) fn from_base64_key(raw: &str) -> Result<Self, String> {
        let bytes = STANDARD
            .decode(raw)
            .map_err(|e| format!("invalid base64 encryption key: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "encryption key is {} bytes, expected 32",
                bytes.len()
            ));
        }
        let unbound =
            UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| "invalid AES key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    /// Encrypt a token and return `v1:<nonce>:<ciphertext>` for DB storage.
    pub(crate) fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| "token encryption failed".to_string())?;
        Ok(format!(
            "v1:{}:{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(in_out)
        ))
    }
}

/// Generate a high-entropy OAuth state value for a browser redirect flow.
pub(crate) fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
