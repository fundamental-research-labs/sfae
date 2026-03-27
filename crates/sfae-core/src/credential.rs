use serde::{Deserialize, Serialize};

/// Supported credential types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credential {
    /// A simple bearer / access token.
    #[serde(rename = "access_token")]
    AccessToken { token: String },
    // Future: OAuth2, API key + secret, etc.
}

impl Credential {
    /// Returns the raw secret value for placeholder resolution.
    pub fn secret_value(&self) -> &str {
        match self {
            Credential::AccessToken { token } => token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_returns_token() {
        let cred = Credential::AccessToken {
            token: "abc123".to_string(),
        };
        assert_eq!(cred.secret_value(), "abc123");
    }

    #[test]
    fn serialize_roundtrip() {
        let cred = Credential::AccessToken {
            token: "secret".to_string(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"type\":\"access_token\""));
        let deserialized: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.secret_value(), "secret");
    }
}
