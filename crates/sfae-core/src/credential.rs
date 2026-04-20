use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Supported credential types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialType {
    AccessToken,
    RefreshToken,
    ApiKey,
    Password,
    Username,
    ClientSecret,
}

impl CredentialType {
    /// Returns all known credential types.
    pub fn all() -> &'static [CredentialType] {
        &[
            CredentialType::AccessToken,
            CredentialType::RefreshToken,
            CredentialType::ApiKey,
            CredentialType::Password,
            CredentialType::Username,
            CredentialType::ClientSecret,
        ]
    }

    /// String representation used in keys and placeholders.
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::AccessToken => "ACCESS_TOKEN",
            CredentialType::RefreshToken => "REFRESH_TOKEN",
            CredentialType::ApiKey => "API_KEY",
            CredentialType::Password => "PASSWORD",
            CredentialType::Username => "USERNAME",
            CredentialType::ClientSecret => "CLIENT_SECRET",
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CredentialType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "ACCESS_TOKEN" => Ok(CredentialType::AccessToken),
            "REFRESH_TOKEN" => Ok(CredentialType::RefreshToken),
            "API_KEY" => Ok(CredentialType::ApiKey),
            "PASSWORD" => Ok(CredentialType::Password),
            "USERNAME" => Ok(CredentialType::Username),
            "CLIENT_SECRET" => Ok(CredentialType::ClientSecret),
            _ => Err(format!("unknown credential type: {s}")),
        }
    }
}

/// The inputs needed to build a legacy flat-key credential key.
pub struct CredentialKey<'a> {
    pub domain: &'a str,
    pub username: Option<&'a str>,
    pub cred_type: CredentialType,
}

impl<'a> CredentialKey<'a> {
    /// Build the keychain key string for this credential.
    ///
    /// Format: `<domain>_<TYPE>` or `<domain>_<username>_<TYPE>`.
    pub fn as_string(&self) -> String {
        match self.username {
            Some(user) => format!("{}_{user}_{}", self.domain, self.cred_type.as_str()),
            None => format!("{}_{}", self.domain, self.cred_type.as_str()),
        }
    }
}

/// Thin wrapper for legacy call sites: build the key string for a credential.
pub fn credential_key(key: CredentialKey<'_>) -> String {
    key.as_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_key_without_username() {
        assert_eq!(
            credential_key(CredentialKey {
                domain: "github.com",
                username: None,
                cred_type: CredentialType::ApiKey,
            }),
            "github.com_API_KEY"
        );
    }

    #[test]
    fn credential_key_with_username() {
        assert_eq!(
            credential_key(CredentialKey {
                domain: "github.com",
                username: Some("aduermael"),
                cred_type: CredentialType::Password,
            }),
            "github.com_aduermael_PASSWORD"
        );
    }

    #[test]
    fn credential_type_roundtrip() {
        for ct in CredentialType::all() {
            let s = ct.to_string();
            let parsed: CredentialType = s.parse().unwrap();
            assert_eq!(*ct, parsed);
        }
    }

    #[test]
    fn credential_type_case_insensitive() {
        assert_eq!(
            "api_key".parse::<CredentialType>().unwrap(),
            CredentialType::ApiKey
        );
        assert_eq!(
            "Access_Token".parse::<CredentialType>().unwrap(),
            CredentialType::AccessToken
        );
    }

    #[test]
    fn credential_type_unknown() {
        assert!("UNKNOWN".parse::<CredentialType>().is_err());
    }
}
