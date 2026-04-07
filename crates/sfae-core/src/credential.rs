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

/// Build the keychain key for a credential.
///
/// Format: `<domain>_<TYPE>` or `<domain>_<username>_<TYPE>`
pub fn credential_key(domain: &str, username: Option<&str>, cred_type: CredentialType) -> String {
    match username {
        Some(user) => format!("{domain}_{user}_{}", cred_type.as_str()),
        None => format!("{domain}_{}", cred_type.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_key_without_username() {
        assert_eq!(
            credential_key("github.com", None, CredentialType::ApiKey),
            "github.com_API_KEY"
        );
    }

    #[test]
    fn credential_key_with_username() {
        assert_eq!(
            credential_key("github.com", Some("aduermael"), CredentialType::Password),
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
