//! Transient one-time code request model used by `sfae code`.
//!
//! A verification code is intentionally not a stored credential. The CLI returns
//! it to the caller so the agent can complete a short-lived 2FA challenge.

use std::time::{Duration, Instant};

use crate::error::SfaeError;

pub const DEFAULT_MIN_LENGTH: usize = 4;
pub const DEFAULT_MAX_LENGTH: usize = 12;
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const MAX_CODE_LENGTH: usize = 128;

/// Accepted character classes for one-time codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFormat {
    Digits,
    Alnum,
    Text,
}

impl CodeFormat {
    /// Parse a CLI/wire value into a code format.
    pub fn parse(value: &str) -> Result<Self, SfaeError> {
        match value {
            "digits" => Ok(Self::Digits),
            "alnum" => Ok(Self::Alnum),
            "text" => Ok(Self::Text),
            _ => Err(SfaeError::ConfigError(
                "code format must be one of: digits, alnum, text".into(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Digits => "digits",
            Self::Alnum => "alnum",
            Self::Text => "text",
        }
    }
}

/// A single transient code request.
#[derive(Debug, Clone)]
pub struct CodeRequest {
    pub domain: String,
    pub label: Option<String>,
    pub message: Option<String>,
    pub help_url: Option<String>,
    pub format: CodeFormat,
    pub min_length: usize,
    pub max_length: usize,
    pub timeout: Duration,
}

impl CodeRequest {
    /// Validate request configuration before opening the browser.
    pub fn validate(&self) -> Result<(), SfaeError> {
        if self.domain.trim().is_empty() {
            return Err(SfaeError::ConfigError("domain cannot be empty".into()));
        }
        if self.domain.chars().any(char::is_control) {
            return Err(SfaeError::ConfigError(
                "domain cannot contain control characters".into(),
            ));
        }
        if self.min_length == 0 {
            return Err(SfaeError::ConfigError(
                "minimum code length must be at least 1".into(),
            ));
        }
        if self.max_length > MAX_CODE_LENGTH {
            return Err(SfaeError::ConfigError(format!(
                "maximum code length cannot exceed {MAX_CODE_LENGTH}"
            )));
        }
        if self.min_length > self.max_length {
            return Err(SfaeError::ConfigError(
                "minimum code length cannot exceed maximum code length".into(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(SfaeError::ConfigError(
                "timeout must be greater than zero seconds".into(),
            ));
        }
        if Instant::now().checked_add(self.timeout).is_none() {
            return Err(SfaeError::ConfigError("timeout is too large".into()));
        }
        if let Some(url) = &self.help_url
            && !is_http_url(url)
        {
            return Err(SfaeError::ConfigError(
                "help-url must start with http:// or https://".into(),
            ));
        }
        Ok(())
    }

    /// Trim and validate a submitted code.
    pub fn normalize_code(&self, raw: &str) -> Result<String, SfaeError> {
        self.validate()?;
        let code = raw.trim();
        if code.is_empty() {
            return Err(SfaeError::ConfigError("code cannot be empty".into()));
        }
        if code.chars().any(char::is_control) {
            return Err(SfaeError::ConfigError(
                "code cannot contain control characters".into(),
            ));
        }

        let len = code.chars().count();
        if len < self.min_length || len > self.max_length {
            return Err(SfaeError::ConfigError(format!(
                "code must be between {} and {} characters",
                self.min_length, self.max_length
            )));
        }

        match self.format {
            CodeFormat::Digits => {
                if !code.chars().all(|c| c.is_ascii_digit()) {
                    return Err(SfaeError::ConfigError(
                        "code must contain only ASCII digits".into(),
                    ));
                }
            }
            CodeFormat::Alnum => {
                if !code.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(SfaeError::ConfigError(
                        "code must contain only ASCII letters and digits".into(),
                    ));
                }
            }
            CodeFormat::Text => {}
        }

        Ok(code.to_string())
    }

    pub fn timeout_secs(&self) -> u64 {
        self.timeout.as_secs()
    }
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(format: CodeFormat) -> CodeRequest {
        CodeRequest {
            domain: "example.com".to_string(),
            label: None,
            message: None,
            help_url: None,
            format,
            min_length: 4,
            max_length: 8,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    #[test]
    fn parses_formats() {
        assert_eq!(CodeFormat::parse("digits").unwrap(), CodeFormat::Digits);
        assert_eq!(CodeFormat::parse("alnum").unwrap(), CodeFormat::Alnum);
        assert_eq!(CodeFormat::parse("text").unwrap(), CodeFormat::Text);
        assert!(CodeFormat::parse("hex").is_err());
    }

    #[test]
    fn validates_digits() {
        let req = request(CodeFormat::Digits);
        assert_eq!(req.normalize_code(" 123456 ").unwrap(), "123456");
        assert!(req.normalize_code("12ab").is_err());
        assert!(req.normalize_code("123").is_err());
        assert!(req.normalize_code("123456789").is_err());
    }

    #[test]
    fn validates_alnum() {
        let req = request(CodeFormat::Alnum);
        assert_eq!(req.normalize_code("AB12").unwrap(), "AB12");
        assert!(req.normalize_code("AB-12").is_err());
    }

    #[test]
    fn text_rejects_control_characters() {
        let req = request(CodeFormat::Text);
        assert_eq!(req.normalize_code("AB-12").unwrap(), "AB-12");
        assert!(req.normalize_code("AB\n12").is_err());
    }

    #[test]
    fn config_rejects_invalid_url_and_lengths() {
        let mut req = request(CodeFormat::Digits);
        req.help_url = Some("file:///tmp/code".to_string());
        assert!(req.validate().is_err());

        req.help_url = None;
        req.min_length = 9;
        assert!(req.validate().is_err());

        req.min_length = 1;
        req.max_length = MAX_CODE_LENGTH + 1;
        assert!(req.validate().is_err());

        req.max_length = 6;
        req.timeout = Duration::MAX;
        assert!(req.validate().is_err());
    }
}
