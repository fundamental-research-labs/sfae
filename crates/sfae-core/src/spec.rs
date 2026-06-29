//! JSON spec types accepted by `sfae prompt --spec` for rendering credential forms.
//!
//! Defines `PromptSpec`, `FieldSpec`, `GroupSpec`, and `OAuthSpec` plus their
//! deserialization shorthands.

use serde::{Deserialize, Serialize};

use crate::error::SfaeError;

/// JSON spec for the `sfae prompt` command.
///
/// At least one of `fields` or `groups` must be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptSpec {
    /// Help link shown on the page (not a form field).
    #[serde(default, alias = "url")]
    pub help_url: Option<String>,

    /// Common fields — always visible above any group selector.
    #[serde(default)]
    pub fields: Option<Vec<FieldSpec>>,

    /// Alternative groups — user picks one.
    #[serde(default)]
    pub groups: Option<Vec<GroupSpec>>,
}

impl PromptSpec {
    /// Validate the spec after deserialization.
    pub fn validate(&self) -> Result<(), SfaeError> {
        let has_fields = self.fields.as_ref().is_some_and(|f| !f.is_empty());
        let has_groups = self.groups.as_ref().is_some_and(|g| !g.is_empty());

        if !has_fields && !has_groups {
            return Err(SfaeError::ConfigError(
                "spec must have at least one of \"fields\" or \"groups\"".into(),
            ));
        }

        if let Some(fields) = &self.fields {
            validate_field_names(fields)?;
        }

        if let Some(groups) = &self.groups {
            for group in groups {
                group.validate()?;
            }
        }

        Ok(())
    }
}

/// A single credential field in the spec.
///
/// Supports a string shorthand: `"API_KEY"` deserializes to
/// `FieldSpec { name: "API_KEY", label: None, default: None, secret: None, optional: None }`.
#[derive(Debug, Clone, Serialize)]
pub struct FieldSpec {
    /// Credential key — stored in the set and used in `{KEY}` placeholders.
    pub name: String,

    /// Display name (defaults to humanized `name`).
    #[serde(default)]
    pub label: Option<String>,

    /// Pre-filled value.
    #[serde(default)]
    pub default: Option<String>,

    /// Password input. Auto-detected if omitted: `true` unless name contains
    /// a known non-secret keyword (USERNAME, HOST, PORT, URL, EMAIL).
    #[serde(default)]
    pub secret: Option<bool>,

    /// Whether this field is optional. Optional fields may be left empty
    /// and will be omitted from the stored credential set when blank.
    #[serde(default)]
    pub optional: Option<bool>,
}

/// Names that are considered non-secret for `is_secret()` auto-detection.
const NON_SECRET_KEYWORDS: &[&str] = &["USERNAME", "HOST", "PORT", "URL", "EMAIL"];

impl FieldSpec {
    /// Validate that the field can be referenced by the request placeholder resolver.
    fn validate_name(&self) -> Result<(), SfaeError> {
        if is_placeholder_field_name(&self.name) {
            return Ok(());
        }
        Err(SfaeError::ConfigError(format!(
            "field name \"{}\" must match [A-Z][A-Z0-9_]* so it can be used as a {{{}}} placeholder",
            self.name,
            if self.name.is_empty() {
                "FIELD_NAME"
            } else {
                self.name.as_str()
            }
        )))
    }

    /// Whether this field should render as a password input.
    ///
    /// Uses the explicit `secret` flag if set; otherwise auto-detects based on
    /// whether the field name contains a known non-secret keyword.
    pub fn is_secret(&self) -> bool {
        if let Some(explicit) = self.secret {
            return explicit;
        }
        let upper = self.name.to_uppercase();
        !NON_SECRET_KEYWORDS.iter().any(|kw| upper.contains(kw))
    }

    /// Whether this field is optional (may be left empty).
    pub fn is_optional(&self) -> bool {
        self.optional.unwrap_or(false)
    }

    /// Display label for this field.
    ///
    /// Uses the explicit `label` if set; otherwise humanizes the name by
    /// replacing underscores with spaces and title-casing each word.
    /// Example: `ACCESS_TOKEN` → `"Access Token"`.
    pub fn display_label(&self) -> String {
        if let Some(label) = &self.label {
            return label.clone();
        }
        self.name
            .split('_')
            .filter(|s| !s.is_empty())
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => {
                        let mut out = first.to_uppercase().to_string();
                        out.extend(chars.map(|c| c.to_lowercase().next().unwrap_or(c)));
                        out
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl<'de> Deserialize<'de> for FieldSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct FieldSpecVisitor;

        impl<'de> de::Visitor<'de> for FieldSpecVisitor {
            type Value = FieldSpec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a string like \"API_KEY\" or an object with at least a \"name\" field",
                )
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(FieldSpec {
                    name: value.to_string(),
                    label: None,
                    default: None,
                    secret: None,
                    optional: None,
                })
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                #[derive(Deserialize)]
                struct FieldSpecObj {
                    name: String,
                    #[serde(default)]
                    label: Option<String>,
                    #[serde(default)]
                    default: Option<String>,
                    #[serde(default)]
                    secret: Option<bool>,
                    #[serde(default)]
                    optional: Option<bool>,
                }

                let obj = FieldSpecObj::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(FieldSpec {
                    name: obj.name,
                    label: obj.label,
                    default: obj.default,
                    secret: obj.secret,
                    optional: obj.optional,
                })
            }
        }

        deserializer.deserialize_any(FieldSpecVisitor)
    }
}

/// An alternative group — the user picks one among all groups.
///
/// A group has either `fields` (regular input fields) or `oauth` (OAuth flow),
/// not both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSpec {
    /// Tab/radio label (e.g. "Basic Auth", "OAuth").
    pub label: String,

    /// Regular input fields for this group.
    #[serde(default)]
    pub fields: Option<Vec<FieldSpec>>,

    /// OAuth flow for this group (mutually exclusive with `fields`).
    #[serde(default)]
    pub oauth: Option<OAuthSpec>,
}

impl GroupSpec {
    fn validate(&self) -> Result<(), SfaeError> {
        let has_fields = self.fields.as_ref().is_some_and(|f| !f.is_empty());
        let has_oauth = self.oauth.is_some();

        if has_fields && has_oauth {
            return Err(SfaeError::ConfigError(format!(
                "group \"{}\" cannot have both \"fields\" and \"oauth\"",
                self.label
            )));
        }

        if !has_fields && !has_oauth {
            return Err(SfaeError::ConfigError(format!(
                "group \"{}\" must have either \"fields\" or \"oauth\"",
                self.label
            )));
        }

        if let Some(fields) = &self.fields {
            validate_field_names(fields)?;
        }

        Ok(())
    }
}

fn validate_field_names(fields: &[FieldSpec]) -> Result<(), SfaeError> {
    for field in fields {
        field.validate_name()?;
    }
    Ok(())
}

fn is_placeholder_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Hosted OAuth flow configuration within a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthSpec {
    /// Hosted OAuth provider name. Defaults from the domain when possible.
    #[serde(default)]
    pub provider: Option<String>,

    /// Single scope string accepted for compact specs and compatibility.
    #[serde(default)]
    pub scope: Option<String>,

    /// Requested OAuth scopes. SFAE forwards arbitrary scope keys and lets the provider reject
    /// unknown, unavailable, or app-restricted scopes. Empty lets the hosted broker apply provider
    /// defaults.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthSpec {
    /// Return all requested scopes, splitting the legacy single-string `scope`.
    pub fn requested_scopes(&self) -> Vec<String> {
        let mut scopes = Vec::new();
        if let Some(scope) = &self.scope {
            scopes.extend(scope.split_whitespace().map(str::to_string));
        }
        scopes.extend(self.scopes.iter().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- FieldSpec deserialization ---

    #[test]
    fn field_spec_from_string() {
        let spec: FieldSpec = serde_json::from_str(r#""API_KEY""#).unwrap();
        assert_eq!(spec.name, "API_KEY");
        assert!(spec.label.is_none());
        assert!(spec.default.is_none());
        assert!(spec.secret.is_none());
    }

    #[test]
    fn field_spec_from_object() {
        let spec: FieldSpec = serde_json::from_str(
            r#"{"name": "HOST", "label": "Server URL", "default": "https://example.com", "secret": false}"#,
        )
        .unwrap();
        assert_eq!(spec.name, "HOST");
        assert_eq!(spec.label.as_deref(), Some("Server URL"));
        assert_eq!(spec.default.as_deref(), Some("https://example.com"));
        assert_eq!(spec.secret, Some(false));
    }

    #[test]
    fn field_spec_from_object_minimal() {
        let spec: FieldSpec = serde_json::from_str(r#"{"name": "PASSWORD"}"#).unwrap();
        assert_eq!(spec.name, "PASSWORD");
        assert!(spec.label.is_none());
        assert!(spec.default.is_none());
        assert!(spec.secret.is_none());
    }

    // --- is_secret() ---

    #[test]
    fn is_secret_auto_detect_secret() {
        let spec = FieldSpec {
            name: "ACCESS_TOKEN".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        assert!(spec.is_secret());
    }

    #[test]
    fn is_secret_auto_detect_password() {
        let spec = FieldSpec {
            name: "PASSWORD".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        // PASSWORD doesn't contain any NON_SECRET_KEYWORDS, so it's secret
        assert!(spec.is_secret());
    }

    #[test]
    fn is_secret_auto_detect_non_secret() {
        for name in &["USERNAME", "HOST", "PORT", "BASE_URL", "EMAIL"] {
            let spec = FieldSpec {
                name: name.to_string(),
                label: None,
                default: None,
                secret: None,
                optional: None,
            };
            assert!(
                !spec.is_secret(),
                "{name} should be auto-detected as non-secret"
            );
        }
    }

    #[test]
    fn is_secret_auto_detect_case_insensitive() {
        let spec = FieldSpec {
            name: "smtp_host".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        assert!(!spec.is_secret());
    }

    #[test]
    fn is_secret_explicit_override() {
        let spec = FieldSpec {
            name: "USERNAME".into(),
            label: None,
            default: None,
            secret: Some(true),
            optional: None,
        };
        assert!(spec.is_secret());
    }

    // --- is_optional() ---

    #[test]
    fn is_optional_default_false() {
        let spec: FieldSpec = serde_json::from_str(r#""API_KEY""#).unwrap();
        assert!(!spec.is_optional());
    }

    #[test]
    fn is_optional_explicit_true() {
        let spec: FieldSpec =
            serde_json::from_str(r#"{"name": "PROJECT_ID", "optional": true}"#).unwrap();
        assert!(spec.is_optional());
    }

    #[test]
    fn is_optional_explicit_false() {
        let spec: FieldSpec =
            serde_json::from_str(r#"{"name": "API_KEY", "optional": false}"#).unwrap();
        assert!(!spec.is_optional());
    }

    // --- display_label() ---

    #[test]
    fn display_label_humanizes_name() {
        let spec = FieldSpec {
            name: "ACCESS_TOKEN".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        assert_eq!(spec.display_label(), "Access Token");
    }

    #[test]
    fn display_label_single_word() {
        let spec = FieldSpec {
            name: "PASSWORD".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        assert_eq!(spec.display_label(), "Password");
    }

    #[test]
    fn display_label_explicit_label() {
        let spec = FieldSpec {
            name: "HOST".into(),
            label: Some("Server URL".into()),
            default: None,
            secret: None,
            optional: None,
        };
        assert_eq!(spec.display_label(), "Server URL");
    }

    #[test]
    fn display_label_three_words() {
        let spec = FieldSpec {
            name: "SMTP_SERVER_HOST".into(),
            label: None,
            default: None,
            secret: None,
            optional: None,
        };
        assert_eq!(spec.display_label(), "Smtp Server Host");
    }

    // --- PromptSpec validation ---

    #[test]
    fn validate_fields_only() {
        let spec: PromptSpec = serde_json::from_str(r#"{"fields": ["API_KEY"]}"#).unwrap();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_groups_only() {
        let spec: PromptSpec =
            serde_json::from_str(r#"{"groups": [{"label": "OAuth", "oauth": {"scope": "read"}}]}"#)
                .unwrap();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_both_fields_and_groups() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{"fields": ["URL"], "groups": [{"label": "Key", "fields": ["API_KEY"]}]}"#,
        )
        .unwrap();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_neither_fields_nor_groups() {
        let spec: PromptSpec = serde_json::from_str(r#"{}"#).unwrap();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_empty_fields_and_no_groups() {
        let spec: PromptSpec = serde_json::from_str(r#"{"fields": []}"#).unwrap();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_field_name() {
        let spec: PromptSpec = serde_json::from_str(r#"{"fields": [""]}"#).unwrap();
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("[A-Z][A-Z0-9_]*"));
    }

    #[test]
    fn validate_rejects_lowercase_field_name() {
        let spec: PromptSpec = serde_json::from_str(r#"{"fields": ["api_key"]}"#).unwrap();
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("api_key"));
    }

    #[test]
    fn validate_rejects_hyphenated_group_field_name() {
        let spec: PromptSpec =
            serde_json::from_str(r#"{"groups": [{"label": "Key", "fields": ["API-KEY"]}]}"#)
                .unwrap();
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("API-KEY"));
    }

    #[test]
    fn validate_accepts_placeholder_field_names() {
        let spec: PromptSpec =
            serde_json::from_str(r#"{"fields": ["API_KEY", "TOKEN2", "A_1"]}"#).unwrap();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_group_with_both_fields_and_oauth() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{"groups": [{"label": "Bad", "fields": ["KEY"], "oauth": {"scope": "read"}}]}"#,
        )
        .unwrap();
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("cannot have both"));
    }

    #[test]
    fn validate_group_with_neither_fields_nor_oauth() {
        let spec: PromptSpec = serde_json::from_str(r#"{"groups": [{"label": "Empty"}]}"#).unwrap();
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("must have either"));
    }

    // --- Full spec deserialization (plan examples) ---

    #[test]
    fn example_1_simple_api_key() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{
            "help_url": "https://github.com/settings/tokens",
            "fields": ["ACCESS_TOKEN"]
        }"#,
        )
        .unwrap();
        spec.validate().unwrap();
        assert_eq!(
            spec.help_url.as_deref(),
            Some("https://github.com/settings/tokens")
        );
        let fields = spec.fields.unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "ACCESS_TOKEN");
        assert!(fields[0].is_secret());
        assert_eq!(fields[0].display_label(), "Access Token");
    }

    #[test]
    fn example_2_multi_field() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{
            "fields": [
                {"name": "HOST", "label": "Server URL", "default": "db.example.com"},
                {"name": "USERNAME", "label": "Database User"},
                {"name": "PASSWORD"}
            ]
        }"#,
        )
        .unwrap();
        spec.validate().unwrap();
        let fields = spec.fields.unwrap();
        assert_eq!(fields.len(), 3);
        assert!(!fields[0].is_secret()); // HOST
        assert!(!fields[1].is_secret()); // USERNAME
        assert!(fields[2].is_secret()); // PASSWORD
    }

    #[test]
    fn example_3_alternative_groups() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{
            "help_url": "https://example.com/developers",
            "fields": [
                {"name": "URL", "label": "API Endpoint", "default": "https://api.example.com/v2"}
            ],
            "groups": [
                {"label": "Basic Auth", "fields": ["USERNAME", "PASSWORD"]},
                {"label": "API Key", "fields": [{"name": "API_KEY", "label": "Developer API Key"}]}
            ]
        }"#,
        )
        .unwrap();
        spec.validate().unwrap();
        let groups = spec.groups.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "Basic Auth");
        assert_eq!(groups[1].label, "API Key");
    }

    #[test]
    fn example_4_oauth_as_alternative() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{
            "groups": [
                {"label": "API Key", "fields": [{"name": "API_KEY", "label": "Discord API Key"}]},
                {"label": "OAuth", "oauth": {"provider": "discord", "scopes": ["scope.read"]}}
            ]
        }"#,
        )
        .unwrap();
        spec.validate().unwrap();
        let groups = spec.groups.unwrap();
        assert!(groups[0].oauth.is_none());
        assert!(groups[0].fields.is_some());
        assert!(groups[1].oauth.is_some());
        assert_eq!(
            groups[1].oauth.as_ref().unwrap().provider.as_deref(),
            Some("discord")
        );
        assert_eq!(
            groups[1].oauth.as_ref().unwrap().requested_scopes(),
            vec!["scope.read"]
        );
    }

    #[test]
    fn oauth_rejects_provider_endpoint_fields() {
        let err = serde_json::from_str::<PromptSpec>(
            r#"{
            "groups": [
                {
                    "label": "OAuth",
                    "oauth": {
                        "auth_url": "https://login.custom-saas.com/oauth/authorize",
                        "token_url": "https://login.custom-saas.com/oauth/token",
                        "revocation_url": "https://login.custom-saas.com/oauth/revoke",
                        "scope": "api.read api.write"
                    }
                }
            ]
        }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn example_6_oauth_only_with_defaults() {
        let spec: PromptSpec = serde_json::from_str(
            r#"{
            "groups": [
                {"label": "OAuth", "oauth": {"scope": "scope.write scope.read"}}
            ]
        }"#,
        )
        .unwrap();
        spec.validate().unwrap();
        let groups = spec.groups.unwrap();
        let oauth = groups[0].oauth.as_ref().unwrap();
        assert!(oauth.provider.is_none());
        assert_eq!(oauth.requested_scopes(), vec!["scope.read", "scope.write"]);
    }

    // --- FieldSpec serialization roundtrip ---

    #[test]
    fn field_spec_roundtrip() {
        let original = FieldSpec {
            name: "API_KEY".into(),
            label: Some("My Key".into()),
            default: Some("default-val".into()),
            secret: Some(true),
            optional: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FieldSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "API_KEY");
        assert_eq!(parsed.label.as_deref(), Some("My Key"));
        assert_eq!(parsed.default.as_deref(), Some("default-val"));
        assert_eq!(parsed.secret, Some(true));
    }
}
