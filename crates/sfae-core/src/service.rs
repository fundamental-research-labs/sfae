use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::SfaeError;
use crate::store::config_dir;

/// Description of an external service the agent can interact with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Unique identifier, e.g. "github", "dropbox"
    pub id: String,
    /// Human-readable name
    pub display_name: String,
    /// Base URL for the service API
    pub base_url: String,
}

/// Manages service configurations persisted to `~/.config/sfae/services.json`.
pub struct ServiceRegistry;

impl ServiceRegistry {
    fn path() -> Result<std::path::PathBuf, SfaeError> {
        Ok(config_dir()?.join("services.json"))
    }

    fn read_all() -> Result<Vec<ServiceConfig>, SfaeError> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&path)?;
        let services: Vec<ServiceConfig> = serde_json::from_str(&data)?;
        Ok(services)
    }

    fn write_all(services: &[ServiceConfig]) -> Result<(), SfaeError> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(services)?;
        fs::write(&path, data)?;
        Ok(())
    }

    /// Add or update a service configuration.
    pub fn add(config: ServiceConfig) -> Result<(), SfaeError> {
        let mut services = Self::read_all()?;
        services.retain(|s| s.id != config.id);
        services.push(config);
        services.sort_by(|a, b| a.id.cmp(&b.id));
        Self::write_all(&services)
    }

    /// Get a service configuration by id.
    pub fn get(id: &str) -> Result<ServiceConfig, SfaeError> {
        let services = Self::read_all()?;
        services
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| SfaeError::ServiceNotFound(id.to_string()))
    }

    /// List all service configurations.
    pub fn list() -> Result<Vec<ServiceConfig>, SfaeError> {
        Self::read_all()
    }

    /// Remove a service configuration by id.
    pub fn remove(id: &str) -> Result<(), SfaeError> {
        let mut services = Self::read_all()?;
        let len_before = services.len();
        services.retain(|s| s.id != id);
        if services.len() == len_before {
            return Err(SfaeError::ServiceNotFound(id.to_string()));
        }
        Self::write_all(&services)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_config_serialize_roundtrip() {
        let config = ServiceConfig {
            id: "github".to_string(),
            display_name: "GitHub".to_string(),
            base_url: "https://api.github.com".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServiceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "github");
        assert_eq!(deserialized.display_name, "GitHub");
        assert_eq!(deserialized.base_url, "https://api.github.com");
    }
}
