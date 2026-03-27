/// Description of an external service the agent can interact with.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Unique identifier, e.g. "github", "dropbox"
    pub id: String,
    /// Human-readable name
    pub display_name: String,
    /// Base URL for the service API
    pub base_url: String,
}
