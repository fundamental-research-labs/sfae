/// A handle to a stored secret. The actual value is never exposed to the agent.
/// Only the placeholder name is visible; resolution happens at proxy time.
#[derive(Debug, Clone)]
pub struct SecretHandle {
    /// Human-readable label, e.g. "dropbox_access_token"
    pub name: String,
}
