/// Supported credential types.
#[derive(Debug, Clone)]
pub enum Credential {
    /// A simple bearer / access token.
    AccessToken { token: String },
    // Future: OAuth2, API key + secret, etc.
}
