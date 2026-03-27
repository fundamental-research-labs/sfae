use crate::error::SfaeError;

/// Abstraction over user interaction, allowing the CLI to prompt for input
/// while tests can supply canned responses.
pub trait UserPrompt {
    /// Display a prompt and read a line of input.
    fn prompt(&self, message: &str) -> Result<String, SfaeError>;

    /// Display a prompt and read a secret (input not echoed).
    fn prompt_secret(&self, message: &str) -> Result<String, SfaeError>;

    /// Ask a yes/no confirmation question. Returns `true` for yes.
    fn confirm(&self, message: &str) -> Result<bool, SfaeError>;
}
