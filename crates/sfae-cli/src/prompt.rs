use std::io::{self, BufRead, Write};

use sfae_core::error::SfaeError;
use sfae_core::ui::UserPrompt;

/// Terminal-based user prompt using stdin/stderr and rpassword for secrets.
pub struct TerminalPrompt;

impl UserPrompt for TerminalPrompt {
    fn prompt(&self, message: &str) -> Result<String, SfaeError> {
        eprint!("{message}: ");
        io::stderr()
            .flush()
            .map_err(|e| SfaeError::Other(e.to_string()))?;
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| SfaeError::Other(e.to_string()))?;
        Ok(line.trim_end().to_string())
    }

    fn prompt_secret(&self, message: &str) -> Result<String, SfaeError> {
        eprint!("{message}: ");
        io::stderr()
            .flush()
            .map_err(|e| SfaeError::Other(e.to_string()))?;
        rpassword::read_password().map_err(|e| SfaeError::Other(e.to_string()))
    }

    fn confirm(&self, message: &str) -> Result<bool, SfaeError> {
        eprint!("{message} [y/N]: ");
        io::stderr()
            .flush()
            .map_err(|e| SfaeError::Other(e.to_string()))?;
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| SfaeError::Other(e.to_string()))?;
        Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
    }
}
