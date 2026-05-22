//! `sfae code`: request a transient one-time verification code from the user.

use std::time::Duration;

use sfae_core::code::{CodeFormat, CodeRequest, DEFAULT_MAX_LENGTH, DEFAULT_MIN_LENGTH};

/// All inputs for `code::run`.
pub struct RunArgs<'a> {
    pub domain: &'a str,
    pub label: Option<&'a str>,
    pub message: Option<&'a str>,
    pub help_url: Option<&'a str>,
    pub format: &'a str,
    pub length: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub timeout_secs: u64,
}

pub fn run(args: RunArgs<'_>) -> anyhow::Result<()> {
    let RunArgs {
        domain,
        label,
        message,
        help_url,
        format,
        length,
        min_length,
        max_length,
        timeout_secs,
    } = args;

    if length.is_some() && (min_length.is_some() || max_length.is_some()) {
        anyhow::bail!("--length cannot be combined with --min-length or --max-length");
    }

    let (min_length, max_length) = match length {
        Some(length) => (length, length),
        None => (
            min_length.unwrap_or(DEFAULT_MIN_LENGTH),
            max_length.unwrap_or(DEFAULT_MAX_LENGTH),
        ),
    };

    let request = CodeRequest {
        domain: domain.to_string(),
        label: label.map(str::to_string),
        message: message.map(str::to_string),
        help_url: help_url.map(str::to_string),
        format: CodeFormat::parse(format)?,
        min_length,
        max_length,
        timeout: Duration::from_secs(timeout_secs),
    };
    request.validate()?;

    eprintln!(
        "Opening browser for one-time code collection. This request times out after {}s.",
        request.timeout_secs()
    );
    let code = sfae_core::browser::browser_code_request(request)?;
    println!("{code}");
    Ok(())
}
