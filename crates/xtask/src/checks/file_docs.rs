use std::path::PathBuf;

use super::Violation;

const MIN_PROSE: usize = 40;

pub fn run(files: &[PathBuf]) -> Vec<Violation> {
    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(message) = inspect(&text) {
            out.push(Violation {
                path: path.clone(),
                line: 1,
                message,
            });
        }
    }
    out
}

fn inspect(text: &str) -> Option<String> {
    let mut prose = String::new();
    let mut saw_doc = false;

    for raw in text.lines() {
        let line = raw.trim_start();
        if line.is_empty() {
            if saw_doc {
                break;
            }
            continue;
        }
        if line.starts_with("#![") {
            // Inner attribute; allowed before the docstring.
            if saw_doc {
                break;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("//!") {
            saw_doc = true;
            let trimmed = rest.strip_prefix(' ').unwrap_or(rest).trim();
            if !prose.is_empty() {
                prose.push(' ');
            }
            prose.push_str(trimmed);
            continue;
        }
        // First non-blank, non-attr, non-//! line.
        break;
    }

    if !saw_doc {
        return Some("missing top-of-file `//!` docstring".into());
    }
    if prose.chars().count() < MIN_PROSE {
        return Some(format!(
            "top-of-file docstring too short: {} chars (need {MIN_PROSE})",
            prose.chars().count()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_docstring_is_flagged() {
        let v = inspect("use std::io;\n");
        assert!(v.unwrap().contains("missing"));
    }

    #[test]
    fn short_docstring_is_flagged() {
        let v = inspect("//! tiny.\n");
        assert!(v.unwrap().contains("too short"));
    }

    #[test]
    fn long_docstring_passes() {
        let v = inspect("//! Secret storage abstractions for SFAE — keychain glue.\n");
        assert!(v.is_none(), "expected pass, got {v:?}");
    }

    #[test]
    fn inner_attribute_before_doc_is_allowed() {
        let src = "#![allow(clippy::too_many_arguments)]\n//! This is the module docstring describing things.\n";
        assert!(inspect(src).is_none());
    }

    #[test]
    fn multi_line_doc_block_concatenates() {
        let src =
            "//! one short line\n//! second short line that brings us comfortably past forty.\n";
        assert!(inspect(src).is_none());
    }

    #[test]
    fn blank_lines_before_doc_are_skipped() {
        let src = "\n\n//! Long enough docstring describing this little file.\n";
        assert!(inspect(src).is_none());
    }
}
