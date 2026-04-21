//! Lint check: no `.rs` file may exceed the per-file line-count limit (1000 lines).

use std::path::PathBuf;

use super::Violation;

const LIMIT: usize = 1000;

pub fn run(files: &[PathBuf]) -> Vec<Violation> {
    let mut out = Vec::new();
    for path in files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let lines = count_lines(&bytes);
        if lines > LIMIT {
            out.push(Violation {
                path: path.clone(),
                line: lines,
                message: format!("{lines} lines (limit {LIMIT})"),
            });
        }
    }
    out
}

fn count_lines(bytes: &[u8]) -> usize {
    let newlines = bytes.iter().filter(|&&b| b == b'\n').count();
    if bytes.last().is_some_and(|&b| b != b'\n') {
        newlines + 1
    } else {
        newlines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_trailing_newline() {
        assert_eq!(count_lines(b""), 0);
        assert_eq!(count_lines(b"a\n"), 1);
        assert_eq!(count_lines(b"a\nb"), 2);
        assert_eq!(count_lines(b"a\nb\n"), 2);
    }

    #[test]
    fn flags_files_over_limit() {
        let big = "x\n".repeat(LIMIT + 5);
        let bytes = big.into_bytes();
        let n = count_lines(&bytes);
        assert!(n > LIMIT);
    }

    #[test]
    fn does_not_flag_at_limit() {
        let exact = "x\n".repeat(LIMIT);
        assert_eq!(count_lines(exact.as_bytes()), LIMIT);
    }
}
