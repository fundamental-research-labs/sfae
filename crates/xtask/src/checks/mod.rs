//! Shared infrastructure (file walker, `Violation` type) for the in-tree lint checks.

use std::path::{Path, PathBuf};

pub mod file_docs;
pub mod file_lines;
pub mod function_params;

#[derive(Debug, Clone)]
pub struct Violation {
    pub path: PathBuf,
    pub line: usize,
    pub message: String,
}

pub fn walk() -> Vec<PathBuf> {
    let mut walker = Walker { out: Vec::new() };
    let crates_dir = workspace_root().join("crates");
    if let Ok(entries) = std::fs::read_dir(&crates_dir) {
        for entry in entries.flatten() {
            let crate_dir = entry.path();
            for sub in ["src", "tests"] {
                walker.visit(&crate_dir.join(sub));
            }
        }
    }
    walker.out.sort();
    walker.out
}

struct Walker {
    out: Vec<PathBuf>,
}

impl Walker {
    fn visit(&mut self, dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if is_fixture_dir(&path) {
                    continue;
                }
                self.visit(&path);
            } else if is_rs_source(&path) {
                self.out.push(path);
            }
        }
    }
}

fn is_fixture_dir(path: &Path) -> bool {
    path.file_name().and_then(|s| s.to_str()) == Some("fixtures")
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            == Some("tests")
}

fn is_rs_source(path: &Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) != Some("rs") {
        return false;
    }
    path.file_name().and_then(|s| s.to_str()) != Some("build.rs")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn run_all(files: &[PathBuf]) -> Vec<Violation> {
    let mut all = Vec::new();
    all.extend(file_lines::run(files));
    all.extend(file_docs::run(files));
    all.extend(function_params::run(files));
    all
}
