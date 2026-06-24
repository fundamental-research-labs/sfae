//! Install and refresh the bundled SFAE agent skill in project-local agent directories.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use super::embedded_skill::{self, WriteRequest, WriteStatus};

const DEFAULT_SKILL_NAME: &str = "sfae";

pub struct RunArgs {
    pub codex: bool,
    pub claude: bool,
    pub grok: bool,
    pub all: bool,
    pub custom_targets: Vec<String>,
    pub name: String,
    pub install_cli: bool,
}

pub fn run(args: RunArgs) -> anyhow::Result<()> {
    let targets = selected_targets(&args);
    let mut first_path = None;
    for path in targets {
        let result = embedded_skill::write(WriteRequest { dest: &path })?;
        match result.status {
            WriteStatus::Installed => println!("Installed sfae skill: {}", result.path.display()),
            WriteStatus::Updated => println!("Updated sfae skill: {}", result.path.display()),
            WriteStatus::Unchanged => {
                println!("sfae skill already up to date: {}", result.path.display());
            }
        }
        first_path.get_or_insert(result.path);
    }

    if let Some(path) = first_path {
        if args.install_cli {
            run_skill_installer(path)?;
        } else {
            println!(
                "The skill will use {}/install.sh if the sfae command is not available.",
                path.display()
            );
        }
    }
    Ok(())
}

pub fn auto_refresh_existing() {
    if std::env::var("SFAE_SKILL_AUTO_UPDATE").is_ok_and(|value| value == "off") {
        return;
    }

    for target in ["codex", "claude", "grok"] {
        let path = target_path(TargetPath {
            target,
            name: DEFAULT_SKILL_NAME,
        });
        if path.join("SKILL.md").is_file() {
            let _ = embedded_skill::write(WriteRequest { dest: &path });
        }
    }
}

fn selected_targets(args: &RunArgs) -> Vec<PathBuf> {
    let mut names = Vec::new();
    if args.all || no_targets_requested(args) {
        names.extend([
            "codex".to_string(),
            "claude".to_string(),
            "grok".to_string(),
        ]);
    } else {
        if args.codex {
            names.push("codex".to_string());
        }
        if args.claude {
            names.push("claude".to_string());
        }
        if args.grok {
            names.push("grok".to_string());
        }
    }
    names.extend(args.custom_targets.iter().cloned());

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for target in names {
        let path = target_path(TargetPath {
            target: &target,
            name: &args.name,
        });
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

fn no_targets_requested(args: &RunArgs) -> bool {
    !args.codex && !args.claude && !args.grok && !args.all && args.custom_targets.is_empty()
}

struct TargetPath<'a> {
    target: &'a str,
    name: &'a str,
}

fn target_path(args: TargetPath<'_>) -> PathBuf {
    match args.target {
        "codex" => [".agents", "skills", args.name].iter().collect(),
        "claude" => [".claude", "skills", args.name].iter().collect(),
        "grok" => [".grok", "skills", args.name].iter().collect(),
        custom => PathBuf::from(custom),
    }
}

fn run_skill_installer(path: PathBuf) -> anyhow::Result<()> {
    let installer = path.join("install.sh");
    let status = Command::new("sh").arg(&installer).status()?;
    if !status.success() {
        anyhow::bail!("{} failed with status {status}", installer.display());
    }
    Ok(())
}
