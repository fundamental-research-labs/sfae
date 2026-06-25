//! Self-update support for Homebrew, npm, and direct-installer SFAE installations.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMethod {
    Brew,
    Npm,
    Direct,
}

pub fn run() -> anyhow::Result<()> {
    match detect_install_method() {
        InstallMethod::Brew => update_brew(),
        InstallMethod::Npm => update_npm(),
        InstallMethod::Direct => update_direct(),
    }
}

fn detect_install_method() -> InstallMethod {
    if let Some(method) = forced_install_method() {
        return method;
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(""));
    if looks_like_npm(&exe) {
        return InstallMethod::Npm;
    }
    if looks_like_brew(&exe) || brew_owns_current_exe(&exe) {
        return InstallMethod::Brew;
    }
    InstallMethod::Direct
}

fn forced_install_method() -> Option<InstallMethod> {
    let value = std::env::var("SFAE_UPDATE_METHOD")
        .or_else(|_| std::env::var("SFAE_INSTALL_METHOD"))
        .ok()?;
    match value.as_str() {
        "brew" | "homebrew" => Some(InstallMethod::Brew),
        "npm" => Some(InstallMethod::Npm),
        "direct" | "standalone" => Some(InstallMethod::Direct),
        _ => None,
    }
}

fn looks_like_npm(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("node_modules") || text.contains("/npm/bin/sfae")
}

fn looks_like_brew(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/Cellar/sfae/") || text.contains("/Homebrew/Cellar/sfae/")
}

fn brew_owns_current_exe(path: &Path) -> bool {
    let formula = std::env::var("SFAE_BREW_FORMULA").unwrap_or_else(|_| "sfae".to_string());
    let formula_prefix = brew_prefix(PrefixRequest { formula: &formula });
    if formula_prefix
        .as_ref()
        .is_some_and(|prefix| path_starts_with(PathPair { path, prefix }))
    {
        return true;
    }

    let Some(homebrew_prefix) = brew_prefix(PrefixRequest { formula: "" }) else {
        return false;
    };
    path == homebrew_prefix.join("bin/sfae")
}

struct PrefixRequest<'a> {
    formula: &'a str,
}

fn brew_prefix(request: PrefixRequest<'_>) -> Option<PathBuf> {
    let mut command = Command::new("brew");
    command.arg("--prefix");
    if !request.formula.is_empty() {
        command.arg(request.formula);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let prefix = PathBuf::from(text.trim());
    if prefix.as_os_str().is_empty() {
        None
    } else {
        Some(prefix)
    }
}

struct PathPair<'a> {
    path: &'a Path,
    prefix: &'a Path,
}

fn path_starts_with(pair: PathPair<'_>) -> bool {
    pair.path.starts_with(pair.prefix)
        || canonical_path(pair.path).is_some_and(|path| {
            canonical_path(pair.prefix).is_some_and(|prefix| path.starts_with(prefix))
        })
}

fn canonical_path(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

fn update_brew() -> anyhow::Result<()> {
    let formula = std::env::var("SFAE_BREW_FORMULA").unwrap_or_else(|_| "sfae".to_string());
    run_command(CommandSpec {
        program: OsString::from("brew"),
        args: vec![OsString::from("update")],
    })?;
    run_command(CommandSpec {
        program: OsString::from("brew"),
        args: vec![OsString::from("upgrade"), OsString::from(formula)],
    })
}

fn update_npm() -> anyhow::Result<()> {
    let package = std::env::var("SFAE_NPM_PACKAGE")
        .unwrap_or_else(|_| "@fundamental-research-labs/sfae".to_string());
    run_command(CommandSpec {
        program: OsString::from("npm"),
        args: vec![
            OsString::from("install"),
            OsString::from("-g"),
            latest_package(package),
        ],
    })
}

fn latest_package(package: String) -> OsString {
    OsString::from(format!("{package}@latest"))
}

fn update_direct() -> anyhow::Result<()> {
    let repo =
        std::env::var("SFAE_REPO").unwrap_or_else(|_| "fundamental-research-labs/sfae".to_string());
    let url = match std::env::var("SFAE_INSTALL_URL") {
        Ok(url) if !url.is_empty() => url,
        _ if repo == "fundamental-research-labs/sfae" => "https://sfae.io/install.sh".to_string(),
        _ => format!("https://raw.githubusercontent.com/{repo}/main/install.sh"),
    };
    let script_path = temp_script_path();
    let install_dir = current_install_dir()?;

    run_command(CommandSpec {
        program: OsString::from("curl"),
        args: vec![
            OsString::from("-fsSL"),
            OsString::from(url),
            OsString::from("-o"),
            script_path.as_os_str().to_os_string(),
        ],
    })?;

    let result = Command::new("sh")
        .arg(&script_path)
        .env("SFAE_INSTALL_DIR", install_dir)
        .status();
    let _ = std::fs::remove_file(&script_path);

    let status = result?;
    if !status.success() {
        anyhow::bail!("direct installer failed with status {status}");
    }
    Ok(())
}

fn current_install_dir() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("cannot determine current sfae install directory"))
}

fn temp_script_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sfae-install-{}-{unique}.sh", std::process::id()))
}

struct CommandSpec {
    program: OsString,
    args: Vec<OsString>,
}

fn run_command(spec: CommandSpec) -> anyhow::Result<()> {
    let status = Command::new(&spec.program).args(&spec.args).status()?;
    if !status.success() {
        anyhow::bail!(
            "{} failed with status {status}",
            spec.program.to_string_lossy()
        );
    }
    Ok(())
}
