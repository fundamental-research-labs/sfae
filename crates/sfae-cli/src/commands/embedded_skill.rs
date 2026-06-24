//! Embedded agent skill files and helpers for writing them into project-local skill directories.

use std::fs;
use std::path::{Path, PathBuf};

pub const SKILL_MD: &str = include_str!("../../../../skill/SKILL.md");
pub const INSTALL_SH: &str = include_str!("../../../../skill/install.sh");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStatus {
    Installed,
    Updated,
    Unchanged,
}

#[derive(Debug, Clone)]
pub struct WriteResult {
    pub path: PathBuf,
    pub status: WriteStatus,
}

pub struct WriteRequest<'a> {
    pub dest: &'a Path,
}

pub fn write(request: WriteRequest<'_>) -> anyhow::Result<WriteResult> {
    let dest = request.dest;
    remove_broken_symlink(dest)?;
    if dest.exists() && !dest.is_dir() {
        anyhow::bail!(
            "cannot install skill at {} because a non-directory file already exists there",
            dest.display()
        );
    }

    let had_skill = dest.join("SKILL.md").is_file();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(dest)?;

    let mut changed = false;
    changed |= write_file_if_changed(FileWrite {
        path: dest.join("SKILL.md"),
        contents: SKILL_MD.as_bytes(),
    })?;
    changed |= write_file_if_changed(FileWrite {
        path: dest.join("install.sh"),
        contents: INSTALL_SH.as_bytes(),
    })?;
    changed |= ensure_installer_executable(&dest.join("install.sh"))?;

    let status = if !changed {
        WriteStatus::Unchanged
    } else if had_skill {
        WriteStatus::Updated
    } else {
        WriteStatus::Installed
    };

    Ok(WriteResult {
        path: dest.to_path_buf(),
        status,
    })
}

fn remove_broken_symlink(path: &Path) -> anyhow::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() && !path.is_dir() {
        fs::remove_file(path)?;
    }
    Ok(())
}

struct FileWrite<'a> {
    path: PathBuf,
    contents: &'a [u8],
}

fn write_file_if_changed(write: FileWrite<'_>) -> anyhow::Result<bool> {
    if fs::read(&write.path).is_ok_and(|existing| existing == write.contents) {
        return Ok(false);
    }
    fs::write(write.path, write.contents)?;
    Ok(true)
}

#[cfg(unix)]
fn ensure_installer_executable(path: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if mode & 0o111 != 0 {
        return Ok(false);
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode | 0o755);
    fs::set_permissions(path, permissions)?;
    Ok(true)
}

#[cfg(not(unix))]
fn ensure_installer_executable(_path: &Path) -> anyhow::Result<bool> {
    Ok(false)
}
