//! Regression tests for the bundled skill installation and refresh behavior.

use assert_cmd::Command;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn install_skill_writes_embedded_files_to_custom_target() {
    let tmp_dir = unique_temp_dir();
    fs::create_dir(&tmp_dir).unwrap();

    Command::cargo_bin("sfae")
        .unwrap()
        .current_dir(&tmp_dir)
        .args(["install-skill", "--target", "agent-skill"])
        .assert()
        .success();

    let skill = fs::read_to_string(tmp_dir.join("agent-skill/SKILL.md")).unwrap();
    let installer = fs::read_to_string(tmp_dir.join("agent-skill/install.sh")).unwrap();
    assert!(skill.contains("SFAE API Credentials"));
    assert!(skill.contains("this skill folder contains `install.sh`"));
    assert!(installer.contains("brew install"));
    assert!(installer.contains("npm install -g"));

    let output = Command::cargo_bin("sfae")
        .unwrap()
        .current_dir(&tmp_dir)
        .args(["install-skill", "--target", "agent-skill"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("already up to date"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn existing_project_skill_is_silently_refreshed() {
    let tmp_dir = unique_temp_dir();
    let skill_dir = tmp_dir.join(".agents/skills/sfae");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(skill_dir.join("SKILL.md"), "old skill").unwrap();
    fs::write(skill_dir.join("install.sh"), "old installer").unwrap();

    Command::cargo_bin("sfae")
        .unwrap()
        .current_dir(&tmp_dir)
        .arg("--version")
        .assert()
        .success();

    let skill = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
    let installer = fs::read_to_string(skill_dir.join("install.sh")).unwrap();
    assert!(skill.contains("SFAE API Credentials"));
    assert!(installer.contains("fundamental-research-labs/sfae"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

fn unique_temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "sfae-distribution-test-{}-{unique}",
        std::process::id()
    ))
}
