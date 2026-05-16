//! Smoke test verifying that `--version` prints whatever name the binary was invoked under.

use assert_cmd::Command;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn version_output_uses_executable_name() {
    let bin_path = assert_cmd::cargo::cargo_bin("sfae");

    // Copy the binary under a different name
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tmp_dir =
        std::env::temp_dir().join(format!("sfae-test-version-{}-{unique}", std::process::id()));
    fs::create_dir(&tmp_dir).unwrap();
    let renamed = tmp_dir.join("myprog");
    fs::copy(&bin_path, &renamed).unwrap();

    // Run the renamed binary with --version
    let output = Command::new(&renamed)
        .arg("--version")
        .output()
        .expect("failed to run renamed binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "renamed binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("myprog "),
        "expected version output to start with 'myprog ', got: {stdout}"
    );

    // Clean up
    let _ = fs::remove_dir_all(&tmp_dir);
}
