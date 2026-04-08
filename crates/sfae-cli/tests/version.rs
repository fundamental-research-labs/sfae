use assert_cmd::Command;
use std::fs;

#[test]
fn version_output_uses_executable_name() {
    let bin_path = assert_cmd::cargo::cargo_bin("sfae");

    // Copy the binary under a different name
    let tmp_dir = std::env::temp_dir().join("sfae-test-version");
    fs::create_dir_all(&tmp_dir).unwrap();
    let renamed = tmp_dir.join("myprog");
    fs::copy(&bin_path, &renamed).unwrap();

    // Run the renamed binary with --version
    let output = Command::new(&renamed)
        .arg("--version")
        .output()
        .expect("failed to run renamed binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("myprog "),
        "expected version output to start with 'myprog ', got: {stdout}"
    );

    // Clean up
    let _ = fs::remove_dir_all(&tmp_dir);
}
