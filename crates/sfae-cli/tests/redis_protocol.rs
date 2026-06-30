//! Integration coverage for Redis protocol requests through the SFAE CLI.
//!
//! The test uses a real password-protected Redis container and a mock remote
//! credential store so it can verify masked previews, command execution,
//! credential deletion failure, and teardown.

use std::thread;
use std::time::Duration;

mod support;

use support::{
    CREDENTIAL_ID, CommandOutputCtx, DockerArgs, MockCredentialStore, assert_success,
    command_with_store, container_endpoint, docker, docker_available, unique_name,
};

const REDIS_PASSWORD: &str = "sfae_redis_password";
const REDIS_VALUE: &str = "cached from sfae";

#[test]
fn redis_request_uses_stored_credentials_until_deleted() {
    if !docker_available() {
        eprintln!("skipping redis protocol integration test: docker is unavailable");
        return;
    }

    let mut redis = RedisContainer::start();
    wait_for_redis(&redis);
    redis.refresh_endpoint();

    let store = MockCredentialStore::start();
    let credential_values = serde_json::json!({
        "HOST": redis.host,
        "PORT": redis.port,
        "PASSWORD": REDIS_PASSWORD,
        "VALUE": REDIS_VALUE
    })
    .to_string();
    let prompt_spec = r#"{"fields":["HOST","PORT","PASSWORD","VALUE"]}"#;

    let prompt_output = command_with_store(&store)
        .args([
            "prompt",
            "redis.local",
            "--spec",
            prompt_spec,
            "--values-stdin",
        ])
        .write_stdin(credential_values)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();
    assert!(
        String::from_utf8(prompt_output)
            .unwrap()
            .contains(&format!("Credential stored: {CREDENTIAL_ID}"))
    );

    let url = "redis://:{PASSWORD}@{HOST}:{PORT}/0";
    let set_args = r#"["sfae:redis","{VALUE}"]"#;
    let dry_run = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "redis",
            "SET",
            url,
            "--domain",
            "redis.local",
            "-d",
            set_args,
            "--dry-run",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run = String::from_utf8(dry_run).unwrap();
    assert!(dry_run.contains("REDIS SET redis://:***@***:***/0"));
    assert!(dry_run.contains(r#""***""#));
    assert!(!dry_run.contains(REDIS_PASSWORD));
    assert!(!dry_run.contains(REDIS_VALUE));

    let set_output = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "redis",
            "SET",
            url,
            "--domain",
            "redis.local",
            "-d",
            set_args,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let set_stdout = String::from_utf8(set_output).unwrap();
    assert!(set_stdout.contains(r#""value": "OK""#));

    let get_output = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "redis",
            "GET",
            url,
            "--domain",
            "redis.local",
            "-d",
            r#"["sfae:redis"]"#,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let get_stdout = String::from_utf8(get_output).unwrap();
    assert!(get_stdout.contains(r#""value": "cached from sfae""#));

    command_with_store(&store)
        .args(["delete", CREDENTIAL_ID, "--purge"])
        .assert()
        .success();

    let failure = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "redis",
            "GET",
            url,
            "--domain",
            "redis.local",
            "-d",
            r#"["sfae:redis"]"#,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(
        String::from_utf8(failure)
            .unwrap()
            .contains("credential resolution failed before request was sent: credential not found")
    );
}

struct RedisContainer {
    name: String,
    host: String,
    port: String,
}

impl RedisContainer {
    fn start() -> Self {
        let name = unique_name("redis-protocol");
        let output = docker(DockerArgs {
            args: &[
                "run",
                "--rm",
                "-d",
                "--name",
                &name,
                "-p",
                "127.0.0.1::6379",
                "redis:7-alpine",
                "redis-server",
                "--requirepass",
                REDIS_PASSWORD,
            ],
            stdin: None,
        });
        assert_success(CommandOutputCtx {
            action: "start redis container",
            output,
        });
        Self {
            name,
            host: "127.0.0.1".to_string(),
            port: "6379".to_string(),
        }
    }

    fn refresh_endpoint(&mut self) {
        let endpoint = container_endpoint(&self.name, "6379");
        self.host = endpoint.host;
        self.port = endpoint.port;
    }
}

impl Drop for RedisContainer {
    fn drop(&mut self) {
        let _ = docker(DockerArgs {
            args: &["rm", "-f", &self.name],
            stdin: None,
        });
    }
}

fn wait_for_redis(container: &RedisContainer) {
    for _ in 0..60 {
        let output = docker(DockerArgs {
            args: &[
                "exec",
                &container.name,
                "redis-cli",
                "--no-auth-warning",
                "-a",
                REDIS_PASSWORD,
                "ping",
            ],
            stdin: None,
        });
        if output.status.success() {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = docker(DockerArgs {
        args: &["logs", &container.name],
        stdin: None,
    });
    panic!(
        "redis container did not become ready:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );
}
