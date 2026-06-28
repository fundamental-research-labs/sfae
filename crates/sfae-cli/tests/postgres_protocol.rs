//! Integration coverage for Postgres protocol requests through the SFAE CLI.
//!
//! The test uses a real Postgres container and a mock remote credential store so
//! it can verify credential create, resolve, delete, and post-delete failure.

use std::thread;
use std::time::Duration;

mod support;

use support::{
    CREDENTIAL_ID, CommandOutputCtx, DockerArgs, MockCredentialStore, assert_success,
    command_with_store, container_endpoint, docker, docker_available, unique_name,
};

const CREATE_DATABASE: &str = "SELECT 'CREATE DATABASE sfae_protocol'\n\
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sfae_protocol')\\gexec\n";
const MIGRATION: &str = include_str!("fixtures/postgres_migration.sql");

#[test]
fn postgres_request_uses_stored_credentials_until_deleted() {
    if !docker_available() {
        eprintln!("skipping postgres protocol integration test: docker is unavailable");
        return;
    }

    let mut postgres = PostgresContainer::start();
    wait_for_postgres(&postgres);
    postgres.refresh_endpoint();
    run_migration(&postgres);

    let store = MockCredentialStore::start();
    let credential_values = serde_json::json!({
        "HOST": postgres.host,
        "PORT": postgres.port,
        "DATABASE": "sfae_protocol",
        "USERNAME": "sfae_app",
        "PASSWORD": "sfae_app_password"
    })
    .to_string();
    let prompt_spec = r#"{"fields":["HOST","PORT","DATABASE","USERNAME","PASSWORD"]}"#;

    let prompt_output = command_with_store(&store)
        .args([
            "prompt",
            "postgres.local",
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

    let dsn = "postgres://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}";
    let query = "select name, role_name from sfae_people order by id";
    let output = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "postgres",
            "QUERY",
            dsn,
            "--domain",
            "postgres.local",
            "-d",
            query,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains(r#""name": "Ada Lovelace""#));
    assert!(stdout.contains(r#""role_name": "admin""#));
    assert!(stdout.contains(r#""name": "Grace Hopper""#));

    command_with_store(&store)
        .args(["delete", CREDENTIAL_ID, "--purge"])
        .assert()
        .success();

    let failure = command_with_store(&store)
        .args([
            "request",
            "--protocol",
            "postgres",
            "QUERY",
            dsn,
            "--domain",
            "postgres.local",
            "-d",
            query,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(
        String::from_utf8(failure)
            .unwrap()
            .contains("credential not found: USERNAME")
    );
}

struct PostgresContainer {
    name: String,
    host: String,
    port: String,
}

impl PostgresContainer {
    fn start() -> Self {
        let name = unique_name("postgres-protocol");
        let output = docker(DockerArgs {
            args: &[
                "run",
                "--rm",
                "-d",
                "--name",
                &name,
                "-e",
                "POSTGRES_DB=sfae_protocol",
                "-e",
                "POSTGRES_USER=sfae_owner",
                "-e",
                "POSTGRES_PASSWORD=sfae_owner_password",
                "-p",
                "127.0.0.1::5432",
                "postgres:16-alpine",
            ],
            stdin: None,
        });
        assert_success(CommandOutputCtx {
            action: "start postgres container",
            output,
        });
        Self {
            name,
            host: "127.0.0.1".to_string(),
            port: "5432".to_string(),
        }
    }

    fn refresh_endpoint(&mut self) {
        let endpoint = container_endpoint(&self.name, "5432");
        self.host = endpoint.host;
        self.port = endpoint.port;
    }
}

impl Drop for PostgresContainer {
    fn drop(&mut self) {
        let _ = docker(DockerArgs {
            args: &["rm", "-f", &self.name],
            stdin: None,
        });
    }
}

fn wait_for_postgres(container: &PostgresContainer) {
    for _ in 0..60 {
        let output = docker(DockerArgs {
            args: &[
                "exec",
                &container.name,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "sfae_owner",
                "-d",
                "sfae_protocol",
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
        "postgres container did not become ready:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );
}

fn run_migration(container: &PostgresContainer) {
    let output = docker(DockerArgs {
        args: &[
            "exec",
            "-i",
            &container.name,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "sfae_owner",
            "-d",
            "postgres",
        ],
        stdin: Some(CREATE_DATABASE),
    });
    assert_success(CommandOutputCtx {
        action: "ensure postgres database",
        output,
    });

    let output = docker(DockerArgs {
        args: &[
            "exec",
            "-i",
            &container.name,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "sfae_owner",
            "-d",
            "sfae_protocol",
        ],
        stdin: Some(MIGRATION),
    });
    assert_success(CommandOutputCtx {
        action: "run postgres migration",
        output,
    });
}
