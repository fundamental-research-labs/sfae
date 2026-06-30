//! Regression tests for agent-facing CLI help text.

use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn help_output(args: &[&str]) -> String {
    help_output_with_env(args, &[("SFAE_OAUTH_BROKER_URL", "http://127.0.0.1:9")])
}

// xtask: allow-multi-param - test helper pairs CLI args with environment overrides
fn help_output_with_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let assert = Command::cargo_bin("sfae")
        .unwrap()
        .args(args)
        .envs(envs.iter().copied())
        .assert()
        .success();
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
}

struct ProviderServer {
    base_url: String,
    handle: thread::JoinHandle<String>,
}

impl ProviderServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cache_key = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_url = format!("http://{}/{}", listener.local_addr().unwrap(), cache_key);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let target = read_request_target(&mut stream);
            let body = r#"{"providers":[{"provider":"discord","domains":["discord.com"]}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            target
        });
        Self { base_url, handle }
    }

    fn finish(self) -> String {
        self.handle.join().unwrap()
    }
}

fn read_request_target(stream: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = stream.read(&mut buf).unwrap();
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..read]);
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&raw);
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn root_help_explains_agent_workflow() {
    for args in [vec!["--help"], vec!["-h"]] {
        let stdout = help_output(&args);
        assert!(stdout.contains("Credential gateway for LLM agents making authenticated requests"));
        assert!(stdout.contains("AGENT WORKFLOW:"));
        assert!(stdout.contains("official online API and authentication docs"));
        assert!(stdout.contains("not a service-specific CLI"));
        assert!(stdout.contains("If a suitable set exists, no human action is needed"));
        assert!(stdout.contains("blocking human-interaction step"));
        assert!(stdout.contains("credential collection can take as long as the human needs"));
        assert!(stdout.contains("Do not impose an agent-side timeout"));
        assert!(stdout.contains("If multiple auth methods are acceptable"));
        assert!(stdout.contains("preferred methods first"));
        assert!(stdout.contains("HTTP is the default protocol"));
        assert!(stdout.contains("--protocol postgres"));
        assert!(stdout.contains("--protocol redis"));
        assert!(stdout.contains("without revealing secret values"));
        assert!(stdout.contains("short-lived 2FA/MFA code"));
        assert!(stdout.contains("sfae code <domain>"));
        assert!(stdout.contains("it is not stored"));
        assert!(!stdout.contains("SECRETS:"));
        assert!(!stdout.contains("Passwords/login keychain on macOS"));
        assert!(!stdout.contains("oauth.sfae.io"));
        assert!(!stdout.contains("SFAE_STORE_URL"));
        assert!(!stdout.contains("STORE MODES:"));
        assert!(stdout.contains("sfae prompt --help"));
        assert!(stdout.contains("sfae request ..."));
    }
}

#[test]
fn code_help_explains_transient_output_and_validation() {
    let stdout = help_output(&["code", "--help"]);
    assert!(stdout.contains("transient 2FA/MFA code"));
    assert!(stdout.contains("short-lived verification codes"));
    assert!(stdout.contains("printed to stdout"));
    assert!(stdout.contains("not stored in the OS credential store"));
    assert!(stdout.contains("Stdout is exactly the submitted code plus a newline"));
    assert!(stdout.contains("Cancel, timeout, or invalid configuration exits non-zero"));
    assert!(stdout.contains("Default format is digits"));
    assert!(stdout.contains("--length N"));
    assert!(stdout.contains("Formats: digits, alnum, text"));
    assert!(stdout.contains("--help-url"));
    assert!(stdout.contains("--timeout"));
}

#[test]
fn distribution_help_explains_skill_install_and_update() {
    let install_stdout = help_output(&["install-skill", "--help"]);
    assert!(install_stdout.contains("AGENT-FIRST INSTALL:"));
    assert!(install_stdout.contains("primary install path is the skill"));
    assert!(install_stdout.contains("includes install.sh"));
    assert!(install_stdout.contains("--codex"));
    assert!(install_stdout.contains(".agents/skills/sfae"));
    assert!(install_stdout.contains("--install-cli"));
    assert!(install_stdout.contains("SFAE_SKILL_AUTO_UPDATE=off"));

    let update_stdout = help_output(&["update", "--help"]);
    assert!(update_stdout.contains("INSTALL METHOD:"));
    assert!(update_stdout.contains("brew update"));
    assert!(update_stdout.contains("npm install -g @fundamental-research-labs/sfae@latest"));
    assert!(update_stdout.contains("Direct installs"));
    assert!(update_stdout.contains("SFAE_UPDATE_METHOD"));
}

#[test]
fn prompt_help_explains_spec_and_secret_handling() {
    for args in [vec!["prompt", "--help"], vec!["prompt", "-h"]] {
        let stdout = help_output(&args);
        assert!(stdout.contains("AGENT RULES:"));
        assert!(stdout.contains("WAITING BEHAVIOR:"));
        assert!(stdout.contains("blocking human-interaction step"));
        assert!(stdout.contains("may take an undefined amount of time"));
        assert!(stdout.contains("Wait until `sfae prompt` exits"));
        assert!(stdout.contains("Do not impose an agent-side timeout"));
        assert!(stdout.contains("SPEC FORMAT:"));
        assert!(stdout.contains("official authentication docs"));
        assert!(stdout.contains("send HTTP API requests"));
        assert!(stdout.contains("Never ask the human to paste secrets into chat"));
        assert!(stdout.contains("Field names must match [A-Z][A-Z0-9_]*"));
        assert!(stdout.contains("{API_KEY}"));
        assert!(stdout.contains("{OAUTH_ACCESS_TOKEN}"));
        assert!(stdout.contains("authorization URLs, token URLs, or provider secrets"));
        assert!(stdout.contains("forwards requested OAuth scopes to the provider"));
        assert!(stdout.contains("Dropbox (`dropboxapi.com`)"));
        assert!(stdout.contains("Ask for any scope required by the user's task"));
        assert!(stdout.contains("choose the narrowest set"));
        assert!(stdout.contains("SFAE or the provider may reject unknown"));
        assert!(stdout.contains("SCOPE UPGRADES / RE-AUTHORIZATION:"));
        assert!(stdout.contains("re-run `sfae prompt` with the same domain/label"));
        assert!(stdout.contains("stores fresh credentials with a new UUID"));
        assert!(stdout.contains("forgets older same-account credential entries"));
        assert!(stdout.contains("without reading or purging keychain secrets"));
        assert!(stdout.contains("older credential sets remain until you run `sfae delete <uuid>`"));
        assert!(stdout.contains("sfae request --cred <uuid>"));
        assert!(!stdout.contains("SFAE_OAUTH_BROKER_URL"));
        assert!(!stdout.contains("SFAE_STORE_URL"));
        assert!(stdout.contains("OAuth requires browser mode"));
        assert!(!stdout.contains("SUPPORTED OAUTH PROVIDERS:"));
        assert!(!stdout.contains("Hosted provider in this build"));
        assert!(!stdout.contains(r#""provider": "discord""#));
        assert!(stdout.contains("--label <LABEL>"));
        assert!(stdout.contains("not agents"));
        assert!(stdout.contains("EXAMPLES:"));
        assert!(!stdout.contains("--oauth"));
        assert!(!stdout.contains("--client-secret"));
    }
}

#[test]
fn prompt_help_displays_provider_list_from_oauth_broker() {
    let server = ProviderServer::start();
    let base_url = server.base_url.clone();
    let stdout = help_output_with_env(
        &["prompt", "--help"],
        &[("SFAE_OAUTH_BROKER_URL", &base_url)],
    );
    assert!(stdout.contains("SUPPORTED OAUTH PROVIDERS:"));
    assert!(stdout.contains("discord (domains: discord.com)"));
    assert!(server.finish().ends_with("/v1/oauth/providers"));

    let server = ProviderServer::start();
    let base_url = server.base_url.clone();
    let cached_stdout = help_output_with_env(
        &["prompt", "--help"],
        &[("SFAE_OAUTH_BROKER_URL", &base_url)],
    );
    assert!(cached_stdout.contains("SUPPORTED OAUTH PROVIDERS:"));
    assert!(cached_stdout.contains("discord (domains: discord.com)"));
    assert!(server.finish().ends_with("/v1/oauth/providers"));
}

#[test]
fn credentials_help_explains_output_and_label_filter() {
    let stdout = help_output(&["credentials", "--help"]);
    assert!(stdout.contains("--label <LABEL>"));
    assert!(stdout.contains("<uuid>  <domain>  <label-or->  [KEY, ...]"));
    assert!(stdout.contains("sfae show <uuid>"));
    assert!(stdout.contains("domain filter is exact"));
    assert!(stdout.contains("legacy alias"));
    assert!(stdout.contains("sfae credentials github.com --label Work"));
    assert!(!stdout.contains("sfae credentials show"));
}

#[test]
fn show_help_explains_metadata_without_secret_blob_access() {
    let stdout = help_output(&["show", "--help"]);
    assert!(stdout.contains("Show non-secret metadata for one credential set"));
    assert!(stdout.contains("sfae show 550e8400-e29b-41d4-a716-446655440000"));
    assert!(
        stdout.contains("does not read credential values from the keychain-backed secret blob")
    );
    assert!(stdout.contains("Older credentials may show empty metadata"));
}

#[test]
fn doctor_help_explains_private_diagnostics() {
    let stdout = help_output(&["doctor", "--help"]);
    assert!(stdout.contains("credential-store availability"));
    assert!(stdout.contains("without printing secrets"));
    assert!(stdout.contains("does not read secret blobs"));
    assert!(stdout.contains("--cred"));
    assert!(stdout.contains("without printing it"));
}

#[test]
fn doctor_reports_incomplete_remote_store_without_secret_details() {
    let assert = Command::cargo_bin("sfae")
        .unwrap()
        .args(["doctor"])
        .env("SFAE_STORE_URL", "http://127.0.0.1:9")
        .env_remove("SFAE_STORE_TOKEN")
        .assert()
        .failure();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stdout.contains("Store backend: remote credential store"));
    assert!(stdout.contains("Remote store URL: set"));
    assert!(stdout.contains("Remote store token: missing"));
    assert!(stderr.contains("credential-store configuration is incomplete"));
    assert!(!stdout.contains("127.0.0.1"));
    assert!(!stderr.contains("127.0.0.1"));
}

#[test]
fn request_help_explains_placeholders_lookup_and_output() {
    let stdout = help_output(&["request", "--help"]);
    assert!(stdout.contains("--label <LABEL>"));
    assert!(stdout.contains("PLACEHOLDERS:"));
    assert!(stdout.contains("Use `{FIELD_NAME}` in the URL, headers, or body"));
    assert!(stdout.contains("--protocol"));
    assert!(stdout.contains("Postgres query"));
    assert!(stdout.contains("Redis commands"));
    assert!(stdout.contains("JSON string array"));
    assert!(stdout.contains("CREDENTIAL LOOKUP:"));
    assert!(stdout.contains("parent-domain fallback"));
    assert!(stdout.contains("Pass `--domain` too if the URL host cannot be parsed"));
    assert!(
        stdout.contains(
            "Prints the HTTP response body, a Postgres JSON result, or a Redis JSON result"
        )
    );
    assert!(stdout.contains("dry-run output masks resolved credentials"));
    assert!(stdout.contains("Hosted OAuth credentials use the same"));
    assert!(!stdout.contains("Username for credential lookup"));
}

#[test]
fn destructive_command_help_explains_scope_and_dry_run() {
    let delete_stdout = help_output(&["delete", "--help"]);
    assert!(
        delete_stdout
            .contains("Default UUID deletion attempts broker-mediated hosted OAuth revoke")
    );
    assert!(delete_stdout.contains("does not delete keychain secret material"));
    assert!(delete_stdout.contains("Use --purge only for manual cleanup"));
    assert!(delete_stdout.contains("may prompt for password"));
    assert!(delete_stdout.contains("Use --all to apply the same behavior"));
    assert!(delete_stdout.contains("sfae delete --all --dry-run"));
    assert!(delete_stdout.contains("sfae delete --all --purge"));
    assert!(delete_stdout.contains("hosted OAuth revoke is attempted for UUID deletes either way"));
    assert!(delete_stdout.contains("--all"));
    assert!(delete_stdout.contains("--purge"));
    assert!(delete_stdout.contains("Domain deletion is for legacy flat credentials"));
    assert!(delete_stdout.contains("--label <LABEL>"));
    assert!(delete_stdout.contains("ACCESS_TOKEN"));
    assert!(!delete_stdout.contains("sfae flush"));
}
