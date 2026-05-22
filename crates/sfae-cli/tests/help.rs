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
        assert!(stdout.contains("Credential gateway for LLM agents making HTTP API requests"));
        assert!(stdout.contains("AGENT WORKFLOW:"));
        assert!(stdout.contains("official online API and authentication docs"));
        assert!(stdout.contains("not a service-specific CLI"));
        assert!(stdout.contains("If a suitable set exists, no human action is needed"));
        assert!(stdout.contains("blocking human-interaction step"));
        assert!(stdout.contains("credential collection can take as long as the human needs"));
        assert!(stdout.contains("Do not impose an agent-side timeout"));
        assert!(stdout.contains("If multiple auth methods are acceptable"));
        assert!(stdout.contains("preferred methods first"));
        assert!(stdout.contains("HTTP is the only protocol currently supported"));
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
        assert!(stdout.contains("Ask for any scope required by the user's task"));
        assert!(stdout.contains("choose the narrowest set"));
        assert!(stdout.contains("SFAE or the provider may reject unknown"));
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
    assert!(stdout.contains("domain filter is exact"));
    assert!(stdout.contains("legacy alias"));
    assert!(stdout.contains("sfae credentials github.com --label Work"));
}

#[test]
fn request_help_explains_placeholders_lookup_and_output() {
    let stdout = help_output(&["request", "--help"]);
    assert!(stdout.contains("--label <LABEL>"));
    assert!(stdout.contains("PLACEHOLDERS:"));
    assert!(stdout.contains("Use `{FIELD_NAME}` in the URL, headers, or body"));
    assert!(stdout.contains("CREDENTIAL LOOKUP:"));
    assert!(stdout.contains("parent-domain fallback"));
    assert!(stdout.contains("Pass `--domain` too if the URL host cannot be parsed"));
    assert!(stdout.contains("Prints the response body to stdout"));
    assert!(stdout.contains("dry-run output masks resolved credentials"));
    assert!(stdout.contains("Hosted OAuth credentials use the same"));
    assert!(!stdout.contains("Username for credential lookup"));
}

#[test]
fn destructive_command_help_explains_scope_and_dry_run() {
    let delete_stdout = help_output(&["delete", "--help"]);
    assert!(delete_stdout.contains("Delete by UUID"));
    assert!(delete_stdout.contains("Domain deletion is for legacy flat credentials"));
    assert!(delete_stdout.contains("--label <LABEL>"));
    assert!(delete_stdout.contains("ACCESS_TOKEN"));

    let flush_stdout = help_output(&["flush", "--help"]);
    assert!(flush_stdout.contains("Deletes every credential indexed by SFAE"));
    assert!(flush_stdout.contains("sfae flush --dry-run"));
    assert!(!flush_stdout.contains("remote store"));
}
