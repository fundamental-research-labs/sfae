//! Regression tests for agent-facing CLI help text.

use assert_cmd::Command;

fn help_output(args: &[&str]) -> String {
    let assert = Command::cargo_bin("sfae")
        .unwrap()
        .args(args)
        .assert()
        .success();
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
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
        assert!(stdout.contains("SECRETS:"));
        assert!(stdout.contains("Passwords/login keychain on macOS"));
        assert!(stdout.contains("SFAE_STORE_URL"));
        assert!(stdout.contains("hosted OAuth requires that backend path"));
        assert!(stdout.contains("not secret values"));
        assert!(!stdout.contains("STORE MODES:"));
        assert!(stdout.contains("sfae prompt --help"));
        assert!(stdout.contains("sfae request ..."));
    }
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
        assert!(stdout.contains("Hosted provider in this build: discord"));
        assert!(stdout.contains("SFAE_STORE_URL"));
        assert!(stdout.contains("OAuth requires browser mode"));
        assert!(stdout.contains("--label <LABEL>"));
        assert!(stdout.contains("not agents"));
        assert!(stdout.contains("EXAMPLES:"));
        assert!(!stdout.contains("--oauth"));
        assert!(!stdout.contains("--client-secret"));
    }
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
    assert!(flush_stdout.contains("Deletes every locally indexed credential"));
    assert!(flush_stdout.contains("sfae flush --dry-run"));
    assert!(!flush_stdout.contains("remote store"));
}
