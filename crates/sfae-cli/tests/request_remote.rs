//! Remote-store request tests covering hosted OAuth credential resolution.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use assert_cmd::Command;

struct ExpectedRequest {
    path: String,
    response: MockResponse,
}

struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: String,
}

struct JsonExpected {
    path: String,
    body: serde_json::Value,
}

struct TextExpected {
    path: String,
    body: String,
}

struct MockStore {
    base_url: String,
    handle: thread::JoinHandle<()>,
}

struct ParsedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

struct SendResponse<'a> {
    stream: &'a mut TcpStream,
    response: &'a MockResponse,
}

impl ExpectedRequest {
    fn json(args: JsonExpected) -> Self {
        Self {
            path: args.path,
            response: MockResponse {
                status: 200,
                content_type: "application/json",
                body: args.body.to_string(),
            },
        }
    }

    fn text(args: TextExpected) -> Self {
        Self {
            path: args.path,
            response: MockResponse {
                status: 200,
                content_type: "text/plain",
                body: args.body,
            },
        }
    }

    // xtask: allow-multi-param - compact fixture helper
    fn error(path: String, status: u16, body: &'static str) -> Self {
        Self {
            path,
            response: MockResponse {
                status,
                content_type: "text/plain",
                body: body.to_string(),
            },
        }
    }
}

impl MockStore {
    fn finish(self) {
        self.handle.join().unwrap();
    }
}

fn spawn_mock_store(requests: Vec<ExpectedRequest>) -> MockStore {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for expected in requests {
            let (mut stream, _) = listener.accept().unwrap();
            let actual = read_request(&mut stream);
            assert_eq!(actual.method, "GET");
            assert_eq!(actual.path, expected.path);
            assert_eq!(
                actual.headers.get("authorization").map(String::as_str),
                Some("Bearer test-token")
            );
            send_response(SendResponse {
                stream: &mut stream,
                response: &expected.response,
            });
        }
    });

    MockStore {
        base_url: format!("http://{addr}"),
        handle,
    }
}

fn read_request(stream: &mut TcpStream) -> ParsedRequest {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let key = name.to_ascii_lowercase();
            let value = value.trim().to_string();
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(key, value);
        }
    }

    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
    }

    ParsedRequest {
        method,
        path,
        headers,
    }
}

fn send_response(args: SendResponse<'_>) {
    let SendResponse { stream, response } = args;
    let http = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        if response.status == 200 {
            "OK"
        } else {
            "Error"
        },
        response.content_type,
        response.body.len(),
        response.body
    );
    stream.write_all(http.as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn request_reports_private_credential_resolution_failure_before_send() {
    let credential_id = "00000000-0000-4000-8000-000000000099";
    let mock = spawn_mock_store(vec![ExpectedRequest::error(
        format!("/credentials/{credential_id}/blob"),
        500,
        "temporary store failure",
    )]);

    let mut command = Command::cargo_bin("sfae").unwrap();
    remove_proxy_env(&mut command);
    let assert = command
        .env("SFAE_STORE_URL", &mock.base_url)
        .env("SFAE_STORE_TOKEN", "test-token")
        .args([
            "request",
            "GET",
            "https://discord.com/api/v10/users/@me",
            "--domain",
            "discord.com",
            "--cred",
            credential_id,
            "-H",
            "Authorization: Bearer {OAUTH_ACCESS_TOKEN}",
            "--dry-run",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("credential resolution failed before request was sent"));
    assert!(!stderr.contains(credential_id));
    assert!(!stderr.contains("discord.com"));
    assert!(!stderr.contains("OAUTH_ACCESS_TOKEN"));
    mock.finish();
}

#[test]
fn request_does_not_echo_missing_credential_identifier() {
    let credential_id = "00000000-0000-4000-8000-000000000100";
    let mock = spawn_mock_store(vec![ExpectedRequest::error(
        format!("/credentials/{credential_id}/blob"),
        404,
        "not found",
    )]);

    let mut command = Command::cargo_bin("sfae").unwrap();
    remove_proxy_env(&mut command);
    let assert = command
        .env("SFAE_STORE_URL", &mock.base_url)
        .env("SFAE_STORE_TOKEN", "test-token")
        .args([
            "request",
            "GET",
            "https://discord.com/api/v10/users/@me",
            "--domain",
            "discord.com",
            "--cred",
            credential_id,
            "-H",
            "Authorization: Bearer {OAUTH_ACCESS_TOKEN}",
            "--dry-run",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("credential resolution failed before request was sent"));
    assert!(stderr.contains("credential not found"));
    assert!(!stderr.contains(credential_id));
    assert!(!stderr.contains("OAUTH_ACCESS_TOKEN"));
    mock.finish();
}

fn remove_proxy_env(command: &mut Command) {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    command.env("NO_PROXY", "127.0.0.1,localhost");
}

#[test]
fn request_dry_run_resolves_remote_discord_oauth_credential() {
    let credential_id = "00000000-0000-4000-8000-000000000011";
    let blob = serde_json::json!({
        "OAUTH_ACCESS_TOKEN": "discord-access-token",
        "OAUTH_ACCOUNT_ID": "00000000-0000-4000-8000-000000000012",
        "OAUTH_PROVIDER": "discord"
    })
    .to_string();
    let mock = spawn_mock_store(vec![
        ExpectedRequest::json(JsonExpected {
            path: "/credentials/discord.com".to_string(),
            body: serde_json::json!({
                "credentials": [{
                    "id": credential_id,
                    "domain": "discord.com",
                    "label": null,
                    "keys": [
                        "OAUTH_ACCESS_TOKEN",
                        "OAUTH_ACCOUNT_ID",
                        "OAUTH_PROVIDER"
                    ]
                }]
            }),
        }),
        ExpectedRequest::text(TextExpected {
            path: format!("/credentials/{credential_id}/blob"),
            body: blob,
        }),
    ]);

    let mut command = Command::cargo_bin("sfae").unwrap();
    remove_proxy_env(&mut command);
    let assert = command
        .env("SFAE_STORE_URL", &mock.base_url)
        .env("SFAE_STORE_TOKEN", "test-token")
        .args([
            "request",
            "GET",
            "https://discord.com/api/v10/users/@me",
            "--domain",
            "discord.com",
            "-H",
            "Authorization: Bearer {OAUTH_ACCESS_TOKEN}",
            "--dry-run",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("GET https://discord.com/api/v10/users/@me"));
    assert!(stdout.contains("Authorization: Bearer ***"));
    assert!(!stdout.contains("discord-access-token"));
    mock.finish();
}
