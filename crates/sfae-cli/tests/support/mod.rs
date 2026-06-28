//! Shared integration-test helpers for CLI protocol tests.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use serde_json::Value;

pub const CREDENTIAL_ID: &str = "00000000-0000-4000-8000-000000000077";
const STORE_TOKEN: &str = "test-token";

pub struct DockerArgs<'a> {
    pub args: &'a [&'a str],
    pub stdin: Option<&'a str>,
}

pub struct CommandOutputCtx {
    pub action: &'static str,
    pub output: std::process::Output,
}

pub struct DockerEndpoint {
    pub host: String,
    pub port: String,
}

pub fn docker_available() -> bool {
    docker(DockerArgs {
        args: &["info"],
        stdin: None,
    })
    .status
    .success()
}

pub fn docker(args: DockerArgs<'_>) -> std::process::Output {
    let mut command = ProcessCommand::new("docker");
    command.args(args.args);
    if args.stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run docker: {e}"));
    if let Some(input) = args.stdin {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
    }
    child.wait_with_output().unwrap()
}

pub fn assert_success(ctx: CommandOutputCtx) {
    if ctx.output.status.success() {
        return;
    }
    panic!(
        "failed to {}:\nstdout:\n{}\nstderr:\n{}",
        ctx.action,
        String::from_utf8_lossy(&ctx.output.stdout),
        String::from_utf8_lossy(&ctx.output.stderr)
    );
}

pub fn unique_name(scope: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("sfae-{scope}-{}-{nanos}", std::process::id())
}

// xtask: allow-multi-param - test helper pairs a container name with its exposed port
pub fn container_endpoint(name: &str, container_port: &str) -> DockerEndpoint {
    if let Some(port) = mapped_container_port(name, container_port) {
        let mapped = DockerEndpoint {
            host: "127.0.0.1".to_string(),
            port,
        };
        if tcp_reachable(&mapped) {
            return mapped;
        }
    }
    DockerEndpoint {
        host: container_ip(name),
        port: container_port.to_string(),
    }
}

// xtask: allow-multi-param - test helper pairs a container name with its exposed port
fn mapped_container_port(name: &str, container_port: &str) -> Option<String> {
    let port_spec = format!("{container_port}/tcp");
    let output = docker(DockerArgs {
        args: &["port", name, &port_spec],
        stdin: None,
    });
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return None;
    }
    stdout
        .lines()
        .find_map(|line| line.rsplit_once(':').map(|(_, port)| port.to_string()))
}

fn container_ip(name: &str) -> String {
    let output = docker(DockerArgs {
        args: &[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ],
        stdin: None,
    });
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_success(CommandOutputCtx {
        action: "inspect container IP",
        output,
    });
    if stdout.is_empty() {
        panic!("container has no bridge IP");
    }
    stdout
}

fn tcp_reachable(endpoint: &DockerEndpoint) -> bool {
    let target = format!("{}:{}", endpoint.host, endpoint.port);
    let Ok(addr) = target.parse() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

#[derive(Clone)]
struct CredentialRecord {
    id: String,
    domain: String,
    label: Option<String>,
    values: HashMap<String, String>,
}

pub struct MockCredentialStore {
    base_url: String,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockCredentialStore {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let records = Arc::new(Mutex::new(Vec::new()));
        let thread_running = Arc::clone(&running);
        let thread_records = Arc::clone(&records);
        let handle = thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_http_request(&mut stream);
                        let response = route_request(RouteCtx {
                            request,
                            records: &thread_records,
                        });
                        write_http_response(ResponseCtx {
                            stream: &mut stream,
                            response,
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("mock credential store accept failed: {e}"),
                }
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            running,
            handle: Some(handle),
        }
    }
}

impl Drop for MockCredentialStore {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
}

struct RouteCtx<'a> {
    request: HttpRequest,
    records: &'a Arc<Mutex<Vec<CredentialRecord>>>,
}

struct ResponseCtx<'a> {
    stream: &'a mut TcpStream,
    response: HttpResponse,
}

fn read_http_request(stream: &mut TcpStream) -> HttpRequest {
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

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).unwrap();
    }

    HttpRequest {
        method,
        path,
        headers,
        body,
    }
}

fn route_request(ctx: RouteCtx<'_>) -> HttpResponse {
    if ctx.request.headers.get("authorization").map(String::as_str) != Some("Bearer test-token") {
        return text_response(TextResponse {
            status: 401,
            reason: "Unauthorized",
            body: "Unauthorized",
        });
    }

    match (ctx.request.method.as_str(), ctx.request.path.as_str()) {
        ("POST", "/credentials") => store_credential(ctx),
        ("GET", "/credentials") => list_credentials(ListCtx {
            records: ctx.records,
            domain: None,
        }),
        ("GET", path) if path.starts_with("/credentials/") && path.ends_with("/blob") => {
            get_blob(BlobCtx {
                records: ctx.records,
                path,
            })
        }
        ("GET", path) if path.starts_with("/credentials/") => list_credentials(ListCtx {
            records: ctx.records,
            domain: Some(path.trim_start_matches("/credentials/")),
        }),
        ("DELETE", path) if path.starts_with("/credentials/") => delete_credential(DeleteCtx {
            records: ctx.records,
            id: path.trim_start_matches("/credentials/"),
        }),
        _ => text_response(TextResponse {
            status: 404,
            reason: "Not Found",
            body: "Not Found",
        }),
    }
}

struct TextResponse<'a> {
    status: u16,
    reason: &'static str,
    body: &'a str,
}

fn text_response(response: TextResponse<'_>) -> HttpResponse {
    HttpResponse {
        status: response.status,
        reason: response.reason,
        content_type: "text/plain",
        body: response.body.to_string(),
    }
}

fn json_response(value: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "application/json",
        body: value.to_string(),
    }
}

fn store_credential(ctx: RouteCtx<'_>) -> HttpResponse {
    let body: Value = serde_json::from_slice(&ctx.request.body).unwrap();
    let domain = body["domain"].as_str().unwrap().to_string();
    let label = body["label"].as_str().map(str::to_string);
    let values = body["values"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
        .collect::<HashMap<_, _>>();
    ctx.records.lock().unwrap().push(CredentialRecord {
        id: CREDENTIAL_ID.to_string(),
        domain,
        label,
        values,
    });
    json_response(serde_json::json!({ "ok": true, "id": CREDENTIAL_ID }))
}

struct ListCtx<'a> {
    records: &'a Arc<Mutex<Vec<CredentialRecord>>>,
    domain: Option<&'a str>,
}

fn list_credentials(ctx: ListCtx<'_>) -> HttpResponse {
    let records = ctx.records.lock().unwrap();
    let credentials = records
        .iter()
        .filter(|record| ctx.domain.is_none_or(|domain| record.domain == domain))
        .map(credential_entry)
        .collect::<Vec<_>>();
    json_response(serde_json::json!({ "credentials": credentials }))
}

fn credential_entry(record: &CredentialRecord) -> Value {
    let mut keys = record.values.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    serde_json::json!({
        "id": record.id,
        "domain": record.domain,
        "label": record.label,
        "keys": keys,
        "metadata": {}
    })
}

struct BlobCtx<'a> {
    records: &'a Arc<Mutex<Vec<CredentialRecord>>>,
    path: &'a str,
}

fn get_blob(ctx: BlobCtx<'_>) -> HttpResponse {
    let id = ctx
        .path
        .trim_start_matches("/credentials/")
        .trim_end_matches("/blob");
    let records = ctx.records.lock().unwrap();
    let Some(record) = records.iter().find(|record| record.id == id) else {
        return text_response(TextResponse {
            status: 404,
            reason: "Not Found",
            body: "Credential set not found",
        });
    };
    json_response(serde_json::json!(record.values))
}

struct DeleteCtx<'a> {
    records: &'a Arc<Mutex<Vec<CredentialRecord>>>,
    id: &'a str,
}

fn delete_credential(ctx: DeleteCtx<'_>) -> HttpResponse {
    let mut records = ctx.records.lock().unwrap();
    let len = records.len();
    records.retain(|record| record.id != ctx.id);
    if records.len() == len {
        return text_response(TextResponse {
            status: 404,
            reason: "Not Found",
            body: "Credential set not found",
        });
    }
    json_response(serde_json::json!({ "ok": true }))
}

fn write_http_response(ctx: ResponseCtx<'_>) {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        ctx.response.status,
        ctx.response.reason,
        ctx.response.content_type,
        ctx.response.body.len(),
        ctx.response.body
    );
    ctx.stream.write_all(response.as_bytes()).unwrap();
    ctx.stream.flush().unwrap();
}

pub fn command_with_store(store: &MockCredentialStore) -> Command {
    let mut command = Command::cargo_bin("sfae").unwrap();
    remove_proxy_env(&mut command);
    command
        .env("SFAE_STORE_URL", &store.base_url)
        .env("SFAE_STORE_TOKEN", STORE_TOKEN);
    command
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
