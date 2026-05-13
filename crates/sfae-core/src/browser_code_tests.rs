//! Route-level tests for the transient code browser loop.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use super::*;
use crate::code::{CodeFormat, CodeRequest};

struct TestHttpRequest {
    port: u16,
    method: &'static str,
    path: &'static str,
    body: String,
}

struct CodeServer {
    port: u16,
    handle: thread::JoinHandle<Result<String, SfaeError>>,
}

fn request() -> CodeRequest {
    CodeRequest {
        domain: "example.com".to_string(),
        label: None,
        message: None,
        help_url: None,
        format: CodeFormat::Digits,
        min_length: 6,
        max_length: 6,
        timeout: Duration::from_secs(5),
    }
}

fn spawn_code_server(request: CodeRequest) -> Option<CodeServer> {
    let server = match LocalServer::new() {
        Ok(server) => server,
        Err(e) => {
            eprintln!("skipping route-level code test: {e}");
            return None;
        }
    };
    let port = server.port();
    let handle = thread::spawn(move || serve_code_request(CodeServe { request, server }));
    Some(CodeServer { port, handle })
}

fn send_http(req: TestHttpRequest) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", req.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let raw = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        req.method,
        req.path,
        req.body.len(),
        req.body
    );
    stream.write_all(raw.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn extract_csrf(html: &str) -> String {
    let marker = r#"name="_csrf" value=""#;
    let start = html.find(marker).unwrap() + marker.len();
    let end = html[start..].find('"').unwrap();
    html[start..start + end].to_string()
}

#[test]
fn code_route_returns_submitted_code() {
    let Some(server) = spawn_code_server(request()) else {
        return;
    };
    let html = send_http(TestHttpRequest {
        port: server.port,
        method: "GET",
        path: "/",
        body: String::new(),
    });
    assert!(html.contains("HTTP/1.1 200 OK"));
    assert!(html.contains("Cache-Control: no-store"));
    let csrf = extract_csrf(&html);

    let done = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/",
        body: format!("_csrf={csrf}&_code=123456"),
    });
    assert!(done.contains("HTTP/1.1 200 OK"));
    assert_eq!(server.handle.join().unwrap().unwrap(), "123456");
}

#[test]
fn code_route_rejects_invalid_csrf_then_accepts_valid_post() {
    let Some(server) = spawn_code_server(request()) else {
        return;
    };
    let csrf = extract_csrf(&send_http(TestHttpRequest {
        port: server.port,
        method: "GET",
        path: "/",
        body: String::new(),
    }));

    let bad = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/",
        body: "_csrf=bad&_code=123456".to_string(),
    });
    assert!(bad.contains("HTTP/1.1 400 Bad Request"));

    let ok = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/",
        body: format!("_csrf={csrf}&_code=123456"),
    });
    assert!(ok.contains("HTTP/1.1 200 OK"));
    assert_eq!(server.handle.join().unwrap().unwrap(), "123456");
}

#[test]
fn code_route_cancel_returns_cancelled() {
    let Some(server) = spawn_code_server(request()) else {
        return;
    };
    let csrf = extract_csrf(&send_http(TestHttpRequest {
        port: server.port,
        method: "GET",
        path: "/",
        body: String::new(),
    }));

    let cancelled = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/cancel",
        body: format!("_csrf={csrf}"),
    });
    assert!(cancelled.contains("HTTP/1.1 200 OK"));
    assert!(matches!(
        server.handle.join().unwrap(),
        Err(SfaeError::Cancelled)
    ));
}

#[test]
fn code_route_rejects_oversized_body_then_accepts_valid_post() {
    let Some(server) = spawn_code_server(request()) else {
        return;
    };
    let csrf = extract_csrf(&send_http(TestHttpRequest {
        port: server.port,
        method: "GET",
        path: "/",
        body: String::new(),
    }));

    let too_large = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/",
        body: format!("_csrf={csrf}&{}", "x".repeat(MAX_CODE_REQUEST_BODY + 1)),
    });
    assert!(too_large.contains("HTTP/1.1 413 Payload Too Large"));

    let ok = send_http(TestHttpRequest {
        port: server.port,
        method: "POST",
        path: "/",
        body: format!("_csrf={csrf}&_code=123456"),
    });
    assert!(ok.contains("HTTP/1.1 200 OK"));
    assert_eq!(server.handle.join().unwrap().unwrap(), "123456");
}

#[test]
fn code_route_times_out() {
    let mut req = request();
    req.timeout = Duration::from_millis(20);
    let Some(server) = spawn_code_server(req) else {
        return;
    };

    let err = server.handle.join().unwrap().unwrap_err();
    assert!(matches!(err, SfaeError::Other(ref msg) if msg.contains("timed out")));
}
