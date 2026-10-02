//! `cordon verify` proves the guarantee against a running daemon, so an
//! operator does not have to trust the README.
//!
//! It speaks HTTP with a hand written request rather than taking an HTTP client
//! dependency. The request is four lines of text and the only response fields
//! that matter are the status and one JSON key.

use std::io::Write;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// Each attempt is a thing a compromised job will actually try. The owner
/// prefix is `cordon-verify` so a probe never touches a real workspace.
const ATTEMPTS: &[(&str, &str)] = &[
    (
        "parent traversal",
        r#"{"owner":["cordon-verify","a"],"path":"../b/secret"}"#,
    ),
    (
        "deep traversal",
        r#"{"owner":["cordon-verify","a"],"path":"../../../../etc/passwd"}"#,
    ),
    (
        "absolute path",
        r#"{"owner":["cordon-verify","a"],"path":"/etc/passwd"}"#,
    ),
    (
        "percent encoded",
        r#"{"owner":["cordon-verify","a"],"path":"..%2fb%2fsecret"}"#,
    ),
    (
        "backslash separator",
        r#"{"owner":["cordon-verify","a"],"path":"..\\b\\secret"}"#,
    ),
    (
        "dotdot owner",
        r#"{"owner":["cordon-verify",".."],"path":"x"}"#,
    ),
    (
        "separator in owner",
        r#"{"owner":["cordon-verify","a/b"],"path":"x"}"#,
    ),
    (
        "non ascii owner",
        r#"{"owner":["cordon-verify","café"],"path":"x"}"#,
    ),
    (
        "reach the token store",
        r#"{"owner":["cordon-verify","a"],"path":"../../artifacts"}"#,
    ),
];

pub async fn run(addr: &str) -> Result<Vec<Check>, String> {
    let host = addr
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut out = Vec::with_capacity(ATTEMPTS.len());

    for (name, payload) in ATTEMPTS {
        let (status, body) = post(&host, "/v1/resolve", payload).await?;
        // A refusal counts only when it is a 4xx carrying a code. A bodiless
        // 403 from a proxy in front of a broken daemon proves nothing.
        let code = json_string(&body, "code");
        let passed = (400..500).contains(&status) && code.is_some();
        out.push(Check {
            name,
            passed,
            detail: format!(
                "status {status}, code {}",
                code.unwrap_or_else(|| "<none>".into())
            ),
        });
    }
    Ok(out)
}

pub fn report(checks: &[Check], w: &mut impl Write) -> bool {
    let failed = checks.iter().filter(|c| !c.passed).count();
    for c in checks {
        let mark = if c.passed { "ok  " } else { "FAIL" };
        let _ = writeln!(w, "{mark} {:<24} {}", c.name, c.detail);
    }
    if failed > 0 {
        let _ = writeln!(w, "\n{failed} of {} checks failed", checks.len());
        return false;
    }
    let _ = writeln!(w, "\nall {} checks passed", checks.len());
    true
}

async fn post(host: &str, path: &str, payload: &str) -> Result<(u16, String), String> {
    let connect = tokio::net::TcpStream::connect(host);
    let mut sock = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| format!("connect {host}: timed out"))?
        .map_err(|e| format!("connect {host}: {e}"))?;

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    sock.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut raw))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|e| e.to_string())?;

    let text = String::from_utf8_lossy(&raw);
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "no status line in response".to_string())?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Pulls one string value out of a JSON object without a parser. verify reads
/// exactly one field and runs once by hand, so the dependency is not worth it.
fn json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one shot server, so the test exercises the real HTTP path without
    /// standing up the whole daemon.
    async fn serve(body: &'static str, status: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn every_check_passes_against_a_daemon_that_refuses() {
        let addr = serve(
            r#"{"error":{"code":"path_escapes_workspace","message":"no"}}"#,
            403,
        )
        .await;
        let checks = run(&addr).await.unwrap();
        assert!(!checks.is_empty(), "no checks ran");
        for c in &checks {
            assert!(c.passed, "{} failed: {}", c.name, c.detail);
        }
    }

    #[tokio::test]
    async fn checks_fail_against_a_daemon_that_allows_an_escape() {
        let addr = serve(r#"{"resolved":"/etc/passwd","exists":true}"#, 200).await;
        let checks = run(&addr).await.unwrap();
        assert!(
            checks.iter().any(|c| !c.passed),
            "a permissive daemon passed every check"
        );
    }

    /// A 403 with an empty body proves nothing: a reverse proxy in front of a
    /// broken daemon returns exactly that.
    #[tokio::test]
    async fn a_refusal_with_no_code_does_not_count_as_a_pass() {
        let addr = serve("", 403).await;
        let checks = run(&addr).await.unwrap();
        assert!(
            checks.iter().any(|c| !c.passed),
            "a bodiless 403 was accepted as proof"
        );
    }

    #[tokio::test]
    async fn an_unreachable_daemon_is_an_error_not_a_pass() {
        assert!(run("http://127.0.0.1:1").await.is_err());
    }

    #[test]
    fn the_report_says_fail_loudly_and_returns_false() {
        let checks = vec![
            Check {
                name: "parent traversal",
                passed: true,
                detail: "status 403".into(),
            },
            Check {
                name: "absolute path",
                passed: false,
                detail: "status 200".into(),
            },
        ];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(!ok);
        assert!(text.contains("FAIL"), "{text}");
        assert!(text.contains("1 of 2 checks failed"), "{text}");
    }
}
