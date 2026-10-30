//! GET /v1/stdio. A long-lived job whose stdin and stdout travel over a WebSocket, one line a message, so an
//! MCP server runs in its owner's sandbox for as long as its client stays connected (#27).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::Extension;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::exec::{Job, Limits, Spawned};
use crate::http::ApiError;
use crate::resolve::owner_or_error;
use crate::run::{exec_error, network_from, pick_backend, workspace_error};
use crate::token::Scope;

/// No MCP message comes near this; a line that does is stopped, not buffered without end.
const MAX_LINE: u64 = 4 * 1024 * 1024;
/// A server's credentials and settings, not a payload channel.
const MAX_ENV: usize = 16;
const MAX_ENV_VALUE: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StdioRequest {
    owner: Vec<String>,
    entrypoint: String,
    #[serde(default)]
    args: Vec<String>,
    /// "none" or "open", as in `/v1/run`. Absent means the backend's own default, and the answer says which.
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    hosts: BTreeMap<String, String>,
    /// May lower the operator's ceiling, never raise it.
    #[serde(default)]
    memory_mb: Option<u64>,
    #[serde(default)]
    backend: Option<String>,
    /// The job's own environment, such as a token its server needs. It reaches only the job: never a
    /// command line, a log or the container CLI's own environment.
    #[serde(default)]
    env: BTreeMap<String, String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| serve(cfg, scope, socket))
}

async fn serve(cfg: Arc<Config>, scope: Scope, mut socket: WebSocket) {
    let first = match socket.recv().await {
        Some(Ok(Message::Text(t))) => t,
        _ => return,
    };
    let spawned = match start(&cfg, &scope, first.as_str()).await {
        Ok(started) => started,
        Err(e) => {
            let mut error = json!({ "code": e.code, "message": e.message });
            if let Some(detail) = e.detail {
                error["detail"] = detail;
            }
            let _ = socket
                .send(Message::Text(json!({ "error": error }).to_string().into()))
                .await;
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    let ready = json!({ "ok": true, "network": spawned.network.label() }).to_string();
    if socket.send(Message::Text(ready.into())).await.is_err() {
        return;
    }
    relay(socket, spawned).await;
}

/// The same owner, scope, backend floor and network checks as `/v1/run`; only the wait differs.
async fn start(cfg: &Config, scope: &Scope, first: &str) -> Result<Spawned, ApiError> {
    let req: StdioRequest = serde_json::from_str(first).map_err(|e| {
        ApiError::bad_request(
            "invalid_request",
            format!("the first message is not a stdio job: {e}"),
        )
    })?;
    let owner = owner_or_error(scope, &req.owner)?;
    let memory_mb = match req.memory_mb {
        None => cfg.max_memory_mb,
        Some(m) if m > 0 && m <= cfg.max_memory_mb => m,
        Some(_) => {
            return Err(ApiError::bad_request(
                "limit_exceeded",
                "memory_mb is zero or above the configured ceiling",
            )
            .with_detail(json!({ "max_memory_mb": cfg.max_memory_mb })))
        }
    };
    check_env(&req.env)?;
    let backend = pick_backend(cfg, req.backend.as_deref())?;
    let network = network_from(req.network.as_deref(), &req.hosts)?;

    let workspace = owner.dir(&cfg.root);
    std::fs::create_dir_all(&workspace).map_err(|e| workspace_error(e, &owner))?;
    let job = Job {
        workspace,
        entrypoint: req.entrypoint,
        args: req.args,
        stdin: String::new(),
        // No wall clock: the job lives as long as its socket. The process backend still caps CPU at 60s.
        limits: Limits {
            wall_ms: cfg.max_wall_ms,
            memory_mb,
            stdout_kb: 0,
        },
        network,
        unsafe_process: cfg.unsafe_process_backend,
        env: req.env.into_iter().collect(),
    };
    backend.spawn(&job).await.map_err(exec_error)
}

/// A plain name, a bounded value, one line each, so it fits an env file and cannot become a second variable.
fn check_env(env: &BTreeMap<String, String>) -> Result<(), ApiError> {
    let bad = |m: String| Err(ApiError::bad_request("invalid_request", m));
    if env.len() > MAX_ENV {
        return bad(format!("env has more than {MAX_ENV} variables"));
    }
    for (k, v) in env {
        let name_ok = !k.is_empty()
            && k.len() <= 64
            && k.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !name_ok {
            return bad(format!("env name {k:?} is not a plain variable name"));
        }
        if v.len() > MAX_ENV_VALUE || v.contains(['\n', '\r', '\0']) {
            return bad(format!(
                "the value of {k} is too long or has a newline or a NUL"
            ));
        }
    }
    Ok(())
}

/// Both directions until either side ends. The client leaving kills the job; the job ending closes the socket.
/// The env file goes with `spawned` when this returns.
async fn relay(mut socket: WebSocket, spawned: Spawned) {
    let Spawned {
        mut child,
        env_file: _env_file,
        ..
    } = spawned;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill().await;
        return;
    };
    // stderr is never relayed, since it can carry what the server was given; it is drained so a full
    // pipe cannot stall the job.
    if let Some(mut stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        });
    }
    let mut out = BufReader::new(stdout);
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                // A JSON-RPC message is one line; a raw newline inside one would split it in two.
                Some(Ok(Message::Text(t))) if !t.as_str().contains('\n') => {
                    let line = format!("{}\n", t.as_str());
                    if stdin.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => break,
            },
            line = next_line(&mut out) => match line {
                Some(l) => {
                    if socket.send(Message::Text(l.into())).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    let _ = child.kill().await;
    let _ = socket.send(Message::Close(None)).await;
}

/// One stdout line without its newline; None at the end of the stream or past MAX_LINE.
async fn next_line<R: AsyncRead + Unpin>(out: &mut BufReader<R>) -> Option<String> {
    let mut buf = Vec::new();
    let n = (&mut *out)
        .take(MAX_LINE)
        .read_until(b'\n', &mut buf)
        .await
        .ok()?;
    if n == 0 || (buf.last() != Some(&b'\n') && n as u64 == MAX_LINE) {
        return None;
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message as Msg;

    use crate::testsupport::{fixture, fixture_with_token, Fixture};

    async fn serve(f: &Fixture) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::http::router(std::sync::Arc::clone(&f.cfg));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("ws://{addr}/v1/stdio")
    }

    async fn open(
        url: &str,
        token: Option<&str>,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Error,
    > {
        let mut req = url.into_client_request().unwrap();
        if let Some(t) = token {
            req.headers_mut()
                .insert("authorization", format!("Bearer {t}").parse().unwrap());
        }
        tokio_tungstenite::connect_async(req)
            .await
            .map(|(ws, _)| ws)
    }

    async fn text<S>(ws: &mut S) -> String
    where
        S: futures_util::Stream<Item = Result<Msg, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        loop {
            match ws.next().await {
                Some(Ok(Msg::Text(t))) => return t.to_string(),
                Some(Ok(Msg::Ping(_) | Msg::Pong(_))) => continue,
                other => panic!("expected text, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_stdio_job_relays_one_line_each_way_until_the_client_leaves() {
        let f = fixture("stdio-echo");
        let mut ws = open(&serve(&f).await, None).await.unwrap();
        ws.send(Msg::Text(
            r#"{"owner":["acme","budi"],"entrypoint":"cat"}"#.into(),
        ))
        .await
        .unwrap();
        let ready: serde_json::Value = serde_json::from_str(&text(&mut ws).await).unwrap();
        assert_eq!(ready["ok"], true, "{ready}");
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":2}"#,
        ] {
            ws.send(Msg::Text(line.into())).await.unwrap();
            assert_eq!(text(&mut ws).await, line);
        }
        ws.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn a_job_that_exits_closes_the_socket() {
        let f = fixture("stdio-exit");
        let mut ws = open(&serve(&f).await, None).await.unwrap();
        ws.send(Msg::Text(
            r#"{"owner":["acme","budi"],"entrypoint":"true"}"#.into(),
        ))
        .await
        .unwrap();
        let _ready = text(&mut ws).await;
        let end = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match ws.next().await {
                    None | Some(Ok(Msg::Close(_))) | Some(Err(_)) => return,
                    _ => continue,
                }
            }
        })
        .await;
        assert!(end.is_ok(), "the socket stayed open after the job exited");
    }

    #[tokio::test]
    async fn a_bad_first_message_or_a_limit_above_the_ceiling_is_refused_in_cordons_shape() {
        let f = fixture("stdio-refuse");
        let url = serve(&f).await;
        for (job, code) in [
            (r#"{"entrypoint":"cat"}"#, "invalid_request"),
            (
                r#"{"owner":["acme","budi"],"entrypoint":"cat","memory_mb":999999}"#,
                "limit_exceeded",
            ),
            (
                r#"{"owner":["acme","budi"],"entrypoint":"cat","network":"maybe"}"#,
                "invalid_request",
            ),
            (
                r#"{"owner":["acme","budi"],"entrypoint":"cat","stdin":"x"}"#,
                "invalid_request",
            ),
        ] {
            let mut ws = open(&url, None).await.unwrap();
            ws.send(Msg::Text(job.into())).await.unwrap();
            let out: serde_json::Value = serde_json::from_str(&text(&mut ws).await).unwrap();
            assert_eq!(out["error"]["code"], code, "{job}: {out}");
        }
    }

    #[tokio::test]
    async fn the_socket_needs_the_token() {
        let f = fixture_with_token("stdio-token", "s3cret");
        let url = serve(&f).await;
        assert!(open(&url, None).await.is_err(), "upgraded without a token");
        assert!(
            open(&url, Some("WRONG")).await.is_err(),
            "upgraded with a wrong token"
        );
        let mut ws = open(&url, Some("s3cret")).await.unwrap();
        ws.send(Msg::Text(
            r#"{"owner":["acme","budi"],"entrypoint":"cat"}"#.into(),
        ))
        .await
        .unwrap();
        let ready: serde_json::Value = serde_json::from_str(&text(&mut ws).await).unwrap();
        assert_eq!(ready["ok"], true, "{ready}");
    }

    #[tokio::test]
    async fn a_stdio_job_gets_its_env_and_a_bad_name_or_value_is_refused() {
        let f = fixture("stdio-env");
        let url = serve(&f).await;
        let mut ws = open(&url, None).await.unwrap();
        let job = r#"{"owner":["acme","budi"],"entrypoint":"sh","args":["-c","echo \"$GREETING\"; cat"],"env":{"GREETING":"hello there"}}"#;
        ws.send(Msg::Text(job.into())).await.unwrap();
        let _ready = text(&mut ws).await;
        assert_eq!(text(&mut ws).await, "hello there");
        for env in [r#"{"A-B":"x"}"#, r#"{"1X":"x"}"#, r#"{"A":"one\nB=two"}"#] {
            let mut ws = open(&url, None).await.unwrap();
            let job = format!(r#"{{"owner":["acme","budi"],"entrypoint":"cat","env":{env}}}"#);
            ws.send(Msg::Text(job.into())).await.unwrap();
            let out: serde_json::Value = serde_json::from_str(&text(&mut ws).await).unwrap();
            assert_eq!(out["error"]["code"], "invalid_request", "{env}: {out}");
        }
    }
}
