#![forbid(unsafe_code)]

mod config;
mod owner;
mod http;

use std::sync::Arc;

const USAGE: &str = "\
cordon gives each owner an isolated workspace and refuses every path out of it.

  cordon serve             run the daemon
  cordon verify [addr]     prove the isolation guarantee against a running daemon
  cordon demo              two owners, every escape refused, no daemon needed
";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve().await,
        Some("-h") | Some("--help") | Some("help") => {
            print!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        Some(other) => {
            eprint!("cordon: unknown command {other:?}\n\n{USAGE}");
            return std::process::ExitCode::from(2);
        }
        None => {
            eprint!("{USAGE}");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cordon: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), String> {
    let cfg = Arc::new(config::Config::from_env()?);
    let app = http::router(Arc::clone(&cfg));
    println!(
        "cordon listening on {}, root {}, backend {}",
        cfg.listen,
        cfg.root.display(),
        cfg.backend
    );

    if let Some(path) = cfg.listen.strip_prefix("unix:") {
        // A stale socket from a killed daemon would otherwise block the bind.
        let _ = std::fs::remove_file(path);
        let listener =
            tokio::net::UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    } else if let Some(addr) = cfg.listen.strip_prefix("tcp:") {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    } else {
        Err(format!("CORDON_LISTEN={:?} must start with unix: or tcp:", cfg.listen))
    }
}
