// deny, not forbid: exec and sandbox need unsafe for their syscalls, which forbid cannot allow.
#![deny(unsafe_code)]

mod artifact;
mod config;
mod demo;
mod exec;
mod fork;
mod guard;
mod http;
mod owner;
mod resolve;
mod run;
mod sandbox;
mod stdio;
mod style;
#[cfg(test)]
mod testsupport;
mod token;
mod verify;

use std::sync::Arc;

const USAGE: &str = "\
cordon gives each owner an isolated workspace and refuses every path out of it.

  cordon serve             run the daemon
  cordon verify [addr] [token] [--root <CORDON_ROOT>]
                           prove the guarantee against a running daemon;
                           --root removes the probe workspaces afterwards
  cordon demo [root]       two owners, every escape refused, no daemon needed
";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve().await,
        Some("verify") => {
            let mut args = args[1..].to_vec();
            // Wherever it appears, so it can be appended to an existing call.
            let root = match args.iter().position(|a| a == "--root") {
                None => None,
                Some(i) if i + 1 < args.len() => {
                    let path = args.remove(i + 1);
                    args.remove(i);
                    Some(std::path::PathBuf::from(path))
                }
                Some(_) => {
                    eprintln!("cordon: --root needs the daemon's CORDON_ROOT");
                    return std::process::ExitCode::from(2);
                }
            };
            let addr = args
                .first()
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:7777".into());
            // Argument or environment, so a pipeline keeps the secret off the command line.
            let token = args
                .get(1)
                .cloned()
                .or_else(|| std::env::var("CORDON_TOKEN").ok())
                .filter(|t| !t.is_empty());
            match verify::run(&addr, token.as_deref()).await {
                Err(e) => Err(e),
                Ok(checks) => {
                    let style = style::Style::for_stdout();
                    let passed = verify::report(&checks, &mut std::io::stdout(), style);
                    verify::tidy(root.as_deref(), passed, &mut std::io::stdout(), style);
                    if passed {
                        Ok(())
                    } else {
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
        }
        Some("demo") => {
            // An optional root, so a reader can watch it and a recording shows no temp path.
            let root = match args.get(1) {
                Some(p) => std::path::PathBuf::from(p),
                None => std::env::temp_dir().join(format!("cordon-demo-{}", std::process::id())),
            };
            match demo::run(&root, &mut std::io::stdout(), style::Style::for_stdout()) {
                Ok(true) => Ok(()),
                Ok(false) => return std::process::ExitCode::FAILURE,
                Err(e) => Err(e.to_string()),
            }
        }
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

    // Only stops records piling up: an expired artifact is refused either way.
    // The first tick fires at once, so a restart sweeps too.
    let root = cfg.root.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let root = root.clone();
            let _ = tokio::task::spawn_blocking(move || {
                artifact::reap(&root);
                token::reap(&root);
            })
            .await;
        }
    });
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
        Err(format!(
            "CORDON_LISTEN={:?} must start with unix: or tcp:",
            cfg.listen
        ))
    }
}
