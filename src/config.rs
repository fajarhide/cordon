//! Settings, read once at startup from the environment.
//!
//! Every setting has a working default so cordon starts with no configuration
//! and still gives the isolation guarantee. The listener is the one setting
//! that can refuse to start the daemon, because a listener the network can
//! reach with no token is not a default anyone chose on purpose.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Only the tests need this list, to clear the environment between cases.
#[cfg(test)]
pub const KEYS: &[&str] = &[
    "CORDON_ROOT",
    "CORDON_LISTEN",
    "CORDON_TOKEN",
    "CORDON_BACKEND",
    "CORDON_IMAGE",
    "CORDON_ARTIFACT_TTL",
    "CORDON_MAX_WALL_MS",
    "CORDON_MAX_MEMORY_MB",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub listen: String,
    pub token: Option<String>,
    pub backend: String,
    pub image: String,
    pub artifact_ttl: Duration,
    pub max_wall_ms: u64,
    pub max_memory_mb: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let cfg = Config {
            root: PathBuf::from(env("CORDON_ROOT", "/var/lib/cordon")),
            listen: env("CORDON_LISTEN", "unix:/run/cordond.sock"),
            token: std::env::var("CORDON_TOKEN").ok().filter(|t| !t.is_empty()),
            backend: env("CORDON_BACKEND", "process"),
            image: env("CORDON_IMAGE", "alpine:3.20"),
            artifact_ttl: parse_duration(&env("CORDON_ARTIFACT_TTL", "24h"))?,
            max_wall_ms: env_u64("CORDON_MAX_WALL_MS", 60_000),
            max_memory_mb: env_u64("CORDON_MAX_MEMORY_MB", 1024),
        };
        if cfg.backend != "process" && cfg.backend != "container" {
            return Err(format!(
                "CORDON_BACKEND={:?} is not a backend, want process or container",
                cfg.backend
            ));
        }
        cfg.require_token_if_public()?;
        Ok(cfg)
    }

    /// Refuses to start on an address other machines can reach unless a token
    /// is set. Starting anyway hands every caller on the network the ability to
    /// name any owner it likes, which is the whole guarantee gone.
    fn require_token_if_public(&self) -> Result<(), String> {
        let Some(addr) = self.listen.strip_prefix("tcp:") else {
            return Ok(());
        };
        if self.token.is_some() {
            return Ok(());
        }
        let host = split_host(addr)
            .ok_or_else(|| format!("CORDON_LISTEN={:?} is not host:port", self.listen))?;
        let loopback = host == "localhost"
            || host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if loopback {
            return Ok(());
        }
        Err(format!(
            "CORDON_LISTEN={:?} is reachable from the network but CORDON_TOKEN is unset",
            self.listen
        ))
    }
}

/// Splits host from port, keeping a bracketed IPv6 literal in one piece.
fn split_host(addr: &str) -> Option<&str> {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next();
    }
    let (host, port) = addr.rsplit_once(':')?;
    (!port.is_empty()).then_some(host)
}

/// A deliberately small duration grammar: seconds, minutes, hours, days.
/// Pulling in a date library to read "24h" is not a trade worth making.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (digits, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = digits.parse().map_err(|_| {
        format!("CORDON_ARTIFACT_TTL={s:?} is not a number followed by s, m, h or d")
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => {
            return Err(format!(
                "CORDON_ARTIFACT_TTL={s:?} must end in s, m, h or d"
            ))
        }
    };
    Ok(Duration::from_secs(secs))
}

fn env(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn env_u64(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test mutates process environment, so they share one lock rather
    /// than racing each other under the default parallel test runner.
    fn with_env<T>(pairs: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _g = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for key in KEYS {
            std::env::remove_var(key);
        }
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        let out = f();
        for key in KEYS {
            std::env::remove_var(key);
        }
        out
    }

    #[test]
    fn defaults_are_usable_with_no_configuration() {
        let cfg = with_env(&[], Config::from_env).expect("defaults must load");
        assert_eq!(cfg.root, PathBuf::from("/var/lib/cordon"));
        assert_eq!(cfg.listen, "unix:/run/cordond.sock");
        assert_eq!(cfg.backend, "process");
        assert_eq!(cfg.artifact_ttl, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn refuses_a_public_listener_with_no_token() {
        let err = with_env(&[("CORDON_LISTEN", "tcp:0.0.0.0:7777")], Config::from_env)
            .expect_err("a public listener with no token must refuse to start");
        assert!(err.contains("CORDON_TOKEN"), "unhelpful error: {err}");
    }

    #[test]
    fn allows_loopback_with_no_token() {
        for addr in ["tcp:127.0.0.1:7777", "tcp:[::1]:7777", "tcp:localhost:7777"] {
            with_env(&[("CORDON_LISTEN", addr)], Config::from_env)
                .unwrap_or_else(|e| panic!("{addr} should be allowed: {e}"));
        }
    }

    #[test]
    fn allows_a_public_listener_once_a_token_is_set() {
        with_env(
            &[
                ("CORDON_LISTEN", "tcp:0.0.0.0:7777"),
                ("CORDON_TOKEN", "s3cret"),
            ],
            Config::from_env,
        )
        .expect("a token makes a public listener legal");
    }

    #[test]
    fn refuses_an_unknown_backend() {
        with_env(&[("CORDON_BACKEND", "firecracker")], Config::from_env)
            .expect_err("an unknown backend must refuse to start");
    }

    #[test]
    fn refuses_an_unparseable_ttl() {
        with_env(&[("CORDON_ARTIFACT_TTL", "ages")], Config::from_env)
            .expect_err("a bad duration must refuse to start");
    }
}
