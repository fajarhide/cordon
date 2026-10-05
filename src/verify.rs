//! `cordon verify` proves the isolation against a running daemon through the data plane (#14).
//! Probes live under the reserved owner prefix `cordon-verify`; `--root` removes them (#20).

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::style::Style;

pub enum Outcome {
    Pass,
    Fail,
    /// Could not be tested here, with the reason. Never counted as a pass.
    Skip(String),
}

pub struct Check {
    pub name: &'static str,
    pub outcome: Outcome,
    pub detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            outcome: Outcome::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            outcome: Outcome::Fail,
            detail: detail.into(),
        }
    }
    fn skip(name: &'static str, why: impl Into<String>) -> Self {
        Check {
            name,
            outcome: Outcome::Skip(why.into()),
            detail: String::new(),
        }
    }
    /// A refusal counts only as a 4xx carrying a code: a bodiless 403 from a proxy proves nothing.
    /// `unauthorized` is a skip, since refusing for want of a token says nothing about paths.
    fn refused(name: &'static str, status: u16, body: &str) -> Self {
        let code = json_string(body, "code");
        match code.as_deref() {
            Some("unauthorized") => Check::skip(
                name,
                "refused for want of a token, so this property was not tested",
            ),
            Some(c) if (400..500).contains(&status) => {
                Check::pass(name, format!("status {status}, code {c}"))
            }
            Some(c) => Check::fail(name, format!("status {status}, code {c}")),
            None => Check::fail(name, format!("status {status}, no error code in the body")),
        }
    }
}

const OWNER_A: &str = r#"["cordon-verify","a"]"#;
const OWNER_B: &str = r#"["cordon-verify","b"]"#;
const SECRET: &str = "CORDON-VERIFY-SECRET-B";

/// Named once so a skipped run lists exactly the same checks a full one does.
const DATA_PLANE_NAMES: [&str; 6] = [
    "a job cannot read another owner",
    "an artifact needs its owner",
    "an artifact refuses another owner",
    "an artifact works for its owner",
    "a weaker backend is refused",
    "a zero memory limit is refused",
];

/// Named once for the same reason (#17).
const SCOPE_NAMES: [&str; 9] = [
    "scoped: its own prefix works",
    "scoped: another owner refused",
    "scoped: a lookalike refused",
    "scoped: its parent refused",
    "scoped: no inherit above it",
    "scoped: no fork across",
    "scoped: cannot issue tokens",
    "scoped: refused past its ttl",
    "scoped: refused once revoked",
];

/// Path strings posted to `/v1/resolve`, each one a confused or hostile caller actually sends.
const PATH_ATTEMPTS: &[(&str, &str)] = &[
    (
        "parent traversal",
        r#"{"owner":["cordon-verify","a"],"path":"../b/secret.md","inherit":true}"#,
    ),
    (
        "deep traversal",
        r#"{"owner":["cordon-verify","a"],"path":"../../../../etc/passwd","inherit":true}"#,
    ),
    (
        "absolute path",
        r#"{"owner":["cordon-verify","a"],"path":"/etc/passwd"}"#,
    ),
    (
        "percent encoded",
        r#"{"owner":["cordon-verify","a"],"path":"..%2fb%2fsecret.md"}"#,
    ),
    (
        "backslash separator",
        r#"{"owner":["cordon-verify","a"],"path":"..\\b\\secret.md"}"#,
    ),
    (
        "parent mid path",
        r#"{"owner":["cordon-verify","a"],"path":"sub/../../b/secret.md"}"#,
    ),
    (
        "dot segment",
        r#"{"owner":["cordon-verify","a"],"path":"./secret.md"}"#,
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
        "uppercase owner",
        r#"{"owner":["cordon-verify","A"],"path":"x"}"#,
    ),
    (
        "reach the token store",
        r#"{"owner":["cordon-verify","a"],"path":"../../artifacts","inherit":true}"#,
    ),
    (
        "parent reaches its child",
        r#"{"owner":["cordon-verify"],"path":"b/secret.md","inherit":true}"#,
    ),
    (
        "parent reaches the child leaf",
        r#"{"owner":["cordon-verify"],"path":"b/.workspace/secret.md","inherit":true}"#,
    ),
];

pub async fn run(addr: &str, token: Option<&str>) -> Result<Vec<Check>, String> {
    let host = addr
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let c = Client {
        host,
        token: token.map(str::to_string),
    };

    // Liveness first, so a dead daemon is reported once rather than per check.
    let (status, _) = c.get("/v1/health").await?;
    if status != 200 {
        return Err(format!("/v1/health answered {status}"));
    }

    let mut out = Vec::new();
    let (auth, usable) = auth_checks(&c).await?;
    out.extend(auth);

    // Without usable credentials every check is a 401, which must not read as a refusal.
    if !usable {
        let why = "no usable credentials for this daemon; pass a token as the second argument or in CORDON_TOKEN".to_string();
        out.extend(
            PATH_ATTEMPTS
                .iter()
                .map(|(n, _)| Check::skip(n, why.clone())),
        );
        out.extend(DATA_PLANE_NAMES.iter().map(|n| Check::skip(n, why.clone())));
        out.extend(SCOPE_NAMES.iter().map(|n| Check::skip(n, why.clone())));
        return Ok(out);
    }

    out.extend(path_checks(&c).await?);
    out.extend(data_plane_checks(&c).await?);
    out.extend(scope_checks(&c).await?);
    Ok(out)
}

/// Returns the auth checks, and whether the rest of the suite can run at all.
async fn auth_checks(c: &Client) -> Result<(Vec<Check>, bool), String> {
    let body = r#"{"owner":["cordon-verify","a"],"path":"x.md"}"#;

    // Whether a token is configured is discovered, not assumed.
    let bare = Client {
        host: c.host.clone(),
        token: None,
    };
    let (status, _) = bare.post("/v1/resolve", body).await?;

    if c.token.is_none() {
        let needs_token = status == 401;
        let why = if needs_token {
            "this daemon requires a token and none was given; pass one as the second argument or in CORDON_TOKEN"
        } else {
            "no token configured on this daemon, so there is nothing to enforce"
        };
        return Ok((
            vec![
                Check::skip("no credentials refused", why),
                Check::skip("a wrong token refused", why),
            ],
            // An open daemon is fine to probe; one that wants a token we lack is not.
            !needs_token,
        ));
    }

    let mut v = vec![if status == 401 {
        Check::pass("no credentials refused", "status 401, code unauthorized")
    } else {
        Check::fail(
            "no credentials refused",
            format!("status {status}: a token is configured and an unauthenticated request worked"),
        )
    }];

    let wrong = Client {
        host: c.host.clone(),
        token: Some("cordon-verify-wrong-token".into()),
    };
    let (status, _) = wrong.post("/v1/resolve", body).await?;
    v.push(if status == 401 {
        Check::pass("a wrong token refused", "status 401, code unauthorized")
    } else {
        Check::fail("a wrong token refused", format!("status {status}"))
    });
    Ok((v, true))
}

async fn path_checks(c: &Client) -> Result<Vec<Check>, String> {
    let mut out = Vec::with_capacity(PATH_ATTEMPTS.len());
    for (name, payload) in PATH_ATTEMPTS {
        let (status, raw) = c.post("/v1/resolve", payload).await?;
        out.push(Check::refused(name, status, &raw));
    }
    Ok(out)
}

/// Goes through `/v1/run` and artifacts, which the path checks cannot see (#14).
async fn data_plane_checks(c: &Client) -> Result<Vec<Check>, String> {
    let names = DATA_PLANE_NAMES;

    // Owner b writes the secret. If /v1/run cannot run here, the checks that need it skip.
    let seed = format!(
        r#"{{"owner":{OWNER_B},"entrypoint":"sh","args":["-c","printf {SECRET} > secret.md"],
             "limits":{{"wall_ms":10000,"memory_mb":128,"stdout_kb":16}}}}"#
    );
    // These two are refused before any job runs, so they must not be gated on the seed.
    let mut out = vec![floor_check(c).await?, zero_memory_check(c).await?];

    let (status, raw) = c.post("/v1/run", &seed).await?;
    if status != 200 {
        let why = format!(
            "/v1/run answered {status} ({}), so the data plane could not be exercised",
            json_string(&raw, "code").unwrap_or_else(|| "no code".into())
        );
        out.extend(names[..4].iter().map(|n| Check::skip(n, why.clone())));
        return Ok(out);
    }

    // Owner a's job goes at it directly, bypassing the path layer (#1).
    let attack = format!(
        r#"{{"owner":{OWNER_A},"entrypoint":"sh","args":["-c",
             "cat ../../b/.workspace/secret.md 2>&1; cat ../b/secret.md 2>&1; find / -name secret.md 2>/dev/null | head -3; echo VERIFY-DONE"],
             "limits":{{"wall_ms":20000,"memory_mb":128,"stdout_kb":64}}}}"#
    );
    let (status, raw) = c.post("/v1/run", &attack).await?;
    out.push(if status != 200 {
        Check::skip(
            names[0],
            format!("the probing job did not run, status {status}"),
        )
    } else if raw.contains(SECRET) {
        Check::fail(names[0], "a job read another owner's file")
    } else if raw.contains("VERIFY-DONE") {
        Check::pass(names[0], "the job ran and could not reach it")
    } else {
        Check::skip(names[0], "the probing job produced no output to judge")
    });

    // An artifact, then the three ways of asking for it.
    let mint = format!(
        r#"{{"owner":{OWNER_A},"entrypoint":"sh","args":["-c","printf own > mine.txt"],
             "collect":["mine.txt"],
             "limits":{{"wall_ms":10000,"memory_mb":128,"stdout_kb":16}}}}"#
    );
    let (status, raw) = c.post("/v1/run", &mint).await?;
    match (status, json_string(&raw, "token")) {
        (200, Some(tok)) => {
            let (s, b) = c.get(&format!("/v1/artifact/{tok}")).await?;
            out.push(if (400..500).contains(&s) {
                Check::pass(names[1], format!("status {s} with no owner"))
            } else {
                Check::fail(names[1], format!("status {s}: a bare token was enough"))
            });

            let (s, b2) = c
                .get(&format!("/v1/artifact/{tok}?owner=cordon-verify/b"))
                .await?;
            out.push(if (400..500).contains(&s) {
                if b == b2 {
                    Check::pass(names[2], format!("status {s}, same body as a bare fetch"))
                } else {
                    Check::fail(
                        names[2],
                        "refused, but the body differs from a bare fetch, which confirms the token exists",
                    )
                }
            } else {
                Check::fail(names[2], format!("status {s}: another owner fetched it"))
            });

            let (s, b3) = c
                .get(&format!("/v1/artifact/{tok}?owner=cordon-verify/a"))
                .await?;
            out.push(if s == 200 && b3 == "own" {
                Check::pass(names[3], "the owner got its own bytes")
            } else {
                Check::fail(names[3], format!("status {s}, body {b3:?}"))
            });
        }
        (s, _) => {
            let why = format!("no artifact could be minted, status {s}");
            out.push(Check::skip(names[1], why.clone()));
            out.push(Check::skip(names[2], why.clone()));
            out.push(Check::skip(names[3], why));
        }
    }

    Ok(out)
}

/// A token scoped to owner a, pointed at everything that is not owner a.
/// Relies on b's secret, which the data plane checks left on disk.
async fn scope_checks(c: &Client) -> Result<Vec<Check>, String> {
    let names = SCOPE_NAMES;
    let skip_all =
        |why: String| -> Vec<Check> { names.iter().map(|n| Check::skip(n, why.clone())).collect() };
    if c.token.is_none() {
        return Ok(skip_all(
            "no token configured on this daemon, so there is nothing to scope".into(),
        ));
    }

    let issue = r#"{"prefix":["cordon-verify","a"]}"#;
    let (status, raw) = c.post("/v1/token", issue).await?;
    let scoped = match (status, json_string(&raw, "token")) {
        (200, Some(t)) => Client {
            host: c.host.clone(),
            token: Some(t),
        },
        (s, _) => {
            return Ok(skip_all(format!(
                "no scoped token could be issued, status {s} ({})",
                json_string(&raw, "code").unwrap_or_else(|| "no code".into())
            )))
        }
    };

    // Only a scope refusal counts. Any other code failed for its own reasons and proves nothing.
    let outside = |name: &'static str, status: u16, raw: &str| {
        if raw.contains(SECRET) {
            return Check::fail(name, "the scoped token read another owner's file");
        }
        match json_string(raw, "code").as_deref() {
            Some("owner_outside_token_scope") if status == 403 => {
                Check::pass(name, "status 403, code owner_outside_token_scope")
            }
            Some(code) if (400..500).contains(&status) => Check::skip(
                name,
                format!("refused with {code}, which says nothing about the scope"),
            ),
            _ => Check::fail(
                name,
                format!("status {status}: the scope did not refuse it"),
            ),
        }
    };
    let mut out = Vec::with_capacity(names.len());

    // Inside the prefix first, to rule out a daemon that refuses this token everything.
    // Compared with the operator's answer: with no job run yet, owner a has no workspace
    // and the same request is refused for everyone.
    let inside = r#"{"owner":["cordon-verify","a"],"path":"x.md"}"#;
    let (operator, _) = c.post("/v1/resolve", inside).await?;
    let (status, _) = scoped.post("/v1/resolve", inside).await?;
    out.push(if operator != 200 {
        Check::skip(
            names[0],
            format!("the operator token gets status {operator} for that request too"),
        )
    } else if status == 200 {
        Check::pass(names[0], "status 200 for its own owner")
    } else {
        Check::fail(names[0], format!("status {status} for its own owner"))
    });

    let read_b = format!(
        r#"{{"owner":{OWNER_B},"entrypoint":"cat","args":["secret.md"],
             "limits":{{"wall_ms":10000,"memory_mb":128,"stdout_kb":16}}}}"#
    );
    let (status, raw) = scoped.post("/v1/run", &read_b).await?;
    out.push(outside(names[1], status, &raw));

    // cordon-verify/a2 starts with the same characters as cordon-verify/a.
    let (status, raw) = scoped
        .post(
            "/v1/resolve",
            r#"{"owner":["cordon-verify","a2"],"path":"x.md"}"#,
        )
        .await?;
    out.push(outside(names[2], status, &raw));

    let (status, raw) = scoped
        .post(
            "/v1/resolve",
            r#"{"owner":["cordon-verify"],"path":"x.md"}"#,
        )
        .await?;
    out.push(outside(names[3], status, &raw));

    // The operator reads the parent's file through inherit first, to show the reach is real.
    let plant = r#"{"owner":["cordon-verify"],"entrypoint":"sh","args":["-c","printf shared > shared.md"],
                    "limits":{"wall_ms":10000,"memory_mb":128,"stdout_kb":16}}"#;
    let up = r#"{"owner":["cordon-verify","a"],"path":"../shared.md","inherit":true}"#;
    let _ = c.post("/v1/run", plant).await?;
    let (baseline, _) = c.post("/v1/resolve", up).await?;
    let (status, raw) = scoped.post("/v1/resolve", up).await?;
    out.push(if baseline != 200 {
        Check::skip(
            names[4],
            format!(
                "the operator token could not reach the parent's file either, status {baseline}"
            ),
        )
    } else if status == 200 {
        Check::fail(names[4], "it resolved a file above its prefix")
    } else {
        Check::refused(names[4], status, &raw)
    });

    let steal = format!(r#"{{"from":{OWNER_B},"to":["cordon-verify","a","stolen"]}}"#);
    let (status, raw) = scoped.post("/v1/fork", &steal).await?;
    out.push(outside(names[5], status, &raw));

    let (status, raw) = scoped.post("/v1/token", issue).await?;
    out.push(if json_string(&raw, "token").is_some() {
        Check::fail(names[6], "a scoped token issued another token")
    } else {
        Check::refused(names[6], status, &raw)
    });

    // Expiry and revocation (#23). Each token is shown to work first, so the
    // refusal afterwards is the daemon acting and not a token that never worked.
    let own = r#"{"owner":["cordon-verify","a"],"path":"x.md"}"#;
    let fresh = |raw: &str| {
        json_string(raw, "token").map(|t| Client {
            host: c.host.clone(),
            token: Some(t),
        })
    };

    let (_, raw) = c
        .post(
            "/v1/token",
            r#"{"prefix":["cordon-verify","a"],"ttl_seconds":1}"#,
        )
        .await?;
    out.push(match fresh(&raw) {
        None => Check::skip(names[7], "no short-lived token could be issued"),
        Some(short) => {
            let (before, _) = short.post("/v1/resolve", own).await?;
            tokio::time::sleep(Duration::from_millis(2100)).await;
            let (after, _) = short.post("/v1/resolve", own).await?;
            match (before, after) {
                (200, 401) => Check::pass(names[7], "status 200, then 401 two seconds later"),
                (200, s) => Check::fail(names[7], format!("status {s} after its ttl had passed")),
                (s, _) => Check::skip(names[7], format!("the token never worked, status {s}")),
            }
        }
    });

    let (_, raw) = c.post("/v1/token", issue).await?;
    out.push(match fresh(&raw) {
        None => Check::skip(names[8], "no token could be issued to revoke"),
        Some(doomed) => {
            let (before, _) = doomed.post("/v1/resolve", own).await?;
            let path = format!("/v1/token/{}", doomed.token.as_deref().unwrap_or_default());
            let (revoked, _) = c.send("DELETE", &path, None).await?;
            let (after, _) = doomed.post("/v1/resolve", own).await?;
            match (before, revoked, after) {
                (200, 200, 401) => Check::pass(names[8], "status 200, then 401 after the revoke"),
                (200, 200, s) => Check::fail(names[8], format!("status {s} after it was revoked")),
                (200, s, _) => Check::skip(
                    names[8],
                    format!("this daemon would not revoke it, status {s}"),
                ),
                (s, _, _) => Check::skip(names[8], format!("the token never worked, status {s}")),
            }
        }
    });

    Ok(out)
}

/// The floor only means something on a container-configured daemon, so a process one skips.
/// Refused before any job runs, so it needs no seed.
async fn floor_check(c: &Client) -> Result<Check, String> {
    let name = DATA_PLANE_NAMES[4];
    let downgrade = format!(
        r#"{{"owner":{OWNER_A},"entrypoint":"true","backend":"process",
             "limits":{{"wall_ms":5000,"memory_mb":64,"stdout_kb":8}}}}"#
    );
    let (status, raw) = c.post("/v1/run", &downgrade).await?;
    Ok(match json_string(&raw, "code").as_deref() {
        Some("backend_below_floor") => Check::pass(name, "status 400, code backend_below_floor"),
        Some("unauthorized") => Check::skip(name, "refused for want of a token"),
        _ if status == 200 || status == 503 => Check::skip(
            name,
            "this daemon is configured for the process backend, so there is no floor to test",
        ),
        _ => Check::fail(name, format!("status {status}, body {raw}")),
    })
}

/// Also refused before any job runs.
async fn zero_memory_check(c: &Client) -> Result<Check, String> {
    let zero = format!(
        r#"{{"owner":{OWNER_A},"entrypoint":"true",
             "limits":{{"wall_ms":5000,"memory_mb":0,"stdout_kb":8}}}}"#
    );
    let (status, raw) = c.post("/v1/run", &zero).await?;
    Ok(Check::refused(DATA_PLANE_NAMES[5], status, &raw))
}

pub fn report(checks: &[Check], w: &mut impl Write, s: Style) -> bool {
    let mut failed = 0usize;
    let mut skipped = 0usize;
    for c in checks {
        match &c.outcome {
            Outcome::Pass => {
                let _ = writeln!(w, "{}   {:<32} {}", s.green("ok"), c.name, s.dim(&c.detail));
            }
            Outcome::Fail => {
                failed += 1;
                let _ = writeln!(w, "{} {:<32} {}", s.red("FAIL"), c.name, c.detail);
            }
            Outcome::Skip(why) => {
                skipped += 1;
                let _ = writeln!(w, "{} {:<32} {}", s.yellow("skip"), c.name, s.dim(why));
            }
        }
    }
    let passed = checks.len() - failed - skipped;
    let _ = writeln!(w);
    if failed > 0 {
        let _ = writeln!(
            w,
            "{}",
            s.red(&format!(
                "{failed} failed, {passed} passed, {skipped} skipped"
            ))
        );
        return false;
    }
    // An all-skip run tested nothing, so a pipeline must not see it as a success.
    if passed == 0 {
        let _ = writeln!(
            w,
            "{}",
            s.red(&format!(
                "{passed} passed, {skipped} skipped. Nothing was actually tested, so this is not a pass."
            ))
        );
        return false;
    }
    if skipped > 0 {
        // A skip is an untested property, so the summary must not read as a clean pass (#14).
        let _ = writeln!(
            w,
            "{} {}",
            s.green(&format!("{passed} passed")),
            s.yellow(&format!(
                "{skipped} skipped. A skip is not a pass: those properties were not tested here."
            ))
        );
    } else {
        let _ = writeln!(w, "{}", s.green(&format!("all {passed} checks passed")));
    }
    true
}

/// Removes the probe workspaces, or says that they are still there (#20).
/// Only after a pass: a failed run is when somebody wants to inspect them.
pub fn tidy(root: Option<&Path>, passed: bool, w: &mut impl Write, s: Style) {
    let msg = match root {
        None => "Workspaces under the reserved owner prefix cordon-verify, and the token scoped to it, are left behind. Pass --root <CORDON_ROOT> to remove them.".to_string(),
        Some(_) if !passed => {
            "The run did not pass, so the cordon-verify workspaces were kept for inspection.".to_string()
        }
        Some(root) => {
            // Whole-prefix match, so an owner named cordon-verify-something keeps its tokens.
            for e in std::fs::read_dir(root.join("tokens")).into_iter().flatten().flatten() {
                if std::fs::read_to_string(e.path()).is_ok_and(|s| s.lines().next() == Some("cordon-verify/a")) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
            let probes = root.join("owners").join("cordon-verify");
            // A missing directory usually means the wrong root, so it is not called a success.
            if !probes.is_dir() {
                format!(
                    "Nothing to remove at {}. Is that the CORDON_ROOT of the daemon that was probed?",
                    probes.display()
                )
            } else {
                match std::fs::remove_dir_all(&probes) {
                    Ok(()) => format!("Removed the probe workspaces at {}.", probes.display()),
                    Err(e) => format!("Could not remove {}: {e}", probes.display()),
                }
            }
        }
    };
    let _ = writeln!(w, "\n{}", s.dim(&msg));
}

struct Client {
    host: String,
    token: Option<String>,
}

impl Client {
    async fn post(&self, path: &str, payload: &str) -> Result<(u16, String), String> {
        self.send("POST", path, Some(payload)).await
    }

    async fn get(&self, path: &str) -> Result<(u16, String), String> {
        self.send("GET", path, None).await
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        payload: Option<&str>,
    ) -> Result<(u16, String), String> {
        let connect = tokio::net::TcpStream::connect(&self.host);
        let mut sock = tokio::time::timeout(Duration::from_secs(5), connect)
            .await
            .map_err(|_| format!("connect {}: timed out", self.host))?
            .map_err(|e| format!("connect {}: {e}", self.host))?;

        let auth = match &self.token {
            Some(t) => format!("Authorization: Bearer {t}\r\n"),
            None => String::new(),
        };
        let req = match payload {
            Some(p) => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{p}",
                self.host,
                p.len()
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\n{auth}Connection: close\r\n\r\n",
                self.host
            ),
        };
        sock.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), sock.read_to_end(&mut raw))
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
}

/// Pulls one string value out of a JSON body. A few fields do not justify a parser dependency.
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

    /// A stub that answers every request but health the same way.
    async fn serve(body: &'static str, status: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();

                // Health always answers, or verify stops at liveness and reaches no check.
                let (status, body) = if req.contains("/v1/health") {
                    (200u16, r#"{"status":"ok"}"#.to_string())
                } else {
                    (status, body.to_string())
                };

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

    fn counts(checks: &[Check]) -> (usize, usize, usize) {
        let f = checks
            .iter()
            .filter(|c| matches!(c.outcome, Outcome::Fail))
            .count();
        let s = checks
            .iter()
            .filter(|c| matches!(c.outcome, Outcome::Skip(_)))
            .count();
        (checks.len() - f - s, f, s)
    }

    /// Asserts on the skips, not on "nothing failed": the blanket 403 is a genuine failure
    /// for the backend floor probe, which expects a 400 with its own code.
    #[tokio::test]
    async fn a_daemon_that_refuses_everything_cannot_prove_its_data_plane() {
        let addr = serve(
            r#"{"error":{"code":"path_escapes_workspace","message":"no"}}"#,
            403,
        )
        .await;
        let checks = run(&addr, None).await.unwrap();

        // The four checks that need a seed job are the ones that must skip.
        for name in &DATA_PLANE_NAMES[..4] {
            let c = checks
                .iter()
                .find(|c| &c.name == name)
                .unwrap_or_else(|| panic!("{name} is missing from the run"));
            assert!(
                matches!(c.outcome, Outcome::Skip(_)),
                "{name} did not skip against a daemon that refuses everything"
            );
        }
        // Every path check got a refusal carrying a code, so none of them fails.
        for (name, _) in PATH_ATTEMPTS {
            let c = checks.iter().find(|c| &c.name == name).unwrap();
            assert!(
                matches!(c.outcome, Outcome::Pass),
                "{name} did not pass: {}",
                c.detail
            );
        }
    }

    #[tokio::test]
    async fn a_permissive_daemon_fails() {
        let addr = serve(r#"{"resolved":"/etc/passwd","exists":true}"#, 200).await;
        let checks = run(&addr, None).await.unwrap();
        let (_, failed, _) = counts(&checks);
        assert!(failed > 0, "a permissive daemon passed every check");
    }

    /// A bodiless 403 is what a reverse proxy in front of a broken daemon returns.
    #[tokio::test]
    async fn a_refusal_with_no_code_is_not_a_pass() {
        let addr = serve("", 403).await;
        let checks = run(&addr, None).await.unwrap();
        let (_, failed, _) = counts(&checks);
        assert!(failed > 0, "a bodiless 403 was accepted as proof");
    }

    /// The path checks cannot see a leak through a job, so the data plane has to (#14).
    #[tokio::test]
    async fn a_daemon_that_leaks_through_a_job_is_caught() {
        let addr = serve(
            r#"{"exit_code":0,"stdout":"CORDON-VERIFY-SECRET-B\nVERIFY-DONE\n","stderr":"","artifacts":[]}"#,
            200,
        )
        .await;
        let checks = run(&addr, None).await.unwrap();
        let leak = checks
            .iter()
            .find(|c| c.name == "a job cannot read another owner")
            .expect("the check exists");
        assert!(
            matches!(leak.outcome, Outcome::Fail),
            "a job reading another owner's secret was not caught: {}",
            leak.detail
        );
    }

    /// A daemon that ignores the scope answers a scoped token as it answers the operator (#17).
    #[tokio::test]
    async fn a_daemon_that_ignores_the_scope_is_caught() {
        let addr = serve(
            r#"{"token":"tok_x","resolved":"/x","exists":true,"exit_code":0,"stdout":"CORDON-VERIFY-SECRET-B","forked":"x"}"#,
            200,
        )
        .await;
        let checks = run(&addr, Some("t")).await.unwrap();
        for name in &SCOPE_NAMES[1..] {
            let c = checks.iter().find(|c| &c.name == name).unwrap();
            assert!(
                matches!(c.outcome, Outcome::Fail),
                "{name} did not fail against a daemon that ignores the scope"
            );
        }
    }

    /// And one that cannot issue a scoped token proves nothing about them.
    #[tokio::test]
    async fn a_daemon_with_no_scoped_tokens_skips_the_scope_checks() {
        let addr = serve(r#"{"error":{"code":"not_found","message":"no"}}"#, 404).await;
        let checks = run(&addr, Some("t")).await.unwrap();
        for name in &SCOPE_NAMES {
            let c = checks.iter().find(|c| &c.name == name).unwrap();
            assert!(matches!(c.outcome, Outcome::Skip(_)), "{name} did not skip");
        }
    }

    #[tokio::test]
    async fn an_unreachable_daemon_is_an_error_not_a_pass() {
        assert!(run("http://127.0.0.1:1", None).await.is_err());
    }

    #[test]
    fn a_run_that_tested_nothing_is_not_a_success() {
        let checks = vec![Check::skip("a", "no token"), Check::skip("b", "no token")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out, Style::plain());
        let text = String::from_utf8(out).unwrap();
        assert!(!ok, "an all-skip run exited successfully");
        assert!(text.contains("Nothing was actually tested"), "{text}");
    }

    #[test]
    fn the_report_never_counts_a_skip_as_a_pass() {
        let checks = vec![Check::pass("a", "fine"), Check::skip("b", "no docker")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out, Style::plain());
        let text = String::from_utf8(out).unwrap();
        assert!(ok, "a skip should not fail the run");
        assert!(text.contains("skip"), "{text}");
        assert!(text.contains("A skip is not a pass"), "{text}");
        assert!(!text.contains("all 2 checks passed"), "{text}");
    }

    /// With a root, a passing run removes its own probes and nothing beside them (#20).
    #[test]
    fn tidy_removes_the_probes_and_only_the_probes() {
        let root = std::env::temp_dir().join(format!("cordon-tidy-{}", std::process::id()));
        let probe = root.join("owners/cordon-verify/a/.workspace");
        let other = root.join("owners/acme/budi/.workspace");
        std::fs::create_dir_all(&probe).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(probe.join("mine.txt"), b"own").unwrap();
        std::fs::write(other.join("notes.md"), b"mine").unwrap();
        let tokens = root.join("tokens");
        std::fs::create_dir_all(&tokens).unwrap();
        std::fs::write(tokens.join("tok_ours.rec"), "cordon-verify/a\n").unwrap();
        std::fs::write(tokens.join("tok_ours_ttl.rec"), "cordon-verify/a\n99\n").unwrap();
        std::fs::write(tokens.join("tok_theirs.rec"), "cordon-verify-prod/a\n").unwrap();
        let say = |root: Option<&Path>, passed| {
            let mut out = Vec::new();
            tidy(root, passed, &mut out, Style::plain());
            String::from_utf8(out).unwrap()
        };

        assert!(say(None, true).contains("left behind"));
        assert!(probe.exists(), "removed with no root given");

        assert!(say(Some(&root), false).contains("kept for inspection"));
        assert!(probe.exists(), "removed after a failed run");

        assert!(say(Some(&root), true).contains("Removed"));
        assert!(
            !root.join("owners/cordon-verify").exists(),
            "the probes are still there"
        );
        assert!(other.join("notes.md").exists(), "another owner was removed");
        assert!(
            !tokens.join("tok_ours.rec").exists(),
            "verify's own token is still valid"
        );
        assert!(
            !tokens.join("tok_ours_ttl.rec").exists(),
            "an expiring one was left behind"
        );
        assert!(
            tokens.join("tok_theirs.rec").exists(),
            "someone else's token was revoked"
        );

        // A second run finds nothing, and does not call that a removal.
        assert!(say(Some(&root), true).contains("Nothing to remove"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_report_says_fail_loudly_and_returns_false() {
        let checks = vec![Check::pass("a", "fine"), Check::fail("b", "status 200")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out, Style::plain());
        let text = String::from_utf8(out).unwrap();
        assert!(!ok);
        assert!(text.contains("FAIL"), "{text}");
        assert!(text.contains("1 failed, 1 passed"), "{text}");
    }
}
