//! `cordon verify` proves the guarantee against a running daemon, so an
//! operator does not have to trust the README.
//!
//! Issue #14: the first version posted nine path strings to `/v1/resolve` with
//! two owners at the same depth, and passed against a daemon that leaked every
//! owner's file through `/v1/run`, had no working authentication and let a
//! caller downgrade the backend. It inherited the test suite's blind spot
//! because both were written from the same mental model.
//!
//! So it now exercises the data plane: it writes a secret as one owner and has
//! another owner's job try to read it, by every shape the review used. A check
//! it cannot run reports as skipped rather than passed, because a probe that
//! silently counts an untested property as a win is worse than no probe.
//!
//! It speaks HTTP with hand written requests rather than taking a client
//! dependency. It runs once, by hand or in a pipeline, and reads a handful of
//! fields.
//!
//! It leaves its workspaces behind under the owner prefix `cordon-verify`,
//! because there is no endpoint that deletes an owner. Say so rather than
//! surprise someone.

use std::io::Write;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub enum Outcome {
    Pass,
    Fail,
    /// The property could not be tested here, with the reason. Never counted
    /// as a pass.
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
    /// A refusal counts only as a 4xx carrying a code. A bodiless 403 from a
    /// proxy in front of a broken daemon proves nothing.
    ///
    /// `unauthorized` is explicitly not a pass. A daemon that refuses every
    /// request for want of a token tells us nothing about how it handles
    /// paths, and counting that as a win is the same false assurance this
    /// whole rewrite exists to remove.
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

/// Path strings posted to `/v1/resolve`, each a thing a confused or hostile
/// caller actually sends.
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

    // Liveness first: everything below is meaningless against a daemon that
    // is not answering, and a connection error should say so once.
    let (status, _) = c.get("/v1/health").await?;
    if status != 200 {
        return Err(format!("/v1/health answered {status}"));
    }

    let mut out = Vec::new();
    let (auth, usable) = auth_checks(&c).await?;
    out.extend(auth);

    // Everything below needs a request the daemon will actually answer. With
    // no usable credentials every check would come back 401, which is a 4xx
    // with a code and would have read as a pass.
    if !usable {
        let why = "no usable credentials for this daemon; pass a token as the second argument or in CORDON_TOKEN".to_string();
        out.extend(
            PATH_ATTEMPTS
                .iter()
                .map(|(n, _)| Check::skip(n, why.clone())),
        );
        out.extend(DATA_PLANE_NAMES.iter().map(|n| Check::skip(n, why.clone())));
        return Ok(out);
    }

    out.extend(path_checks(&c).await?);
    out.extend(data_plane_checks(&c).await?);
    Ok(out)
}

/// Returns the auth checks, and whether the rest of the suite can run at all.
async fn auth_checks(c: &Client) -> Result<(Vec<Check>, bool), String> {
    let body = r#"{"owner":["cordon-verify","a"],"path":"x.md"}"#;

    // Whether a token is configured is discovered rather than assumed: a
    // request with no credentials either works or does not.
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
            // An open daemon is fine to probe; one that wants a token we do
            // not have is not.
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

/// The checks the first version of this tool did not have, and the ones the
/// review's critical findings lived behind.
async fn data_plane_checks(c: &Client) -> Result<Vec<Check>, String> {
    let names = DATA_PLANE_NAMES;

    // Owner b writes the secret. If /v1/run cannot run here at all, every
    // check below is unprovable and says so.
    let seed = format!(
        r#"{{"owner":{OWNER_B},"entrypoint":"sh","args":["-c","printf {SECRET} > secret.md"],
             "limits":{{"wall_ms":10000,"memory_mb":128,"stdout_kb":16}}}}"#
    );
    // These two are refused before any job runs, so they do not need the seed
    // and must not be skipped when it fails. An earlier version gated every
    // check on the seed, which hid both of them behind a missing image.
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

    // Owner a's job goes at it directly, bypassing the path layer entirely,
    // which is exactly what issue #1 was.
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

/// The backend floor only means something on a container-configured daemon.
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

pub fn report(checks: &[Check], w: &mut impl Write) -> bool {
    let mut failed = 0usize;
    let mut skipped = 0usize;
    for c in checks {
        match &c.outcome {
            Outcome::Pass => {
                let _ = writeln!(w, "ok   {:<32} {}", c.name, c.detail);
            }
            Outcome::Fail => {
                failed += 1;
                let _ = writeln!(w, "FAIL {:<32} {}", c.name, c.detail);
            }
            Outcome::Skip(why) => {
                skipped += 1;
                let _ = writeln!(w, "skip {:<32} {why}", c.name);
            }
        }
    }
    let passed = checks.len() - failed - skipped;
    let _ = writeln!(w);
    if failed > 0 {
        let _ = writeln!(w, "{failed} failed, {passed} passed, {skipped} skipped");
        return false;
    }
    // Nothing failed and nothing passed either. A pipeline reading exit 0 as
    // success here is back to the false assurance this tool was rewritten to
    // remove, so an all-skip run is not a success.
    if passed == 0 {
        let _ = writeln!(
            w,
            "{passed} passed, {skipped} skipped. Nothing was actually tested, so this is not a pass."
        );
        return false;
    }
    if skipped > 0 {
        // Said plainly, because a skip is an untested property and reading
        // this output as a clean bill of health is how #14 happened.
        let _ = writeln!(
            w,
            "{passed} passed, {skipped} skipped. A skip is not a pass: those properties were not tested here."
        );
    } else {
        let _ = writeln!(w, "all {passed} checks passed");
    }
    let _ = writeln!(
        w,
        "\nWorkspaces under the owner prefix cordon-verify are left behind; there is no endpoint that deletes an owner."
    );
    true
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

/// Pulls one string value out of a JSON body without a parser. verify reads a
/// handful of fields and runs once, so the dependency is not worth it.
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

    /// A stub that answers everything the same way, which is enough to pin how
    /// the checks read a response.
    async fn serve(body: &'static str, status: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();

                // Health always answers, because verify checks liveness first
                // and a stub that refuses it never reaches the real checks.
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

    /// A daemon that refuses everything cannot have its data plane exercised,
    /// so those checks must skip rather than pass.
    ///
    /// Asserted on the skips rather than on "nothing failed". The blanket 403
    /// this stub returns is a genuine failure for the backend floor probe,
    /// which expects a 400 with its own code, and verify is right to say so.
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
        // And nothing in the path layer failed, since every one of those is a
        // refusal carrying a code.
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

    /// A 403 with an empty body proves nothing: that is what a reverse proxy in
    /// front of a broken daemon returns.
    #[tokio::test]
    async fn a_refusal_with_no_code_is_not_a_pass() {
        let addr = serve("", 403).await;
        let checks = run(&addr, None).await.unwrap();
        let (_, failed, _) = counts(&checks);
        assert!(failed > 0, "a bodiless 403 was accepted as proof");
    }

    /// The daemon leaks the secret through a job. The path checks are all
    /// refusals, so only the data plane can catch it, which is the whole point
    /// of issue #14.
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

    #[tokio::test]
    async fn an_unreachable_daemon_is_an_error_not_a_pass() {
        assert!(run("http://127.0.0.1:1", None).await.is_err());
    }

    #[test]
    fn a_run_that_tested_nothing_is_not_a_success() {
        let checks = vec![Check::skip("a", "no token"), Check::skip("b", "no token")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(!ok, "an all-skip run exited successfully");
        assert!(text.contains("Nothing was actually tested"), "{text}");
    }

    #[test]
    fn the_report_never_counts_a_skip_as_a_pass() {
        let checks = vec![Check::pass("a", "fine"), Check::skip("b", "no docker")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(ok, "a skip should not fail the run");
        assert!(text.contains("skip"), "{text}");
        assert!(text.contains("A skip is not a pass"), "{text}");
        assert!(!text.contains("all 2 checks passed"), "{text}");
    }

    #[test]
    fn the_report_says_fail_loudly_and_returns_false() {
        let checks = vec![Check::pass("a", "fine"), Check::fail("b", "status 200")];
        let mut out = Vec::new();
        let ok = report(&checks, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(!ok);
        assert!(text.contains("FAIL"), "{text}");
        assert!(text.contains("1 failed, 1 passed"), "{text}");
    }
}
