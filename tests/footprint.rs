//! The 20 MB claim in the spec, asserted rather than asserted in prose.
//!
//! The first version of this test accepted any reading above zero, which let a
//! bogus measurement pass: it once reported 32 KB for a daemon whose real RSS
//! was 2768 KB, and went green. A test that carries a claim has to fail when it
//! cannot measure, not when the number happens to be small.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: &str = "7791";
/// A daemon that has bound a socket and served 50 requests cannot plausibly be
/// under a megabyte, so a reading below this means the measurement is wrong
/// rather than the daemon being small.
const FLOOR_KB: u64 = 1_000;
const CEILING_KB: u64 = 20 * 1024;

#[test]
fn the_daemon_stays_under_twenty_megabytes_while_serving() {
    let root = std::env::temp_dir().join(format!("cordon-footprint-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&root);

    let mut child = Command::new(env!("CARGO_BIN_EXE_cordon"))
        .arg("serve")
        .env("CORDON_ROOT", &root)
        .env("CORDON_LISTEN", format!("tcp:127.0.0.1:{PORT}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");

    let cleanup = |child: &mut Child, root: &std::path::Path| {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(root);
    };

    if !wait_for_health() {
        cleanup(&mut child, &root);
        panic!("the daemon never answered /v1/health on port {PORT}, so nothing was measured");
    }

    // Measured while serving, not at rest: a request builds the router state
    // and allocates, and that is the number an operator cares about.
    for _ in 0..50 {
        let _ = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                &format!("http://127.0.0.1:{PORT}/v1/resolve"),
                "-H",
                "content-type: application/json",
                "-d",
                r#"{"owner":["foot","print"],"path":"a.md"}"#,
            ])
            .stdout(Stdio::null())
            .status();
    }

    // Still alive, so the reading below belongs to a process that is serving
    // rather than one that fell over partway through.
    if !health_ok() {
        cleanup(&mut child, &root);
        panic!("the daemon stopped answering during the load, so the reading would be meaningless");
    }

    let reading = rss_kb(child.id());
    cleanup(&mut child, &root);

    let rss_kb = reading.unwrap_or_else(|| panic!("ps gave no usable RSS for the daemon"));
    println!("daemon RSS while serving: {rss_kb} KB");

    assert!(
        rss_kb >= FLOOR_KB,
        "ps reported {rss_kb} KB, below the {FLOOR_KB} KB a serving daemon can plausibly use. \
         The measurement is wrong, not the daemon."
    );
    assert!(
        rss_kb < CEILING_KB,
        "the daemon used {rss_kb} KB while serving, and the spec promises under 20 MB"
    );
}

fn wait_for_health() -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if health_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn health_ok() -> bool {
    Command::new("curl")
        .args(["-sf", &format!("http://127.0.0.1:{PORT}/v1/health")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn rss_kb(pid: u32) -> Option<u64> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}
