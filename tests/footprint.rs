//! The 20 MB claim in the spec, asserted rather than asserted in prose.

use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn the_daemon_stays_under_twenty_megabytes_while_serving() {
    let bin = env!("CARGO_BIN_EXE_cordon");
    let root = std::env::temp_dir().join(format!("cordon-footprint-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&root);

    let mut child = Command::new(bin)
        .arg("serve")
        .env("CORDON_ROOT", &root)
        .env("CORDON_LISTEN", "tcp:127.0.0.1:7791")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");

    std::thread::sleep(Duration::from_millis(800));

    // Measured while serving, not at rest: a request builds the router state
    // and allocates, and that is the number an operator cares about.
    for _ in 0..50 {
        let _ = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "http://127.0.0.1:7791/v1/resolve",
                "-H",
                "content-type: application/json",
                "-d",
                r#"{"owner":["foot","print"],"path":"a.md"}"#,
            ])
            .stdout(Stdio::null())
            .status();
    }

    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &child.id().to_string()])
        .output()
        .expect("ps");
    let _ = child.kill();
    // Reaped on purpose: a zombie daemon would outlive the test run.
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    let rss_kb: u64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("ps printed a number");

    assert!(
        rss_kb > 0,
        "ps reported nothing, the daemon was not running"
    );
    assert!(
        rss_kb < 20 * 1024,
        "the daemon used {rss_kb} KB while serving, the spec promises under 20 MB"
    );
    println!("daemon RSS while serving: {rss_kb} KB");
}
