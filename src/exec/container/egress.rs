//! Per job egress. An empty list is the caller's business and means no network
//! at all; this module exists only for the case where a job has to reach
//! something named.
//!
//! What it gives: the named hosts resolve, nothing else does, because the
//! container gets no resolver and only the pinned entries.
//!
//! What it does not give: a port level firewall. A job allowed to reach
//! `db.internal:5432` can reach that host on any port. v1 says so in the
//! README's isolation table rather than implying otherwise. Closing it needs a
//! per job network namespace with nftables rules, which is the v2 item.

use crate::exec::ExecError;

const MAX_ENTRIES: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub host: String,
    pub port: u16,
}

pub fn args(egress: &[String]) -> Result<Vec<String>, ExecError> {
    let entries = parse(egress).map_err(ExecError::Unsupported)?;
    let mut a: Vec<String> = vec!["--network".into(), "bridge".into()];
    for e in &entries {
        // host-gateway resolves to the host the daemon runs on, which is where
        // an operator terminates whatever the job is allowed to reach.
        a.push("--add-host".into());
        a.push(format!("{}:host-gateway", e.host));
    }
    // No resolver, so only the pinned entries above resolve. Without this the
    // job reaches anything it can name.
    a.push("--dns".into());
    a.push("0.0.0.0".into());
    Ok(a)
}

pub fn parse(egress: &[String]) -> Result<Vec<Entry>, String> {
    if egress.is_empty() {
        return Err("egress allowlist is empty; the caller should have used no network".into());
    }
    if egress.len() > MAX_ENTRIES {
        return Err(format!(
            "egress allowlist has {} entries, the limit is {MAX_ENTRIES}",
            egress.len()
        ));
    }
    egress.iter().map(|e| parse_one(e)).collect()
}

fn parse_one(entry: &str) -> Result<Entry, String> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| format!("egress entry {entry:?} is not host:port"))?;
    if !is_hostname(host) {
        return Err(format!(
            "egress entry {entry:?} has a host that is not a plain hostname or IP"
        ));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("egress entry {entry:?} has a port that is not a number"))?;
    if port == 0 {
        return Err(format!("egress entry {entry:?} has port 0"));
    }
    Ok(Entry {
        host: host.to_string(),
        port,
    })
}

/// An allowlist again, not a blocklist. A host made only of letters, digits,
/// dots and hyphens cannot become a docker flag, a shell word or a CIDR.
fn is_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('-')
        && !h.starts_with('.')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(v: &[&str]) -> Result<Vec<Entry>, String> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_host_and_port() {
        let got = entries(&["litellm.internal:4000", "api.example.com:443"]).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].host, "litellm.internal");
        assert_eq!(got[0].port, 4000);
    }

    #[test]
    fn refuses_anything_that_is_not_host_colon_port() {
        for bad in [
            "no-port",
            "host:",
            ":443",
            "host:not-a-number",
            "host:0",
            "host:65536",
            "",
            "host with space:443",
            "host;rm -rf /:443",
            "--privileged:443",
            "0.0.0.0/0:443",
            "-flag:443",
        ] {
            assert!(entries(&[bad]).is_err(), "{bad:?} was accepted");
        }
    }

    /// The caller decides that an empty list means no network. Arriving here
    /// with an empty list is a bug, so it errors rather than defaulting.
    #[test]
    fn an_empty_list_is_not_this_functions_business() {
        assert!(entries(&[]).is_err());
    }

    #[test]
    fn refuses_more_entries_than_the_cap() {
        let many: Vec<String> = (0..33).map(|i| format!("h{i}.example.com:443")).collect();
        assert!(parse(&many).is_err(), "33 entries was accepted");
    }

    #[test]
    fn an_allowlist_does_not_leave_the_container_on_the_none_network() {
        let a = args(&["litellm.internal:4000".to_string()])
            .unwrap()
            .join(" ");
        assert!(
            !a.contains("--network none"),
            "an allowlisted job got no network at all: {a}"
        );
    }

    #[test]
    fn every_allowlisted_host_is_pinned_and_nothing_else_resolves() {
        let a = args(&[
            "litellm.internal:4000".to_string(),
            "api.example.com:443".to_string(),
        ])
        .unwrap()
        .join(" ");
        assert!(a.contains("--add-host litellm.internal:"), "{a}");
        assert!(a.contains("--add-host api.example.com:"), "{a}");
        assert!(
            a.contains("--dns 0.0.0.0"),
            "the resolver was left open: {a}"
        );
    }

    #[test]
    fn a_hostile_entry_cannot_become_a_docker_flag() {
        assert!(args(&["--privileged:443".to_string()]).is_err());
    }
}
