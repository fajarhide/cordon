//! Name pins for a container that has network access.
//!
//! Issue #11, and the rename matters more than the code. This was
//! `egress::args`, an "allowlist" that attached the container to a bridge and
//! set `--dns 0.0.0.0`. That blocks name resolution and nothing else: measured
//! on a real host, a job with one allowlisted entry still reached
//! `8.8.8.8:53` directly. `--dns` is not a packet filter and never was, so the
//! feature promised a boundary it did not have, which is worse than offering
//! nothing.
//!
//! What is left is honest: a job either has no network or has the host's
//! outbound access, and these pins are a convenience for naming an internal
//! service, not a restriction. The field is called `hosts` and the mode is
//! called `open` so neither can be misread.
//!
//! The pins take an address from the caller rather than the magic
//! `host-gateway` name the old code used. `host-gateway` is unresolvable under
//! rootless podman with netavark, where it fails the container outright, and
//! resolves under slirp4netns, so what it meant depended on the network
//! backend. An address the caller supplies means the same thing everywhere.

use std::net::IpAddr;

const MAX_PINS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub name: String,
    pub addr: IpAddr,
}

/// Parses `{"name": "addr"}` pairs into pins.
pub fn parse<'a, I>(pairs: I) -> Result<Vec<Pin>, String>
where
    I: IntoIterator<Item = (&'a String, &'a String)>,
{
    let mut out = Vec::new();
    for (name, addr) in pairs {
        if out.len() == MAX_PINS {
            return Err(format!("more than {MAX_PINS} host pins"));
        }
        if !is_hostname(name) {
            return Err(format!("host pin {name:?} is not a plain hostname"));
        }
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("host pin {name:?} has an address that is not an IP: {addr:?}"))?;
        out.push(Pin {
            name: name.clone(),
            addr,
        });
    }
    // Stable order, so two identical requests produce identical arguments.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// An allowlist, not a blocklist. A name made only of letters, digits, dots and
/// hyphens cannot become a container flag, a shell word or a CIDR.
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
    use std::collections::BTreeMap;

    fn pins(pairs: &[(&str, &str)]) -> Result<Vec<Pin>, String> {
        let m: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parse(m.iter())
    }

    #[test]
    fn parses_a_name_and_an_address() {
        let got = pins(&[("litellm.internal", "10.0.0.5")]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "litellm.internal");
        assert_eq!(got[0].addr.to_string(), "10.0.0.5");
    }

    #[test]
    fn accepts_ipv6() {
        let got = pins(&[("db.internal", "fd00::1")]).unwrap();
        assert_eq!(got[0].addr.to_string(), "fd00::1");
    }

    #[test]
    fn refuses_a_name_that_could_become_a_flag_or_a_shell_word() {
        for bad in [
            "--privileged",
            "-flag",
            "host;rm -rf /",
            "host with space",
            "",
            ".hidden",
            "0.0.0.0/0",
        ] {
            assert!(pins(&[(bad, "10.0.0.5")]).is_err(), "{bad:?} was accepted");
        }
    }

    /// The magic name the old code used is gone: it meant different things on
    /// different network backends and failed the container outright on one.
    #[test]
    fn refuses_an_address_that_is_not_an_ip() {
        for bad in [
            "host-gateway",
            "localhost",
            "example.com",
            "10.0.0.5:4000",
            "",
        ] {
            assert!(
                pins(&[("svc.internal", bad)]).is_err(),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn refuses_more_pins_than_the_cap() {
        let many: Vec<(String, String)> = (0..33)
            .map(|i| (format!("h{i}.internal"), "10.0.0.1".to_string()))
            .collect();
        assert!(parse(many.iter().map(|(k, v)| (k, v))).is_err());
    }

    #[test]
    fn an_empty_set_is_fine_and_means_no_pins() {
        assert_eq!(pins(&[]).unwrap(), vec![]);
    }
}
