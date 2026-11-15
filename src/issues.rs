// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Protocol checks (UDA 2.0 §1) with a severity per finding: errors
//! break interoperability, warnings bend a SHOULD, infos are notable but
//! legitimate. Pure functions, unit-tested without sockets.

use std::net::{IpAddr, SocketAddr};

use crate::app::{parse_max_age, usn_uuid};
use crate::describe;
use crate::ssdp::{Kind, Message};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Nerd Font level icon, as in mex's metrics overlay.
    pub fn icon(self) -> char {
        match self {
            Severity::Error => '\u{f057}',
            Severity::Warning => '\u{f071}',
            Severity::Info => '\u{f05a}',
        }
    }

    /// Errors and warnings mark rows; infos only show in lists.
    pub fn marks(self) -> bool {
        self != Severity::Info
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Issue {
    pub severity: Severity,
    pub text: String,
}

impl Issue {
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            text: text.into(),
        }
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            text: text.into(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            text: text.into(),
        }
    }
}

/// Worst severity that marks a row, if any.
pub fn worst_mark(issues: &[Issue]) -> Option<Severity> {
    issues
        .iter()
        .map(|i| i.severity)
        .filter(|s| s.marks())
        .min()
}

/// Header checks for one advertisement (NOTIFY or search response).
pub fn advert_issues(msg: &Message, src: &SocketAddr) -> Vec<Issue> {
    let mut out = Vec::new();
    let nts = msg.header("NTS").unwrap_or("");
    let byebye = nts.eq_ignore_ascii_case("ssdp:byebye");
    let required: &[&str] = match msg.kind {
        Kind::Notify if byebye => &["HOST", "NT", "NTS", "USN"],
        Kind::Notify => &[
            "HOST",
            "CACHE-CONTROL",
            "LOCATION",
            "NT",
            "NTS",
            "SERVER",
            "USN",
        ],
        Kind::Response => &["CACHE-CONTROL", "EXT", "LOCATION", "SERVER", "ST", "USN"],
        Kind::Search => &[],
    };
    for h in required {
        if !msg.has_header(h) {
            out.push(Issue::error(format!("missing {h} header")));
        }
    }
    if msg.malformed_lines > 0 {
        out.push(Issue::warning(format!(
            "{} malformed header line(s)",
            msg.malformed_lines
        )));
    }
    if msg.kind == Kind::Response && msg.status() != Some(200) {
        out.push(Issue::error(format!(
            "status line '{}' (want 200)",
            msg.start_line
        )));
    }
    if msg.kind == Kind::Notify
        && msg.has_header("NTS")
        && !["ssdp:alive", "ssdp:byebye", "ssdp:update"]
            .iter()
            .any(|v| nts.eq_ignore_ascii_case(v))
    {
        out.push(Issue::error(format!("unknown NTS '{nts}'")));
    }
    if let Some(cc) = msg.header("CACHE-CONTROL") {
        match parse_max_age(cc) {
            None => out.push(Issue::error(format!(
                "CACHE-CONTROL without max-age: '{cc}'"
            ))),
            Some(n) if n < 1800 => out.push(Issue::warning(format!(
                "max-age={n} below recommended 1800"
            ))),
            _ => {}
        }
    }
    let target = match msg.kind {
        Kind::Notify => msg.header("NT"),
        _ => msg.header("ST"),
    };
    if let Some(usn) = msg.header("USN") {
        if usn_uuid(usn).is_none() {
            out.push(Issue::error(format!(
                "USN '{usn}' does not start with uuid:"
            )));
        } else if let Some(t) = target {
            // Root/uuid adverts have their own USN shapes; typed ones
            // are `uuid:<id>::<NT>`.
            let typed = !t.to_ascii_lowercase().starts_with("uuid:");
            match usn.split_once("::").map(|(_, s)| s) {
                Some(s) if typed && !s.eq_ignore_ascii_case(t) => {
                    out.push(Issue::error(format!("USN suffix does not match {t}")))
                }
                None if typed => out.push(Issue::error(format!("USN lacks '::{t}' suffix"))),
                _ => {}
            }
        }
    }
    if let Some(loc) = msg.header("LOCATION") {
        match describe::check_location(loc) {
            Err(e) => out.push(Issue::error(e)),
            Ok(url) => {
                let host_ip = match url.host() {
                    Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                    Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                    _ => None,
                };
                // Legitimate behind proxies or on multi-homed hosts.
                if host_ip.is_some_and(|ip| ip != src.ip()) {
                    out.push(Issue::info(format!(
                        "LOCATION host differs from sender {}",
                        src.ip()
                    )));
                }
            }
        }
    }
    if let Some(server) = msg.header("SERVER") {
        if !server.to_ascii_uppercase().contains("UPNP/") {
            out.push(Issue::warning(format!(
                "SERVER '{server}' lacks UPnP/x.y token"
            )));
        }
    }
    out
}

/// M-SEARCH checks (UDA 2.0 §1.3.2). MX is only required for multicast.
pub fn search_issues(msg: &Message, multicast: bool) -> Vec<Issue> {
    let mut out = Vec::new();
    for h in ["HOST", "MAN", "ST"] {
        if !msg.has_header(h) {
            out.push(Issue::error(format!("missing {h} header")));
        }
    }
    if msg.header("MAN").is_some_and(|v| v != "\"ssdp:discover\"") {
        out.push(Issue::warning("MAN must be \"ssdp:discover\" (quoted)"));
    }
    match msg.header("MX").map(str::parse::<u32>) {
        None if multicast => out.push(Issue::error("multicast search without MX")),
        Some(Err(_)) => out.push(Issue::error("MX not a number")),
        Some(Ok(n)) if multicast && !(1..=5).contains(&n) => {
            out.push(Issue::warning(format!("MX={n} outside 1..5")))
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssdp;

    fn src() -> SocketAddr {
        "10.0.0.2:1900".parse().unwrap()
    }

    #[test]
    fn advert_findings_have_severities() {
        let raw = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=60\r\nST: urn:x:device:A:1\r\n\
                   USN: uuid:z::urn:x:device:B:1\r\nLOCATION: http://10.0.0.9/d.xml\r\n\
                   SERVER: foo\r\n\r\n";
        let issues = advert_issues(&ssdp::parse(raw.as_bytes()).unwrap(), &src());
        let sev = |s: &str| {
            issues
                .iter()
                .find(|i| i.text.contains(s))
                .map(|i| i.severity)
        };
        assert_eq!(sev("missing EXT"), Some(Severity::Error), "{issues:?}");
        assert_eq!(sev("max-age=60"), Some(Severity::Warning));
        assert_eq!(sev("USN suffix"), Some(Severity::Error));
        assert_eq!(sev("differs from sender"), Some(Severity::Info));
        assert_eq!(sev("lacks UPnP/"), Some(Severity::Warning));
        assert_eq!(worst_mark(&issues), Some(Severity::Error));
    }

    #[test]
    fn clean_notify_has_no_findings() {
        let raw = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
                   CACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.0.0.2/d.xml\r\n\
                   NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nSERVER: Linux/5 UPnP/1.0 x/1\r\n\
                   USN: uuid:q::upnp:rootdevice\r\n\r\n";
        let issues = advert_issues(&ssdp::parse(raw.as_bytes()).unwrap(), &src());
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn info_only_does_not_mark() {
        assert_eq!(worst_mark(&[Issue::info("x")]), None);
        assert_eq!(
            worst_mark(&[Issue::info("x"), Issue::warning("y")]),
            Some(Severity::Warning)
        );
    }

    #[test]
    fn search_checks() {
        let m = ssdp::parse(b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\nMAN: ssdp:discover\r\nMX: 9\r\nST: ssdp:all\r\n\r\n")
            .unwrap();
        let issues = search_issues(&m, true);
        assert_eq!(issues.len(), 2, "{issues:?}");
        assert!(search_issues(&m, false).len() == 1);
    }
}
