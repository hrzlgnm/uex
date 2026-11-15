// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Cumulative counters and the metrics overlay rows (`m`), modeled on
//! mex's overlay: `(key, value)` rows, an empty value marks a section.
//! Maps stay bounded by network size (devices, hosts, interfaces).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::app::{App, DescState, RowKey};
use crate::issues::{Issue, Severity};
use crate::ssdp::{Kind, Packet, Via};

const RECENT: Duration = Duration::from_secs(60);
/// Top-N cap for per-host/per-type listings; the rest is summarized.
const TOP: usize = 8;

#[derive(Debug, Clone)]
pub struct ControlPoint {
    pub searches: u64,
    pub user_agent: String,
    pub last: Instant,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub bytes_total: u64,
    pub packet_times: VecDeque<Instant>,
    pub last_packet_at: Option<Instant>,
    pub notify_alive: u64,
    pub notify_update: u64,
    pub notify_byebye: u64,
    pub notify_other: u64,
    pub responses_ok: u64,
    pub responses_bad: u64,
    pub searches_foreign: u64,
    pub searches_own: u64,
    pub v4_rx: u64,
    pub v6_rx: u64,
    pub via_listener: u64,
    pub via_search: u64,
    pub iface_rx: HashMap<String, u64>,
    pub source_rx: HashMap<IpAddr, u64>,
    pub devices_seen_total: u64,
    pub devices_expired_total: u64,
    pub devices_byebye_total: u64,
    pub fetch_started: u64,
    pub fetch_link_local: u64,
    pub fetch_ok: u64,
    pub fetch_failed: u64,
    pub fetch_bytes: u64,
    pub fetch_ms_total: u64,
    pub fetch_ms_max: u64,
    pub control_points: HashMap<IpAddr, ControlPoint>,
    pub search_targets: HashMap<String, u64>,
}

impl Metrics {
    pub fn on_packet(&mut self, p: &Packet, own: bool) {
        let now = p.received;
        self.bytes_total += p.raw.len() as u64;
        self.last_packet_at = Some(now);
        self.packet_times.push_back(now);
        while self
            .packet_times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > RECENT)
        {
            self.packet_times.pop_front();
        }
        match p.src.ip() {
            IpAddr::V4(_) => self.v4_rx += 1,
            IpAddr::V6(_) => self.v6_rx += 1,
        }
        match p.via {
            Via::Listener => self.via_listener += 1,
            Via::Search => self.via_search += 1,
        }
        *self.iface_rx.entry(display_iface(&p.iface)).or_default() += 1;
        *self.source_rx.entry(p.src.ip()).or_default() += 1;
        let Some(m) = &p.msg else { return };
        match m.kind {
            Kind::Notify => {
                let nts = m.header("NTS").unwrap_or("").to_ascii_lowercase();
                match nts.as_str() {
                    "ssdp:alive" => self.notify_alive += 1,
                    "ssdp:update" => self.notify_update += 1,
                    "ssdp:byebye" => self.notify_byebye += 1,
                    _ => self.notify_other += 1,
                }
            }
            Kind::Response if m.status() == Some(200) => self.responses_ok += 1,
            Kind::Response => self.responses_bad += 1,
            Kind::Search if own => self.searches_own += 1,
            Kind::Search => {
                self.searches_foreign += 1;
                let cp = self
                    .control_points
                    .entry(p.src.ip())
                    .or_insert(ControlPoint {
                        searches: 0,
                        user_agent: String::new(),
                        last: now,
                    });
                cp.searches += 1;
                cp.last = now;
                if let Some(ua) = m.header("USER-AGENT") {
                    cp.user_agent = ua.to_string();
                }
                let st = m.header("ST").unwrap_or("-").to_string();
                *self.search_targets.entry(st).or_default() += 1;
            }
        }
    }

    pub fn recent_packets(&self) -> usize {
        self.packet_times
            .iter()
            .filter(|t| t.elapsed() <= RECENT)
            .count()
    }
}

fn display_iface(iface: &str) -> String {
    if iface.is_empty() {
        "?".into()
    } else {
        iface.to_string()
    }
}

pub fn fmt_age(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

pub fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn or_dash(v: Vec<String>) -> String {
    if v.is_empty() {
        "—".into()
    } else {
        v.join(", ")
    }
}

/// Sorted by count descending, then key, capped at `TOP`.
fn top<K: Ord + Clone>(map: &HashMap<K, u64>) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// One overlay finding: where it was seen plus the issue.
pub struct Finding {
    pub scope: String,
    pub issue: Issue,
}

impl App {
    /// Every current finding, worst first: per device (adverts and
    /// descriptions) and per control point (latest search issues).
    pub fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        for uuid in self.devices.keys() {
            let name = self.display_name(uuid);
            for issue in self.device_issues(uuid) {
                out.push(Finding {
                    scope: name.clone(),
                    issue,
                });
            }
        }
        let mut seen = HashSet::new();
        for s in self.searches.iter().rev().filter(|s| !s.own) {
            for issue in &s.issues {
                if seen.insert((s.src.ip(), issue.text.clone())) {
                    out.push(Finding {
                        scope: format!("control point {}", s.src.ip()),
                        issue: issue.clone(),
                    });
                }
            }
        }
        out.sort_by(|a, b| {
            a.issue
                .severity
                .cmp(&b.issue.severity)
                .then_with(|| a.scope.cmp(&b.scope))
        });
        out
    }

    pub fn metrics_rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        let section = |rows: &mut Vec<(String, String)>, name: &str| {
            rows.push((name.to_string(), String::new()));
        };
        let kv = |rows: &mut Vec<(String, String)>, k: &str, v: String| {
            rows.push((k.to_string(), v));
        };
        let m = &self.metrics;
        let now = Instant::now();

        section(&mut rows, "Session");
        let uptime = self.start.elapsed().as_secs();
        kv(&mut rows, "uptime", fmt_age(uptime));
        kv(
            &mut rows,
            "packets",
            format!(
                "{} ({} v4 · {} v6 · {} unparsed)",
                self.packet_total, m.v4_rx, m.v6_rx, self.unparsed
            ),
        );
        let per_min = if uptime > 0 {
            self.packet_total as f64 * 60.0 / uptime as f64
        } else {
            0.0
        };
        kv(&mut rows, "pkt/min overall", format!("{per_min:.1}"));
        kv(
            &mut rows,
            "pkt/min last 60s",
            m.recent_packets().to_string(),
        );
        let avg = m.bytes_total.checked_div(self.packet_total).unwrap_or(0);
        kv(
            &mut rows,
            "bytes",
            format!("{} (avg {avg} B/pkt)", fmt_bytes(m.bytes_total)),
        );
        kv(
            &mut rows,
            "last packet",
            m.last_packet_at
                .map(|t| {
                    format!(
                        "{} ago",
                        fmt_age(now.saturating_duration_since(t).as_secs())
                    )
                })
                .unwrap_or_else(|| "—".into()),
        );

        section(&mut rows, "Traffic");
        kv(
            &mut rows,
            "NOTIFY",
            format!(
                "{} alive · {} update · {} byebye · {} other",
                m.notify_alive, m.notify_update, m.notify_byebye, m.notify_other
            ),
        );
        kv(
            &mut rows,
            "search replies",
            format!("{} ok · {} non-200", m.responses_ok, m.responses_bad),
        );
        kv(
            &mut rows,
            "M-SEARCH seen",
            format!(
                "{} foreign · {} own (looped back)",
                m.searches_foreign, m.searches_own
            ),
        );
        kv(
            &mut rows,
            "socket",
            format!(
                "{} via 1900 listener · {} via search socket",
                m.via_listener, m.via_search
            ),
        );

        section(&mut rows, "Discovery");
        let live = self.devices.values().filter(|d| d.live()).count();
        kv(
            &mut rows,
            "devices",
            format!(
                "{} ({} live, {} byebye only)",
                self.devices.len(),
                live,
                self.devices.len() - live
            ),
        );
        kv(
            &mut rows,
            "devices ever / expired / byebye",
            format!(
                "{} / {} / {}",
                m.devices_seen_total, m.devices_expired_total, m.devices_byebye_total
            ),
        );
        let tree = self.rows();
        let nested = tree.iter().filter(|r| r.depth > 0).count();
        let roots = tree
            .iter()
            .filter(|r| r.depth == 0 && r.key != RowKey::Searches)
            .count();
        kv(
            &mut rows,
            "tree",
            format!("{roots} top-level · {nested} embedded"),
        );
        let adverts: Vec<_> = self
            .devices
            .values()
            .flat_map(|d| d.adverts.values())
            .collect();
        let (mut by_notify, mut by_reply, mut gone) = (0, 0, 0);
        let (mut short, mut std_age, mut long, mut missing) = (0, 0, 0, 0);
        let mut servers: HashMap<String, u64> = HashMap::new();
        let mut types: HashMap<String, u64> = HashMap::new();
        for a in &adverts {
            match (a.gone, a.via) {
                (Some(_), _) => gone += 1,
                (None, crate::app::AdvertVia::Notify) => by_notify += 1,
                (None, crate::app::AdvertVia::Response) => by_reply += 1,
            }
            match a.max_age {
                None => missing += 1,
                Some(n) if n < 1800 => short += 1,
                Some(1800) => std_age += 1,
                Some(_) => long += 1,
            }
            if let Some(s) = &a.server {
                *servers.entry(s.clone()).or_default() += 1;
            }
            let t = a.target.to_ascii_lowercase();
            let class = if t == "upnp:rootdevice" {
                "rootdevice".to_string()
            } else if t.starts_with("uuid:") {
                "uuid".to_string()
            } else if let Some((kind, name)) = urn_kind(&a.target) {
                format!("{kind}:{name}")
            } else {
                a.target.clone()
            };
            *types.entry(class).or_default() += 1;
        }
        kv(
            &mut rows,
            "adverts current",
            format!(
                "{} ({by_notify} via NOTIFY · {by_reply} via reply · {gone} byebye)",
                adverts.len()
            ),
        );
        kv(
            &mut rows,
            "max-age",
            format!("{short} <1800 · {std_age} =1800 · {long} >1800 · {missing} missing"),
        );
        let soonest = adverts
            .iter()
            .filter(|a| a.gone.is_none())
            .map(|a| a.remaining(now))
            .min();
        kv(
            &mut rows,
            "next expiry",
            soonest
                .map(|d| fmt_age(d.as_secs()))
                .unwrap_or_else(|| "—".into()),
        );
        let types = top(&types);
        for (t, c) in types.iter().take(TOP) {
            kv(&mut rows, &format!("type {t}"), c.to_string());
        }
        if types.len() > TOP {
            kv(
                &mut rows,
                "type more",
                format!("+{} more", types.len() - TOP),
            );
        }
        for (s, c) in top(&servers).iter().take(5) {
            kv(&mut rows, &format!("server ×{c}"), s.clone());
        }

        section(&mut rows, "Descriptions");
        let (mut ready, mut pending, mut failed) = (0, 0, 0);
        for st in self.descriptions.values() {
            match st {
                DescState::Ready(_) => ready += 1,
                DescState::Pending => pending += 1,
                DescState::Failed(_) => failed += 1,
            }
        }
        kv(
            &mut rows,
            "locations",
            format!(
                "{} ({ready} ready · {pending} pending · {failed} failed)",
                self.descriptions.len()
            ),
        );
        kv(
            &mut rows,
            "fetches ever",
            format!(
                "{} started ({} link-local) · {} ok · {} failed",
                m.fetch_started, m.fetch_link_local, m.fetch_ok, m.fetch_failed
            ),
        );
        let avg_ms = m.fetch_ms_total.checked_div(m.fetch_ok).unwrap_or(0);
        kv(
            &mut rows,
            "fetch time / size",
            format!(
                "avg {avg_ms} ms · max {} ms · {} total",
                m.fetch_ms_max,
                fmt_bytes(m.fetch_bytes)
            ),
        );
        let mut specs: HashMap<String, u64> = HashMap::new();
        let mut services = 0;
        for st in self.descriptions.values() {
            if let DescState::Ready(f) = st {
                let v = &f.description.spec_version;
                *specs
                    .entry(if v.is_empty() { "?".into() } else { v.clone() })
                    .or_default() += 1;
                f.description
                    .root
                    .walk(None, &mut |d, _| services += d.services.len());
            }
        }
        kv(
            &mut rows,
            "spec versions",
            or_dash(
                top(&specs)
                    .into_iter()
                    .map(|(v, c)| format!("UPnP {v} ×{c}"))
                    .collect(),
            ),
        );
        kv(&mut rows, "services described", services.to_string());

        section(&mut rows, "Searching");
        if self.passive {
            kv(&mut rows, "mode", "passive (no M-SEARCH)".into());
        } else {
            kv(
                &mut rows,
                "mode",
                format!(
                    "active · ST {} · MX {} · from port {}",
                    self.targets.join(", "),
                    self.mx,
                    {
                        let mut ports = self.search_ports.clone();
                        ports.sort_unstable();
                        ports.dedup();
                        or_dash(ports.iter().map(u16::to_string).collect())
                    }
                ),
            );
            kv(
                &mut rows,
                "sent",
                format!(
                    "{} rounds · next in {} · interval {}",
                    self.searches_sent,
                    self.next_search_in()
                        .map(|d| fmt_age(d.as_secs()))
                        .unwrap_or_else(|| "—".into()),
                    fmt_age(self.search_interval().as_secs())
                ),
            );
            let per = if self.searches_sent > 0 {
                self.responses as f64 / self.searches_sent as f64
            } else {
                0.0
            };
            kv(
                &mut rows,
                "replies",
                format!("{} ({per:.1} per round)", self.responses),
            );
        }

        section(&mut rows, "Control points");
        kv(
            &mut rows,
            "hosts",
            format!(
                "{} searching · {} active last 60s",
                m.control_points.len(),
                m.control_points
                    .values()
                    .filter(|c| now.saturating_duration_since(c.last) <= RECENT)
                    .count()
            ),
        );
        let mut cps: Vec<(&IpAddr, &ControlPoint)> = m.control_points.iter().collect();
        cps.sort_by(|a, b| b.1.searches.cmp(&a.1.searches).then_with(|| a.0.cmp(b.0)));
        for (ip, cp) in cps.iter().take(TOP) {
            let local = if self.local_ips.contains(ip) {
                " (this host)"
            } else {
                ""
            };
            kv(
                &mut rows,
                &format!("cp {ip}{local}"),
                format!(
                    "{} searches · {} ago · {}",
                    cp.searches,
                    fmt_age(now.saturating_duration_since(cp.last).as_secs()),
                    if cp.user_agent.is_empty() {
                        "(no USER-AGENT)"
                    } else {
                        &cp.user_agent
                    }
                ),
            );
        }
        for (st, c) in top(&m.search_targets).iter().take(5) {
            kv(&mut rows, &format!("ST ×{c}"), st.clone());
        }

        section(&mut rows, "Links");
        if let Some(sel) = &self.selection {
            let mut names: Vec<String> = sel.iter().cloned().collect();
            names.sort();
            kv(&mut rows, "selected", names.join(", "));
        }
        kv(&mut rows, "usable v4", or_dash(self.links.0.clone()));
        kv(&mut rows, "usable v6", or_dash(self.links.1.clone()));
        kv(&mut rows, "local addrs", self.local_ips.len().to_string());
        let ifaces = top(&m.iface_rx);
        for (iface, c) in ifaces.iter().take(TOP) {
            kv(&mut rows, &format!("rx {iface}"), c.to_string());
        }
        for (ip, c) in top(&m.source_rx).iter().take(5) {
            kv(&mut rows, &format!("talker {ip}"), format!("{c} pkts"));
        }

        // Issues last: the list can be long and the overlay scrolls.
        section(&mut rows, "Issues");
        let found = self.findings();
        let count = |s: Severity| found.iter().filter(|f| f.issue.severity == s).count();
        kv(
            &mut rows,
            "summary",
            format!(
                "{} errors · {} warnings · {} info",
                count(Severity::Error),
                count(Severity::Warning),
                count(Severity::Info)
            ),
        );
        // Embedded devices often share a name and a finding: one row
        // per (severity, scope, text) with a count, in worst-first order.
        let mut grouped: Vec<(&Finding, usize)> = Vec::new();
        for f in &found {
            match grouped
                .iter_mut()
                .find(|(g, _)| g.scope == f.scope && g.issue == f.issue)
            {
                Some((_, n)) => *n += 1,
                None => grouped.push((f, 1)),
            }
        }
        for (f, n) in grouped {
            let times = if n > 1 {
                format!(" ×{n}")
            } else {
                String::new()
            };
            kv(
                &mut rows,
                &format!("{} {}{times}", f.issue.severity.icon(), f.scope),
                f.issue.text.clone(),
            );
        }
        rows
    }
}

/// `urn:<domain>:device|service:<name>:<ver>` → (`device`, `name`).
fn urn_kind(t: &str) -> Option<(&str, &str)> {
    let mut parts = t.split(':');
    (parts.next()? == "urn").then_some(())?;
    parts.next()?;
    let kind = parts.next()?;
    let name = parts.next()?;
    matches!(kind, "device" | "service").then_some((kind, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urn_kinds() {
        assert_eq!(
            urn_kind("urn:schemas-upnp-org:device:MediaRenderer:1"),
            Some(("device", "MediaRenderer"))
        );
        assert_eq!(
            urn_kind("urn:dial-multiscreen-org:service:dial:1"),
            Some(("service", "dial"))
        );
        assert_eq!(urn_kind("upnp:rootdevice"), None);
    }

    #[test]
    fn top_sorts_by_count_then_key() {
        let m: HashMap<String, u64> = [("b".into(), 2), ("a".into(), 2), ("c".into(), 5)].into();
        let v: Vec<String> = top(&m).into_iter().map(|(k, _)| k).collect();
        assert_eq!(v, ["c", "a", "b"]);
    }
}
