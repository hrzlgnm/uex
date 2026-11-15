// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Raw SSDP transport (UDA 2.0 §1): the multicast listeners on port 1900
//! that observe NOTIFY and other control points' M-SEARCH, plus one
//! ephemeral-port search socket per family that sends our M-SEARCH and
//! receives the unicast responses. Every packet carries its ingress
//! interface from IP_PKTINFO.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use socket2::{Domain, SockAddr};
use socket_pktinfo::PktInfoUdpSocket;

pub const SSDP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// Link-local scope (UDA 2.0 §1.1.2): the one IPv6 control points search on.
pub const SSDP_V6_LINK: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);
/// Site-local scope: devices may also announce here, so listen on it.
pub const SSDP_V6_SITE: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xc);
pub const SSDP_PORT: u16 = 1900;
/// Interface re-enumeration period: picks up links that appear at
/// runtime and re-joins flapped ones.
const IFACE_REFRESH: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// Which socket a packet arrived on: the shared port-1900 listener
/// (multicast NOTIFY / M-SEARCH) or our own search socket (unicast
/// M-SEARCH responses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Listener,
    Search,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Notify,
    Search,
    Response,
}

/// One parsed HTTPU message: start line plus headers in wire order.
/// Header names keep wire case for display; lookups are case-insensitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    /// Lines that are neither blank nor `Name: value`.
    pub malformed_lines: usize,
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// HTTP status code of a response start line.
    pub fn status(&self) -> Option<u16> {
        if self.kind != Kind::Response {
            return None;
        }
        self.start_line.split_whitespace().nth(1)?.parse().ok()
    }
}

/// Parse an SSDP datagram. Tolerates bare `\n` line endings (common in
/// the wild); anything after the blank line is ignored (SSDP has no
/// body). Returns `None` when the start line is not an SSDP request or
/// an HTTP response.
pub fn parse(raw: &[u8]) -> Option<Message> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let start_line = lines.next()?.trim().to_string();
    let kind = if start_line.starts_with("NOTIFY ") {
        Kind::Notify
    } else if start_line.starts_with("M-SEARCH ") {
        Kind::Search
    } else if start_line.starts_with("HTTP/") {
        Kind::Response
    } else {
        return None;
    };
    let mut headers = Vec::new();
    let mut malformed_lines = 0;
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        match line.split_once(':') {
            Some((k, v)) if !k.trim().is_empty() => {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            _ => malformed_lines += 1,
        }
    }
    Some(Message {
        kind,
        start_line,
        headers,
        malformed_lines,
    })
}

/// One received datagram with its ingress context.
#[derive(Clone, Debug)]
pub struct Packet {
    pub at: SystemTime,
    pub received: Instant,
    pub src: SocketAddr,
    pub dst: IpAddr,
    pub iface: String,
    /// Ingress interface index: the zone for link-local LOCATION URLs.
    pub ifindex: u32,
    pub via: Via,
    pub raw: Vec<u8>,
    pub msg: Option<Message>,
}

/// An M-SEARCH to send on every selected interface of both families.
#[derive(Clone, Debug)]
pub struct SearchRequest {
    pub st: String,
    pub mx: u8,
}

/// Handles to the running transport threads.
pub struct Transport {
    pub rx: mpsc::Receiver<Packet>,
    pub search_tx: Vec<mpsc::Sender<SearchRequest>>,
    /// Local ports of our search sockets: our own M-SEARCH loops back to
    /// the port-1900 listener and is recognized by these.
    pub search_ports: Vec<u16>,
    /// Startup problems worth surfacing in the UI (e.g. port 1900 busy).
    pub warnings: Vec<String>,
}

/// Start listener and search threads for both families. A family whose
/// sockets fail to open is skipped with a warning instead of aborting:
/// hosts without IPv6 are common.
/// `search_port` 0 picks an ephemeral port; a fixed one lets a host
/// firewall allow the unicast M-SEARCH replies (stateful firewalls
/// cannot match a unicast reply to a multicast request).
pub fn spawn(
    selection: Option<HashSet<String>>,
    passive: bool,
    search_port: u16,
) -> Result<Transport> {
    let (tx, rx) = mpsc::channel();
    let mut search_tx = Vec::new();
    let mut search_ports = Vec::new();
    let mut warnings = Vec::new();
    let mut any = false;

    for family in [Family::V4, Family::V6] {
        // Searching from 1900 means the listener sends too: a second
        // socket on 1900 would receive every multicast packet twice.
        let shared = !passive && search_port == SSDP_PORT;
        let mut listening = false;
        match create_socket(family, SSDP_PORT) {
            Ok(sock) => {
                any = true;
                listening = true;
                let qrx = shared.then(|| {
                    let (qtx, qrx) = mpsc::channel();
                    search_tx.push(qtx);
                    search_ports.push(SSDP_PORT);
                    qrx
                });
                let tx = tx.clone();
                let sel = selection.clone();
                thread::Builder::new()
                    .name(format!("ssdp-listen-{family:?}"))
                    .spawn(move || run_socket(&sock, tx, qrx, family, Via::Listener, sel))?;
            }
            Err(e) => warnings.push(format!("{family:?} listener on port {SSDP_PORT}: {e}")),
        }
        if passive || (shared && listening) {
            continue;
        }
        // Without a 1900 listener, fall back to an ephemeral search port.
        let port = if search_port == SSDP_PORT {
            0
        } else {
            search_port
        };
        match create_socket(family, port) {
            Ok(sock) => {
                any = true;
                if let Ok(std) = sock.try_clone_std() {
                    if let Ok(addr) = std.local_addr() {
                        search_ports.push(addr.port());
                    }
                }
                let (qtx, qrx) = mpsc::channel();
                search_tx.push(qtx);
                let tx = tx.clone();
                let sel = selection.clone();
                thread::Builder::new()
                    .name(format!("ssdp-search-{family:?}"))
                    .spawn(move || run_socket(&sock, tx, Some(qrx), family, Via::Search, sel))?;
            }
            Err(e) => warnings.push(format!("{family:?} search socket: {e}")),
        }
    }
    if !any {
        anyhow::bail!("no SSDP socket could be opened: {}", warnings.join("; "));
    }
    for w in &warnings {
        log::warn!("uex: {w}");
    }
    Ok(Transport {
        rx,
        search_tx,
        search_ports,
        warnings,
    })
}

fn create_socket(family: Family, port: u16) -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(match family {
        Family::V4 => Domain::IPV4,
        Family::V6 => Domain::IPV6,
    })?;
    // Share port 1900 with any local SSDP stack (minissdpd, a media
    // server, ...): multicast is delivered to every reusing socket.
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    // Loop stays on: without it, devices on this very host would never
    // see our M-SEARCH. Our own loopback is filtered by search port.
    match family {
        Family::V4 => {
            socket.set_multicast_loop_v4(true)?;
            // UDA 2.0 §1.1.2: TTL default 2.
            socket.set_multicast_ttl_v4(2)?;
            socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        }
        Family::V6 => {
            socket.set_multicast_loop_v6(true)?;
            socket.set_multicast_hops_v6(2)?;
            socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        }
    }
    Ok(socket)
}

fn run_socket(
    socket: &PktInfoUdpSocket,
    tx: mpsc::Sender<Packet>,
    search_rx: Option<mpsc::Receiver<SearchRequest>>,
    family: Family,
    via: Via,
    selection: Option<HashSet<String>>,
) {
    let mut buf = vec![0u8; 65535];
    let mut ifaces_v4: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut ifaces_v6: Vec<(String, u32)> = Vec::new();
    let mut ifnames: HashMap<u32, String> = HashMap::new();
    let mut last_refresh: Option<Instant> = None;

    loop {
        if last_refresh.is_none_or(|t| t.elapsed() >= IFACE_REFRESH) {
            last_refresh = Some(Instant::now());
            ifnames = interface_names();
            match family {
                Family::V4 => ifaces_v4 = v4_interfaces(selection.as_ref()),
                Family::V6 => ifaces_v6 = v6_interfaces(selection.as_ref()),
            }
            // Only the listener joins the groups; responses to our
            // search socket are unicast. Joins are idempotent and
            // re-run so flapped links get their membership back.
            if via == Via::Listener {
                for (name, ip) in &ifaces_v4 {
                    join_logged(socket.join_multicast_v4(&SSDP_V4, ip), name);
                }
                for (name, idx) in &ifaces_v6 {
                    join_logged(socket.join_multicast_v6(&SSDP_V6_LINK, *idx), name);
                    join_logged(socket.join_multicast_v6(&SSDP_V6_SITE, *idx), name);
                }
            }
        }

        if let Some(rx) = search_rx.as_ref() {
            while let Ok(req) = rx.try_recv() {
                send_search(socket, &req, family, &ifaces_v4, &ifaces_v6);
            }
        }

        match socket.recv(&mut buf) {
            Ok((len, info)) => {
                // The v6 socket is dual-stack: leave v4 to the v4 socket.
                if is_v4_mapped(&info.addr_src) {
                    continue;
                }
                let ifindex = info.if_index as u32;
                if !ifnames.contains_key(&ifindex) {
                    ifnames = interface_names();
                }
                let iface = ifnames.get(&ifindex).cloned().unwrap_or_default();
                if !interface_selected(&iface, selection.as_ref()) {
                    continue;
                }
                let raw = buf[..len].to_vec();
                let packet = Packet {
                    at: SystemTime::now(),
                    received: Instant::now(),
                    src: info.addr_src,
                    dst: info.addr_dst,
                    iface,
                    ifindex,
                    via,
                    msg: parse(&raw),
                    raw,
                };
                if tx.send(packet).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(30));
            }
            Err(e) => {
                log::error!("uex: recv error: {e}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn join_logged(res: std::io::Result<()>, name: &str) {
    if let Err(e) = res {
        // Duplicate joins report AddrInUse: membership already there.
        if e.kind() != std::io::ErrorKind::AddrInUse {
            log::warn!("uex: multicast join on {name}: {e}");
        }
    }
}

/// UDA 2.0 §1.3.2 M-SEARCH. HOST names the family's multicast group.
pub fn encode_search(req: &SearchRequest, family: Family) -> String {
    let host = match family {
        Family::V4 => format!("{SSDP_V4}:{SSDP_PORT}"),
        Family::V6 => format!("[FF02::C]:{SSDP_PORT}"),
    };
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {host}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: {st}\r\n\
         USER-AGENT: {ua}\r\n\
         \r\n",
        mx = req.mx,
        st = req.st,
        ua = user_agent(),
    )
}

/// `OS/version UPnP/2.0 product/version` (UDA 2.0 §1.3.2).
pub fn user_agent() -> String {
    format!(
        "{}/1 UPnP/2.0 {}/{}",
        std::env::consts::OS,
        crate::APP_NAME,
        env!("CARGO_PKG_VERSION")
    )
}

/// One copy per interface, each forced out its own link: otherwise
/// the kernel uses only the default multicast interface.
fn send_search(
    socket: &PktInfoUdpSocket,
    req: &SearchRequest,
    family: Family,
    ifaces_v4: &[(String, Ipv4Addr)],
    ifaces_v6: &[(String, u32)],
) {
    let payload = encode_search(req, family);
    let send = |dest: SocketAddr, name: &str| {
        if let Err(e) = socket.send_to(payload.as_bytes(), &SockAddr::from(dest)) {
            log::debug!("uex: M-SEARCH via {name}: {e}");
        }
    };
    match family {
        Family::V4 => {
            for (name, ip) in ifaces_v4 {
                let _ = socket.set_multicast_if_v4(ip);
                send(SocketAddrV4::new(SSDP_V4, SSDP_PORT).into(), name);
            }
        }
        Family::V6 => {
            for (name, idx) in ifaces_v6 {
                let _ = socket.set_multicast_if_v6(*idx);
                send(
                    SocketAddrV6::new(SSDP_V6_LINK, SSDP_PORT, 0, *idx).into(),
                    name,
                );
            }
        }
    }
}

fn is_v4_mapped(addr: &SocketAddr) -> bool {
    matches!(addr.ip(), IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

fn interface_names() -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let Some(idx) = iface.index {
            names.entry(idx).or_insert(iface.name);
        }
    }
    names
}

/// Every local address, for recognizing our own looped-back searches.
pub fn local_ips() -> HashSet<IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.ip())
        .collect()
}

fn usable_interface(iface: &if_addrs::Interface) -> bool {
    !iface.is_p2p() && iface.is_oper_up()
}

fn skipped_interface(name: &str) -> bool {
    name == "lo" || name.starts_with("docker") || name.starts_with("veth")
}

/// All interface names in any state: the validation universe for `-i`.
pub fn available_interfaces() -> HashSet<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.name)
        .collect()
}

/// Validate an explicit `-i/--interfaces` selection against the
/// available names; abort listing them when one is unknown.
pub fn validate_selection(
    requested: &[String],
    available: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut sorted: Vec<&str> = available.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    for name in requested {
        if !available.contains(name) {
            anyhow::bail!(
                "Interface '{name}' not found. Available interfaces: {}",
                sorted.join(", ")
            );
        }
    }
    Ok(requested.iter().cloned().collect())
}

fn interface_selected(name: &str, selection: Option<&HashSet<String>>) -> bool {
    selection.is_none_or(|sel| sel.contains(name))
}

/// Explicit selection overrides the loopback/container skip policy but
/// still requires the link to be up.
fn join_candidate(name: &str, usable: bool, selection: Option<&HashSet<String>>) -> bool {
    usable
        && match selection {
            Some(sel) => sel.contains(name),
            None => !skipped_interface(name),
        }
}

fn v4_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if !join_candidate(&iface.name, usable_interface(&iface), selection) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            if seen.insert(iface.name.clone()) {
                out.push((iface.name.clone(), v4.ip));
            }
        }
    }
    out
}

fn v6_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if !join_candidate(&iface.name, usable_interface(&iface), selection) {
            continue;
        }
        if let (if_addrs::IfAddr::V6(v6), Some(idx)) = (&iface.addr, iface.index) {
            // One join per link; only links with a link-local address
            // can carry FF02::C traffic.
            if v6.ip.is_unicast_link_local() && seen.insert(iface.name.clone()) {
                out.push((iface.name.clone(), idx));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_notify_with_crlf() {
        let raw = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
            CACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.0.0.2:49152/desc.xml\r\n\
            NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n\
            USN: uuid:abc::upnp:rootdevice\r\n\r\n";
        let m = parse(raw).unwrap();
        assert_eq!(m.kind, Kind::Notify);
        assert_eq!(m.header("nts"), Some("ssdp:alive"));
        assert_eq!(m.header("Location"), Some("http://10.0.0.2:49152/desc.xml"));
        assert_eq!(m.malformed_lines, 0);
    }

    #[test]
    fn parses_response_with_bare_lf_and_empty_ext() {
        let raw = b"HTTP/1.1 200 OK\nEXT:\nST: ssdp:all\nUSN: uuid:x\n\n";
        let m = parse(raw).unwrap();
        assert_eq!(m.kind, Kind::Response);
        assert_eq!(m.status(), Some(200));
        assert!(m.has_header("ext"));
        assert_eq!(m.header("EXT"), Some(""));
    }

    #[test]
    fn counts_malformed_lines_and_rejects_garbage() {
        let m = parse(b"M-SEARCH * HTTP/1.1\r\nnot a header\r\nMX: 2\r\n\r\n").unwrap();
        assert_eq!(m.kind, Kind::Search);
        assert_eq!(m.malformed_lines, 1);
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(b"").is_none());
    }

    #[test]
    fn encoded_search_round_trips() {
        let req = SearchRequest {
            st: "ssdp:all".into(),
            mx: 2,
        };
        let text = encode_search(&req, Family::V6);
        assert!(text.ends_with("\r\n\r\n"));
        let m = parse(text.as_bytes()).unwrap();
        assert_eq!(m.kind, Kind::Search);
        assert_eq!(m.header("HOST"), Some("[FF02::C]:1900"));
        assert_eq!(m.header("MAN"), Some("\"ssdp:discover\""));
        assert_eq!(m.header("MX"), Some("2"));
        assert!(m.header("USER-AGENT").unwrap().contains(" UPnP/2.0 "));
    }

    #[test]
    fn selection_validation_names_alternatives() {
        let avail: HashSet<String> = ["eth0", "br0"].iter().map(|s| s.to_string()).collect();
        assert!(validate_selection(&["eth0".into()], &avail).is_ok());
        let err = validate_selection(&["wlan9".into()], &avail).unwrap_err();
        assert!(err.to_string().contains("br0, eth0"));
    }

    #[test]
    fn explicit_selection_overrides_skip_policy() {
        assert!(!join_candidate("lo", true, None));
        let sel: HashSet<String> = ["lo".to_string()].into();
        assert!(join_candidate("lo", true, Some(&sel)));
        assert!(!join_candidate("lo", false, Some(&sel)));
    }
}
