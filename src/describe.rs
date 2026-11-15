// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! UPnP device description (UDA 2.0 §2.3): HTTP GET of an advertised
//! LOCATION and a namespace-agnostic parse of the device tree.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// ureq's resolver hook lives in its semver-exempt `unversioned` module;
// a breaking change there shows up as a compile error on upgrade.
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

/// Descriptions are a few KiB; anything past this is refused.
const MAX_BODY: u64 = 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Icon {
    pub mimetype: String,
    pub width: String,
    pub height: String,
    pub depth: String,
    pub url: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Service {
    pub service_type: String,
    pub service_id: String,
    pub scpd_url: String,
    pub control_url: String,
    pub event_sub_url: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    pub device_type: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub manufacturer_url: String,
    pub model_description: String,
    pub model_name: String,
    pub model_number: String,
    pub model_url: String,
    pub serial_number: String,
    pub udn: String,
    pub presentation_url: String,
    pub icons: Vec<Icon>,
    pub services: Vec<Service>,
    pub devices: Vec<Device>,
}

impl Device {
    /// Depth-first search by UDN (`uuid:...`, case-insensitive).
    pub fn find(&self, udn: &str) -> Option<&Device> {
        if self.udn.eq_ignore_ascii_case(udn) {
            return Some(self);
        }
        self.devices.iter().find_map(|d| d.find(udn))
    }

    /// Visit every device with its parent UDN (`None` for the root).
    pub fn walk<'a>(
        &'a self,
        parent: Option<&'a str>,
        f: &mut dyn FnMut(&'a Device, Option<&'a str>),
    ) {
        f(self, parent);
        for d in &self.devices {
            d.walk(Some(&self.udn), f);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub spec_version: String,
    pub url_base: String,
    pub root: Device,
}

#[derive(Clone, Debug)]
pub struct Fetched {
    pub description: Description,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub bytes: usize,
    pub elapsed: Duration,
}

/// Local-name match: UPnP XML is namespaced (`urn:schemas-upnp-org:device-1-0`)
/// but vendors get prefixes and default namespaces wrong often enough
/// that matching the namespace would hide real devices.
fn child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn text(node: roxmltree::Node, name: &str) -> String {
    child(node, name)
        .and_then(|c| c.text())
        .map(|t| t.trim().to_string())
        .unwrap_or_default()
}

fn children<'a>(
    node: roxmltree::Node<'a, 'a>,
    list: &str,
    item: &'a str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'a>> + 'a {
    child(node, list).into_iter().flat_map(move |l| {
        l.children()
            .filter(move |c| c.is_element() && c.tag_name().name() == item)
    })
}

fn parse_device(node: roxmltree::Node) -> Device {
    Device {
        device_type: text(node, "deviceType"),
        friendly_name: text(node, "friendlyName"),
        manufacturer: text(node, "manufacturer"),
        manufacturer_url: text(node, "manufacturerURL"),
        model_description: text(node, "modelDescription"),
        model_name: text(node, "modelName"),
        model_number: text(node, "modelNumber"),
        model_url: text(node, "modelURL"),
        serial_number: text(node, "serialNumber"),
        udn: text(node, "UDN"),
        presentation_url: text(node, "presentationURL"),
        icons: children(node, "iconList", "icon")
            .map(|i| Icon {
                mimetype: text(i, "mimetype"),
                width: text(i, "width"),
                height: text(i, "height"),
                depth: text(i, "depth"),
                url: text(i, "url"),
            })
            .collect(),
        services: children(node, "serviceList", "service")
            .map(|s| Service {
                service_type: text(s, "serviceType"),
                service_id: text(s, "serviceId"),
                scpd_url: text(s, "SCPDURL"),
                control_url: text(s, "controlURL"),
                event_sub_url: text(s, "eventSubURL"),
            })
            .collect(),
        devices: children(node, "deviceList", "device")
            .map(parse_device)
            .collect(),
    }
}

/// Lines and characters kept from a failed body for display.
const PREVIEW_LINES: usize = 12;
const PREVIEW_LINE_CHARS: usize = 160;

/// Printable form of untrusted text: control characters (bar tab) are
/// escaped so a hostile body cannot drive the terminal.
pub fn printable(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

/// Up to 60 characters around a 1-based (row, col) position, quoted:
/// enough to see what the parser tripped over.
pub fn excerpt(text: &str, row: u32, col: u32) -> String {
    let line = text
        .lines()
        .nth(row.saturating_sub(1) as usize)
        .unwrap_or("");
    let at = col.saturating_sub(1) as usize;
    let start = at.saturating_sub(20);
    let window: String = line.chars().skip(start).take(60).collect();
    let lead = if start > 0 { "…" } else { "" };
    let tail = if line.chars().count() > start + 60 {
        "…"
    } else {
        ""
    };
    format!("\"{lead}{}{tail}\"", printable(&window))
}

pub fn parse(xml: &str) -> Result<Description, String> {
    let xml = xml.trim_start_matches('\u{feff}').trim_start();
    if xml.is_empty() {
        return Err("empty body".into());
    }
    let doc = roxmltree::Document::parse(xml).map_err(|e| {
        let pos = e.pos();
        format!("XML: {e} near {}", excerpt(xml, pos.row, pos.col))
    })?;
    let root = doc.root_element();
    if root.tag_name().name() != "root" {
        return Err(format!(
            "unexpected document element <{}>, want <root>",
            root.tag_name().name()
        ));
    }
    let device = child(root, "device").ok_or("missing <device>")?;
    let spec_version = child(root, "specVersion")
        .map(|s| format!("{}.{}", text(s, "major"), text(s, "minor")))
        .unwrap_or_default();
    Ok(Description {
        spec_version,
        url_base: text(root, "URLBase"),
        root: parse_device(device),
    })
}

/// Resolve a description-relative URL against URLBase (deprecated but
/// still honored) or the LOCATION it was fetched from.
pub fn resolve(location: &str, url_base: &str, rel: &str) -> String {
    if rel.is_empty() {
        return String::new();
    }
    let base = if url_base.is_empty() {
        location
    } else {
        url_base
    };
    url::Url::parse(base)
        .and_then(|b| b.join(rel))
        .map(|u| u.to_string())
        .unwrap_or_else(|_| rel.to_string())
}

/// Only plain http: LOCATION is attacker-controlled input from the
/// network, and UDA descriptions are served over HTTP.
pub fn check_location(location: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(location).map_err(|e| format!("bad LOCATION URL: {e}"))?;
    if url.scheme() != "http" {
        return Err(format!("unsupported scheme '{}' (http only)", url.scheme()));
    }
    if url.host().is_none() {
        return Err("LOCATION URL has no host".into());
    }
    Ok(url)
}

/// IPv6 link-local LOCATION host (`fe80::/10`): only reachable with
/// the zone of the link the advert arrived on.
pub fn link_local_host(url: &url::Url) -> Option<Ipv6Addr> {
    match url.host() {
        Some(url::Host::Ipv6(ip)) if ip.is_unicast_link_local() => Some(ip),
        _ => None,
    }
}

/// Resolver that pins a link-local host to its zone (scope id), so the
/// connect leaves through the advert's ingress interface. The HTTP Host
/// header stays zone-free, as RFC 6874 §2 requires.
#[derive(Debug)]
struct ScopedResolver {
    addr: SocketAddrV6,
}

impl Resolver for ScopedResolver {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut addrs = self.empty();
        addrs.push(SocketAddr::V6(self.addr));
        Ok(addrs)
    }
}

/// What the server sent alongside a failure: status, headers, and the
/// first lines of the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyPreview {
    pub status: u16,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub bytes: usize,
    pub lines: Vec<String>,
    /// Lines past `PREVIEW_LINES` that were cut.
    pub more_lines: usize,
}

impl BodyPreview {
    fn new(status: u16, content_type: Option<String>, server: Option<String>, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let all: Vec<&str> = text.lines().collect();
        BodyPreview {
            status,
            content_type,
            server,
            bytes: body.len(),
            lines: all
                .iter()
                .take(PREVIEW_LINES)
                .map(|l| clip(&printable(l), PREVIEW_LINE_CHARS))
                .collect(),
            more_lines: all.len().saturating_sub(PREVIEW_LINES),
        }
    }
}

/// A failed fetch: one-line message (used in issue lists) plus the body
/// preview when the server answered at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchError {
    pub message: String,
    pub body: Option<BodyPreview>,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for FetchError {
    fn from(message: String) -> Self {
        Self {
            message,
            body: None,
        }
    }
}

impl From<&str> for FetchError {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

fn fetch(location: &str, scope: u32) -> Result<Fetched, FetchError> {
    let url = check_location(location)?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(FETCH_TIMEOUT))
        // Non-2xx bodies are kept for the preview instead of an opaque error.
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent(crate::ssdp::user_agent())
        .build();
    let agent = match link_local_host(&url) {
        Some(_) if scope == 0 => return Err("link-local LOCATION without a known interface".into()),
        Some(ip) => {
            let port = url.port_or_known_default().unwrap_or(80);
            ureq::Agent::with_parts(
                config,
                DefaultConnector::default(),
                ScopedResolver {
                    addr: SocketAddrV6::new(ip, port, 0, scope),
                },
            )
        }
        None => ureq::Agent::new_with_config(config),
    };
    let start = Instant::now();
    let mut resp = agent
        .get(url.as_str())
        .call()
        .map_err(|e| FetchError::from(format!("GET failed: {e}")))?;
    let status = resp.status().as_u16();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let server = header("server");
    let content_type = header("content-type");
    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_vec()
        .map_err(|e| FetchError::from(format!("reading body: {e}")))?;
    let elapsed = start.elapsed();
    let failed = |message: String| FetchError {
        message,
        body: Some(BodyPreview::new(
            status,
            content_type.clone(),
            server.clone(),
            &body,
        )),
    };
    if !(200..300).contains(&status) {
        return Err(failed(format!("HTTP {status}")));
    }
    let description = parse(&String::from_utf8_lossy(&body)).map_err(failed)?;
    Ok(Fetched {
        description,
        server,
        content_type,
        bytes: body.len(),
        elapsed,
    })
}

pub type FetchResult = (String, Result<Fetched, FetchError>);

/// Fetch on a short-lived thread; the result is posted back keyed by
/// LOCATION. Callers dedupe so each location has one fetch in flight.
pub fn spawn_fetch(location: String, scope: u32, tx: mpsc::Sender<FetchResult>) {
    let _ = thread::Builder::new()
        .name("describe".into())
        .spawn(move || {
            let res = fetch(&location, scope);
            if let Err(e) = &res {
                log::info!("uex: description {location}: {e}");
            }
            let _ = tx.send((location, res));
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName> Router </friendlyName>
    <manufacturer>ACME</manufacturer>
    <UDN>uuid:root-1</UDN>
    <iconList><icon><mimetype>image/png</mimetype><width>48</width><height>48</height><depth>24</depth><url>/i.png</url></icon></iconList>
    <serviceList><service>
      <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
      <serviceId>urn:upnp-org:serviceId:L3F</serviceId>
      <SCPDURL>/l3f.xml</SCPDURL><controlURL>/ctl</controlURL><eventSubURL>/evt</eventSubURL>
    </service></serviceList>
    <deviceList><device>
      <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <friendlyName>WAN</friendlyName>
      <UDN>uuid:wan-1</UDN>
    </device></deviceList>
  </device>
</root>"#;

    #[test]
    fn parses_tree() {
        let d = parse(XML).unwrap();
        assert_eq!(d.spec_version, "1.0");
        assert_eq!(d.root.friendly_name, "Router");
        assert_eq!(d.root.icons[0].width, "48");
        assert_eq!(d.root.services[0].control_url, "/ctl");
        assert_eq!(d.root.devices[0].udn, "uuid:wan-1");
        assert_eq!(d.root.find("UUID:WAN-1").unwrap().friendly_name, "WAN");
        let mut seen = Vec::new();
        d.root.walk(None, &mut |dev, parent| {
            seen.push((dev.udn.clone(), parent.map(str::to_string)))
        });
        assert_eq!(seen[1], ("uuid:wan-1".into(), Some("uuid:root-1".into())));
    }

    #[test]
    fn tolerates_bom_and_prefixed_namespace() {
        let xml = "\u{feff}  <u:root xmlns:u=\"urn:x\"><u:device><u:UDN>uuid:a</u:UDN></u:device></u:root>";
        assert_eq!(parse(xml).unwrap().root.udn, "uuid:a");
        assert!(parse("<html/>").is_err());
        assert!(parse("<root/>").is_err());
    }

    #[test]
    fn resolves_relative_urls() {
        let loc = "http://10.0.0.1:5000/dev/desc.xml";
        assert_eq!(resolve(loc, "", "/i.png"), "http://10.0.0.1:5000/i.png");
        assert_eq!(resolve(loc, "", "ctl"), "http://10.0.0.1:5000/dev/ctl");
        assert_eq!(
            resolve(loc, "http://10.0.0.9:80/", "ctl"),
            "http://10.0.0.9/ctl"
        );
        assert_eq!(resolve(loc, "", ""), "");
    }

    #[test]
    fn detects_link_local_hosts() {
        let ll = |u: &str| link_local_host(&url::Url::parse(u).unwrap());
        assert!(ll("http://[fe80::1]:49000/d.xml").is_some());
        assert!(ll("http://[fd00::1]/d.xml").is_none());
        assert!(ll("http://[2001:db8::1]/d.xml").is_none());
        assert!(ll("http://10.0.0.1/d.xml").is_none());
        let err = fetch("http://[fe80::1]:49000/d.xml", 0).unwrap_err();
        assert!(err.message.contains("without a known interface"), "{err}");
    }

    /// End to end over a real link-local address when the host has one
    /// (CI runners may not): serve on `fe80::…%iface`, fetch by zone.
    #[test]
    fn fetches_link_local_with_scope() {
        use std::io::{Read, Write};
        let Some((ip, idx)) = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .find_map(|i| match (i.addr, i.index) {
                (if_addrs::IfAddr::V6(v6), Some(idx)) if v6.ip.is_unicast_link_local() => {
                    Some((v6.ip, idx))
                }
                _ => None,
            })
        else {
            return;
        };
        let Ok(listener) = std::net::TcpListener::bind(SocketAddrV6::new(ip, 0, 0, idx)) else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let body = "<root><device><UDN>uuid:ll</UDN></device></root>";
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let n = conn.read(&mut req).unwrap();
            let req = String::from_utf8_lossy(&req[..n]).to_string();
            write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            req
        });
        let f = fetch(&format!("http://[{ip}]:{port}/d.xml"), idx).unwrap();
        assert_eq!(f.description.root.udn, "uuid:ll");
        let req = server.join().unwrap();
        // Host header carries no zone (RFC 6874 §2).
        assert!(
            req.to_ascii_lowercase()
                .contains(&format!("host: [{ip}]:{port}")),
            "{req}"
        );
    }

    #[test]
    fn parse_errors_quote_the_offending_text() {
        let err = parse("status=ok").unwrap_err();
        assert!(err.starts_with("XML: "), "{err}");
        assert!(err.ends_with("near \"status=ok\""), "{err}");
        assert_eq!(parse("  \n").unwrap_err(), "empty body");
        let long = format!("<root>\n<a>{}<b></a>", "x".repeat(100));
        let err = parse(&long).unwrap_err();
        assert!(err.contains("near \"…"), "{err}");
        // Control characters are escaped, never passed to the terminal.
        assert_eq!(excerpt("a\x1b[2Jb", 1, 1), "\"a\\u{1b}[2Jb\"");
    }

    #[test]
    fn body_preview_caps_lines_and_width() {
        let body: String = (0..20)
            .map(|i| format!("line {i} {}\n", "y".repeat(200)))
            .collect();
        let p = BodyPreview::new(404, Some("text/plain".into()), None, body.as_bytes());
        assert_eq!(p.lines.len(), PREVIEW_LINES);
        assert_eq!(p.more_lines, 8);
        assert!(p.lines[0].ends_with('…'));
        assert_eq!(p.lines[0].chars().count(), PREVIEW_LINE_CHARS + 1);
    }

    /// Serve one canned HTTP response on loopback, return the URL.
    fn serve_once(response: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _ = conn.read(&mut [0u8; 1024]);
            conn.write_all(response.as_bytes()).unwrap();
        });
        format!("http://127.0.0.1:{port}/d.xml")
    }

    #[test]
    fn failed_fetches_keep_a_body_preview() {
        let url = serve_once(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 22\r\n\
             Connection: close\r\n\r\n<h1>no such page</h1>\n",
        );
        let err = fetch(&url, 0).unwrap_err();
        assert_eq!(err.message, "HTTP 404");
        let body = err.body.unwrap();
        assert_eq!(body.status, 404);
        assert_eq!(body.content_type.as_deref(), Some("text/html"));
        assert_eq!(body.lines, ["<h1>no such page</h1>"]);

        let url = serve_once(
            "HTTP/1.1 200 OK\r\nServer: NRDP/1\r\nContent-Length: 9\r\n\
             Connection: close\r\n\r\nstatus=ok",
        );
        let err = fetch(&url, 0).unwrap_err();
        assert!(err.message.contains("near \"status=ok\""), "{err}");
        let body = err.body.unwrap();
        assert_eq!((body.status, body.content_type, body.bytes), (200, None, 9));
        assert_eq!(body.server.as_deref(), Some("NRDP/1"));
    }

    #[test]
    fn location_must_be_http() {
        assert!(check_location("http://10.0.0.1/d.xml").is_ok());
        assert!(check_location("https://10.0.0.1/d.xml").is_err());
        assert!(check_location("file:///etc/passwd").is_err());
        assert!(check_location("not a url").is_err());
    }
}
