// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! UPnP device description (UDA 2.0 §2.3): HTTP GET of an advertised
//! LOCATION and a namespace-agnostic parse of the device tree.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

pub fn parse(xml: &str) -> Result<Description, String> {
    let xml = xml.trim_start_matches('\u{feff}').trim_start();
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("XML: {e}"))?;
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

fn fetch(location: &str) -> Result<Fetched, String> {
    let url = check_location(location)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(FETCH_TIMEOUT))
        .max_redirects(0)
        .user_agent(crate::ssdp::user_agent())
        .build()
        .into();
    let start = Instant::now();
    let mut resp = agent
        .get(url.as_str())
        .call()
        .map_err(|e| format!("GET failed: {e}"))?;
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
        .map_err(|e| format!("reading body: {e}"))?;
    let elapsed = start.elapsed();
    let description = parse(&String::from_utf8_lossy(&body))?;
    Ok(Fetched {
        description,
        server,
        content_type,
        bytes: body.len(),
        elapsed,
    })
}

pub type FetchResult = (String, Result<Fetched, String>);

/// Fetch on a short-lived thread; the result is posted back keyed by
/// LOCATION. Callers dedupe so each location has one fetch in flight.
pub fn spawn_fetch(location: String, tx: mpsc::Sender<FetchResult>) {
    let _ = thread::Builder::new()
        .name("describe".into())
        .spawn(move || {
            let res = fetch(&location);
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
    fn location_must_be_http() {
        assert!(check_location("http://10.0.0.1/d.xml").is_ok());
        assert!(check_location("https://10.0.0.1/d.xml").is_err());
        assert!(check_location("file:///etc/passwd").is_err());
        assert!(check_location("not a url").is_err());
    }
}
