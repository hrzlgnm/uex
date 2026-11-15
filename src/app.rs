// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Browser state: advertisement cache keyed by device UUID and USN,
//! description fetches, search scheduling, expiry, and selection.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::describe::{self, FetchResult, Fetched};
use crate::issues::{advert_issues, search_issues, Issue};
use crate::metrics::Metrics;
use crate::ssdp::{self, Kind, Message, Packet, SearchRequest, Transport};
use crate::ui;

/// Packet log and observed-search caps: bounded memory on busy links.
const MAX_PACKETS: usize = 2000;
const MAX_SEARCHES: usize = 500;
/// How long a byebye'd advert stays visible (greyed) before removal.
const BYEBYE_LINGER: Duration = Duration::from_secs(30);
/// UDA 2.0 §1.2.2: max-age SHOULD be ≥ 1800; used when a cache entry
/// carries no parsable max-age, so it still expires eventually.
const DEFAULT_MAX_AGE: u32 = 1800;
/// Re-search backoff: first rescan after the startup burst, doubling
/// up to the cap. Devices re-announce on their own well before expiry.
const FIRST_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// Startup burst spacing: SSDP is plain UDP, UDA advises repeating.
const BURST_GAPS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];

/// std-only jitter source (splitmix64 over time and a counter).
fn rand_u32() -> u32 {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() ^ (d.subsec_nanos() as u64))
        .unwrap_or(0x9e3779b9);
    let c = CTR.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    let mut x = t.wrapping_add(c).wrapping_add(0x9e3779b97f4a7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x >> 32) as u32
}

fn rand_range(lo_ms: u64, hi_ms: u64) -> Duration {
    let span = hi_ms.saturating_sub(lo_ms).saturating_add(1);
    Duration::from_millis(lo_ms + (rand_u32() as u64 % span))
}

/// Device key from a USN: `uuid:<id>[::<type>]` → lowercase `<id>`.
pub fn usn_uuid(usn: &str) -> Option<String> {
    let rest = usn
        .get(..5)?
        .eq_ignore_ascii_case("uuid:")
        .then(|| &usn[5..])?;
    let id = rest.split("::").next()?.trim();
    (!id.is_empty()).then(|| id.to_ascii_lowercase())
}

/// `max-age=N` from CACHE-CONTROL (directives may be comma-separated).
pub fn parse_max_age(cache_control: &str) -> Option<u32> {
    cache_control.split(',').find_map(|d| {
        let (k, v) = d.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| v.trim().trim_matches('"').parse().ok())?
    })
}

/// Drop the common UPnP Forum prefix for compact display.
pub fn short_type(t: &str) -> &str {
    t.strip_prefix("urn:schemas-upnp-org:").unwrap_or(t)
}

/// Source address with its ingress interface: `%iface` for IPv6
/// link-local (it is the scope), `@iface` otherwise.
pub fn source_label(src: &SocketAddr, iface: &str) -> String {
    let ip = src.ip();
    if iface.is_empty() {
        return ip.to_string();
    }
    match ip {
        IpAddr::V6(v6) if v6.is_unicast_link_local() => format!("{ip}%{iface}"),
        _ => format!("{ip}@{iface}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertVia {
    Notify,
    Response,
}

#[derive(Clone, Debug)]
pub struct Advert {
    /// NT for NOTIFY, ST for responses.
    pub target: String,
    pub location: Option<String>,
    /// Every LOCATION this advert has used: multi-homed devices
    /// alternate v4/v6 URLs, and each keeps its description cached.
    pub locations: Vec<String>,
    pub server: Option<String>,
    pub max_age: Option<u32>,
    pub refreshed: Instant,
    pub first_seen: Instant,
    pub src: SocketAddr,
    pub iface: String,
    pub via: AdvertVia,
    pub boot_id: Option<String>,
    pub config_id: Option<String>,
    pub count: u64,
    pub issues: Vec<Issue>,
    pub gone: Option<Instant>,
}

impl Advert {
    pub fn lifetime(&self) -> Duration {
        Duration::from_secs(self.max_age.unwrap_or(DEFAULT_MAX_AGE) as u64)
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.lifetime()
            .saturating_sub(now.saturating_duration_since(self.refreshed))
    }
}

#[derive(Clone, Debug)]
pub struct DeviceEntry {
    pub uuid: String,
    pub adverts: BTreeMap<String, Advert>,
    pub first_seen: Instant,
}

impl DeviceEntry {
    pub fn live(&self) -> bool {
        self.adverts.values().any(|a| a.gone.is_none())
    }
}

#[derive(Clone, Debug)]
pub enum DescState {
    Pending,
    Ready(Box<Fetched>),
    Failed(describe::FetchError),
}

#[derive(Clone, Debug)]
pub struct SeenSearch {
    pub at: SystemTime,
    pub src: SocketAddr,
    pub iface: String,
    pub st: String,
    pub mx: String,
    pub user_agent: String,
    pub own: bool,
    pub issues: Vec<Issue>,
}

#[derive(Clone, Debug)]
pub struct PacketEntry {
    pub packet: Packet,
    pub uuid: Option<String>,
    pub summary: String,
    pub own: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Adverts,
    Description,
    Packets,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Adverts, Tab::Description, Tab::Packets];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKey {
    Searches,
    Device(String),
}

#[derive(Clone, Debug)]
pub struct Row {
    pub key: RowKey,
    pub depth: usize,
}

pub struct App {
    rx: mpsc::Receiver<Packet>,
    search_tx: Vec<mpsc::Sender<SearchRequest>>,
    pub(crate) search_ports: Vec<u16>,
    pub(crate) local_ips: HashSet<IpAddr>,
    pub(crate) selection: Option<HashSet<String>>,
    /// Joined v4/v6 link names, refreshed every 10s for the metrics view.
    pub(crate) links: (Vec<String>, Vec<String>),
    links_at: Option<Instant>,
    pub metrics: Metrics,
    pub show_metrics: bool,
    /// Overlay scroll state; the renderer clamps and writes back.
    pub metrics_scroll: Cell<usize>,
    pub metrics_hscroll: Cell<usize>,
    pub metrics_viewport: Cell<usize>,
    fetch_tx: mpsc::Sender<FetchResult>,
    fetch_rx: mpsc::Receiver<FetchResult>,

    pub devices: BTreeMap<String, DeviceEntry>,
    pub descriptions: HashMap<String, DescState>,
    /// Ingress interface index per LOCATION, the zone for fetching
    /// link-local URLs (a URL cannot carry one; RFC 6874 is unsupported).
    scopes: HashMap<String, u32>,
    pub searches: VecDeque<SeenSearch>,
    pub packets: VecDeque<PacketEntry>,
    pub packet_total: u64,
    pub unparsed: u64,
    pub searches_sent: u64,
    /// Unicast M-SEARCH replies received on our search sockets.
    pub responses: u64,
    first_search: Option<Instant>,
    pub warnings: Vec<String>,

    pub passive: bool,
    pub mx: u8,
    pub targets: Vec<String>,
    next_search: Option<Instant>,
    burst_left: usize,
    interval: Duration,

    pub selected: RowKey,
    pub tab: Tab,
    pub scroll: u16,
    pub packet_cursor: usize,
    pub status: Option<(String, Instant)>,
    pub running: bool,
    pub start: Instant,
    headless: bool,
    /// Off in unit tests: descriptions are injected, never fetched.
    fetching: bool,
}

pub struct Options {
    pub passive: bool,
    pub selection: Option<HashSet<String>>,
    pub mx: u8,
    pub targets: Vec<String>,
    pub search_port: u16,
}

/// Silence after the startup burst that suggests replies are filtered.
const NO_REPLY_HINT_AFTER: Duration = Duration::from_secs(8);

impl App {
    pub fn new(opts: Options, headless: bool) -> Result<Self> {
        let Transport {
            rx,
            search_tx,
            search_ports,
            warnings,
        } = ssdp::spawn(opts.selection.clone(), opts.passive, opts.search_port)?;
        let (fetch_tx, fetch_rx) = mpsc::channel();
        let mut app = Self::with_channels(rx, fetch_tx, fetch_rx, opts.passive, headless);
        app.search_tx = search_tx;
        app.search_ports = search_ports;
        app.local_ips = ssdp::local_ips();
        app.selection = opts.selection;
        app.warnings = warnings;
        app.mx = opts.mx;
        app.targets = opts.targets;
        app.fetching = true;
        app.start_burst();
        Ok(app)
    }

    fn with_channels(
        rx: mpsc::Receiver<Packet>,
        fetch_tx: mpsc::Sender<FetchResult>,
        fetch_rx: mpsc::Receiver<FetchResult>,
        passive: bool,
        headless: bool,
    ) -> Self {
        Self {
            rx,
            search_tx: Vec::new(),
            search_ports: Vec::new(),
            local_ips: HashSet::new(),
            selection: None,
            links: (Vec::new(), Vec::new()),
            links_at: None,
            metrics: Metrics::default(),
            show_metrics: false,
            metrics_scroll: Cell::new(0),
            metrics_hscroll: Cell::new(0),
            metrics_viewport: Cell::new(0),
            fetch_tx,
            fetch_rx,
            devices: BTreeMap::new(),
            descriptions: HashMap::new(),
            scopes: HashMap::new(),
            searches: VecDeque::new(),
            packets: VecDeque::new(),
            packet_total: 0,
            unparsed: 0,
            searches_sent: 0,
            responses: 0,
            first_search: None,
            warnings: Vec::new(),
            passive,
            mx: 2,
            targets: vec!["ssdp:all".into()],
            next_search: None,
            burst_left: 0,
            interval: FIRST_INTERVAL,
            selected: RowKey::Searches,
            tab: Tab::Adverts,
            scroll: 0,
            packet_cursor: 0,
            status: None,
            running: true,
            start: Instant::now(),
            headless,
            fetching: false,
        }
    }

    pub fn run(&mut self, terminal: &mut Option<ui::Terminal>) -> Result<()> {
        match terminal.as_mut() {
            Some(term) => self.run_tui(term),
            None => self.run_headless(),
        }
    }

    fn tick(&mut self) {
        if self
            .links_at
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(10))
        {
            self.links_at = Some(Instant::now());
            self.links = ssdp::usable_links(self.selection.as_ref());
            self.local_ips = ssdp::local_ips();
        }
        self.drain();
        self.send_searches();
        self.evict(Instant::now());
    }

    fn run_tui(&mut self, terminal: &mut ui::Terminal) -> Result<()> {
        let mut dirty = true;
        let mut drawn_sec = None;
        while self.running {
            let before = (self.packet_total, self.descriptions.len());
            self.tick();
            dirty |= before != (self.packet_total, self.descriptions.len());
            if let Some(msg) = crate::take_log_error() {
                self.set_status(msg);
                dirty = true;
            }
            let sec = self.start.elapsed().as_secs();
            if dirty || drawn_sec != Some(sec) {
                terminal.draw(|f| ui::draw(f, self))?;
                dirty = false;
                drawn_sec = Some(sec);
            }
            if event::poll(Duration::from_millis(80))? {
                dirty = true;
                loop {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            #[cfg(unix)]
                            if key.code == KeyCode::Char('z')
                                && key.modifiers.contains(KeyModifiers::CONTROL)
                            {
                                if !ui::suspend(terminal)? {
                                    self.running = false;
                                    return Ok(());
                                }
                                break;
                            }
                            self.handle_key(&key);
                        }
                        _ => {}
                    }
                    if !event::poll(Duration::ZERO)? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn run_headless(&mut self) -> Result<()> {
        log::info!("uex: started headless");
        for w in &self.warnings {
            eprintln!("uex: {w}");
        }
        let mut hinted = false;
        while self.running {
            self.tick();
            if let Some(msg) = crate::take_log_error() {
                eprintln!("uex: {msg}");
            }
            if !hinted && self.hints().len() > self.warnings.len() {
                hinted = true;
                for h in &self.hints()[self.warnings.len()..] {
                    eprintln!("uex: {h}");
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Discovery event line: stdout when headless, log otherwise.
    fn note(&self, line: String) {
        if self.headless {
            println!("{} {line}", chrono::Local::now().format("%H:%M:%S"));
        } else {
            log::info!("uex: {line}");
        }
    }

    /// Startup warnings plus live diagnostics for the header.
    pub fn hints(&self) -> Vec<String> {
        let mut out = self.warnings.clone();
        if self.responses == 0
            && self
                .first_search
                .is_some_and(|t| t.elapsed() >= NO_REPLY_HINT_AFTER)
        {
            out.push(
                "no M-SEARCH replies: a host firewall may drop them; \
                 allow UDP port 1900 (or the --search-port in use)"
                    .into(),
            );
        }
        out
    }

    pub fn set_status(&mut self, msg: String) {
        self.status = Some((msg, Instant::now()));
    }

    pub fn status_text(&self) -> Option<&str> {
        self.status
            .as_ref()
            .filter(|(_, t)| t.elapsed() < Duration::from_secs(4))
            .map(|(m, _)| m.as_str())
    }

    // ---- searching -------------------------------------------------

    fn start_burst(&mut self) {
        if self.passive {
            return;
        }
        self.next_search = Some(Instant::now() + rand_range(20, 120));
        self.burst_left = BURST_GAPS.len() + 1;
        self.interval = FIRST_INTERVAL;
    }

    /// Current rescan interval (the gap after the next search).
    pub fn search_interval(&self) -> Duration {
        self.interval
    }

    pub fn next_search_in(&self) -> Option<Duration> {
        self.next_search
            .map(|t| t.saturating_duration_since(Instant::now()))
    }

    fn send_searches(&mut self) {
        let Some(due) = self.next_search else { return };
        let now = Instant::now();
        if now < due {
            return;
        }
        for st in &self.targets {
            let req = SearchRequest {
                st: st.clone(),
                mx: self.mx,
            };
            for tx in &self.search_tx {
                let _ = tx.send(req.clone());
            }
        }
        self.searches_sent += 1;
        self.first_search.get_or_insert(now);
        self.burst_left = self.burst_left.saturating_sub(1);
        let gap = if self.burst_left > 0 {
            BURST_GAPS[BURST_GAPS.len() - self.burst_left]
        } else {
            // 0-2% jitter keeps several instances from synchronizing.
            let jitter = self.interval.as_millis() as u64 * (rand_u32() as u64 % 3) / 100;
            let gap = self.interval + Duration::from_millis(jitter);
            self.interval = (self.interval * 2).min(MAX_INTERVAL);
            gap
        };
        self.next_search = Some(now + gap);
    }

    // ---- ingest ----------------------------------------------------

    fn drain(&mut self) {
        while let Ok(p) = self.rx.try_recv() {
            self.ingest(p);
        }
        while let Ok((location, res)) = self.fetch_rx.try_recv() {
            self.on_fetched(location, res);
        }
    }

    fn on_fetched(&mut self, location: String, res: Result<Fetched, describe::FetchError>) {
        // Dropped meanwhile (all adverts expired): don't resurrect.
        if !self.descriptions.contains_key(&location) {
            return;
        }
        match res {
            Ok(f) => {
                let ms = f.elapsed.as_millis() as u64;
                self.metrics.fetch_ok += 1;
                self.metrics.fetch_bytes += f.bytes as u64;
                self.metrics.fetch_ms_total += ms;
                self.metrics.fetch_ms_max = self.metrics.fetch_ms_max.max(ms);
                self.note(format!(
                    "= {} \"{}\" ({})",
                    f.description.root.udn, f.description.root.friendly_name, location
                ));
                self.descriptions
                    .insert(location, DescState::Ready(Box::new(f)));
            }
            Err(e) => {
                self.metrics.fetch_failed += 1;
                self.descriptions.insert(location, DescState::Failed(e));
            }
        }
    }

    fn request_description(&mut self, location: &str, force: bool) {
        if !force && self.descriptions.contains_key(location) {
            return;
        }
        if matches!(self.descriptions.get(location), Some(DescState::Pending)) {
            return;
        }
        log::debug!("uex: fetch {location} (force={force})");
        self.descriptions
            .insert(location.to_string(), DescState::Pending);
        self.metrics.fetch_started += 1;
        if url::Url::parse(location)
            .ok()
            .and_then(|u| describe::link_local_host(&u))
            .is_some()
        {
            self.metrics.fetch_link_local += 1;
        }
        if self.fetching {
            let scope = self.scopes.get(location).copied().unwrap_or(0);
            describe::spawn_fetch(location.to_string(), scope, self.fetch_tx.clone());
        }
    }

    fn is_own(&self, p: &Packet) -> bool {
        self.search_ports.contains(&p.src.port()) && self.local_ips.contains(&p.src.ip())
    }

    pub fn ingest(&mut self, p: Packet) {
        self.packet_total += 1;
        // By message kind, not socket: with the default search port the
        // replies arrive on the shared port-1900 listener.
        if matches!(&p.msg, Some(m) if m.kind == Kind::Response) {
            self.responses += 1;
        }
        let own = matches!(&p.msg, Some(m) if m.kind == Kind::Search) && self.is_own(&p);
        self.metrics.on_packet(&p, own);
        let (summary, uuid) = match &p.msg {
            None => {
                self.unparsed += 1;
                (format!("(unparsed, {} bytes)", p.raw.len()), None)
            }
            Some(m) => {
                let uuid = m.header("USN").and_then(usn_uuid);
                (packet_summary(m), uuid)
            }
        };
        if let Some(m) = p.msg.clone() {
            match m.kind {
                Kind::Search => self.on_search(&p, &m, own),
                Kind::Notify | Kind::Response => self.on_advert(&p, &m),
            }
        }
        self.packets.push_back(PacketEntry {
            packet: p,
            uuid,
            summary,
            own,
        });
        while self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
        }
    }

    fn on_search(&mut self, p: &Packet, m: &Message, own: bool) {
        let issues = search_issues(m, p.dst.is_multicast());
        self.searches.push_back(SeenSearch {
            at: p.at,
            src: p.src,
            iface: p.iface.clone(),
            st: m.header("ST").unwrap_or("").to_string(),
            mx: m.header("MX").unwrap_or("").to_string(),
            user_agent: m.header("USER-AGENT").unwrap_or("").to_string(),
            own,
            issues,
        });
        while self.searches.len() > MAX_SEARCHES {
            self.searches.pop_front();
        }
    }

    fn on_advert(&mut self, p: &Packet, m: &Message) {
        let Some(usn) = m.header("USN") else { return };
        let Some(uuid) = usn_uuid(usn) else { return };
        let nts = m.header("NTS").unwrap_or("").to_ascii_lowercase();
        let via = if m.kind == Kind::Notify {
            AdvertVia::Notify
        } else {
            AdvertVia::Response
        };
        let target = match via {
            AdvertVia::Notify => m.header("NT"),
            AdvertVia::Response => m.header("ST"),
        }
        .unwrap_or("")
        .to_string();
        let now = p.received;
        let mut issues = advert_issues(m, &p.src);
        let key = usn.to_ascii_lowercase();
        let new_device = !self.devices.contains_key(&uuid);
        let dev = self
            .devices
            .entry(uuid.clone())
            .or_insert_with(|| DeviceEntry {
                uuid: uuid.clone(),
                adverts: BTreeMap::new(),
                first_seen: now,
            });

        if nts == "ssdp:byebye" {
            match dev.adverts.get_mut(&key) {
                Some(a) => {
                    a.gone = Some(now);
                    a.count += 1;
                }
                None => {
                    issues.push(Issue::info("byebye for an advert never seen alive"));
                    dev.adverts.insert(
                        key,
                        Advert {
                            target,
                            location: None,
                            locations: Vec::new(),
                            server: None,
                            max_age: None,
                            refreshed: now,
                            first_seen: now,
                            src: p.src,
                            iface: p.iface.clone(),
                            via,
                            boot_id: m.header("BOOTID.UPNP.ORG").map(str::to_string),
                            config_id: m.header("CONFIGID.UPNP.ORG").map(str::to_string),
                            count: 1,
                            issues,
                            gone: Some(now),
                        },
                    );
                }
            }
            let all_gone = !dev.live();
            if all_gone {
                self.metrics.devices_byebye_total += 1;
                self.note(format!("- uuid:{uuid} byebye"));
            }
            return;
        }

        let boot_id = m.header("BOOTID.UPNP.ORG").map(str::to_string);
        let config_id = m.header("CONFIGID.UPNP.ORG").map(str::to_string);
        let location = m.header("LOCATION").map(str::to_string);
        let mut refetch = false;
        match dev.adverts.get_mut(&key) {
            Some(a) => {
                if nts == "ssdp:update" {
                    // ssdp:update carries the next BOOTID; keep timers.
                    if let Some(next) = m.header("NEXTBOOTID.UPNP.ORG") {
                        a.boot_id = Some(next.to_string());
                    }
                } else {
                    if boot_id.is_some() && a.boot_id.is_some() && boot_id != a.boot_id {
                        issues.push(Issue::warning(format!(
                            "BOOTID changed {} → {} without ssdp:update",
                            a.boot_id.as_deref().unwrap_or(""),
                            boot_id.as_deref().unwrap_or("")
                        )));
                    }
                    a.boot_id = boot_id.or(a.boot_id.take());
                    a.refreshed = now;
                    a.max_age = m
                        .header("CACHE-CONTROL")
                        .and_then(parse_max_age)
                        .or(a.max_age);
                }
                if config_id.is_some() && config_id != a.config_id {
                    refetch = a.config_id.is_some();
                    a.config_id = config_id;
                }
                // A new LOCATION is fetched once (not forced): multi-homed
                // devices alternate v4/v6 LOCATION URLs for the same USN.
                if let Some(l) = location {
                    if !a.locations.contains(&l) {
                        a.locations.push(l.clone());
                    }
                    a.location = Some(l);
                }
                if let Some(s) = m.header("SERVER") {
                    a.server = Some(s.to_string());
                }
                a.target = target;
                a.src = p.src;
                a.iface = p.iface.clone();
                a.via = via;
                a.count += 1;
                a.gone = None;
                a.issues = issues;
            }
            None => {
                dev.adverts.insert(
                    key.clone(),
                    Advert {
                        target,
                        locations: location.iter().cloned().collect(),
                        location,
                        server: m.header("SERVER").map(str::to_string),
                        max_age: m.header("CACHE-CONTROL").and_then(parse_max_age),
                        refreshed: now,
                        first_seen: now,
                        src: p.src,
                        iface: p.iface.clone(),
                        via,
                        boot_id,
                        config_id,
                        count: 1,
                        issues,
                        gone: None,
                    },
                );
            }
        }
        let loc = dev.adverts.get(&key).and_then(|a| a.location.clone());
        if new_device {
            self.metrics.devices_seen_total += 1;
            self.note(format!(
                "+ uuid:{uuid} {} {}",
                loc.as_deref().unwrap_or("-"),
                m.header("SERVER").unwrap_or("")
            ));
        }
        if let Some(loc) = loc {
            if describe::check_location(&loc).is_ok() {
                self.scopes.insert(loc.clone(), p.ifindex);
                self.request_description(&loc, refetch);
            }
        }
    }

    /// Expire adverts at 100% of max-age, drop byebye'd ones after a
    /// short linger, prune empty devices and unreferenced descriptions.
    pub fn evict(&mut self, now: Instant) {
        let mut expired = Vec::new();
        for dev in self.devices.values_mut() {
            dev.adverts.retain(|_, a| match a.gone {
                Some(t) => now.saturating_duration_since(t) < BYEBYE_LINGER,
                None => now.saturating_duration_since(a.refreshed) < a.lifetime(),
            });
            if dev.adverts.is_empty() {
                expired.push(dev.uuid.clone());
            }
        }
        for uuid in expired {
            self.devices.remove(&uuid);
            self.metrics.devices_expired_total += 1;
            self.note(format!("x uuid:{uuid} expired"));
        }
        let referenced: HashSet<&str> = self
            .devices
            .values()
            .flat_map(|d| d.adverts.values())
            .flat_map(|a| a.locations.iter().map(String::as_str))
            .collect();
        self.scopes
            .retain(|loc, _| referenced.contains(loc.as_str()));
        self.descriptions.retain(|loc, _| {
            let keep = referenced.contains(loc.as_str());
            if !keep {
                log::debug!("uex: drop description {loc}");
            }
            keep
        });
    }

    // ---- derived views ----------------------------------------------

    /// The described device for a UUID, from any of its adverts'
    /// LOCATION URLs (embedded devices usually point at the root's).
    pub fn described(&self, uuid: &str) -> Option<(&str, &Fetched, &describe::Device)> {
        let dev = self.devices.get(uuid)?;
        let udn = format!("uuid:{uuid}");
        dev.adverts
            .values()
            .flat_map(|a| a.locations.iter().map(String::as_str))
            .find_map(|loc| match self.descriptions.get(loc) {
                Some(DescState::Ready(f)) => {
                    f.description.root.find(&udn).map(|d| (loc, f.as_ref(), d))
                }
                _ => None,
            })
    }

    /// Description states for a device's distinct LOCATION URLs.
    pub fn description_states(&self, uuid: &str) -> Vec<(&str, &DescState)> {
        let Some(dev) = self.devices.get(uuid) else {
            return Vec::new();
        };
        let mut seen = HashSet::new();
        dev.adverts
            .values()
            .flat_map(|a| a.locations.iter().map(String::as_str))
            .filter(|l| seen.insert(*l))
            .filter_map(|l| self.descriptions.get(l).map(|s| (l, s)))
            .collect()
    }

    pub fn display_name(&self, uuid: &str) -> String {
        if let Some((_, _, d)) = self.described(uuid) {
            if !d.friendly_name.is_empty() {
                return d.friendly_name.clone();
            }
        }
        self.devices
            .get(uuid)
            .and_then(|d| d.adverts.values().find_map(|a| a.server.clone()))
            .unwrap_or_else(|| format!("uuid:{uuid}"))
    }

    /// Advert issues plus description-level findings, deduplicated and
    /// sorted worst first.
    pub fn device_issues(&self, uuid: &str) -> Vec<Issue> {
        let mut out: Vec<Issue> = Vec::new();
        let Some(dev) = self.devices.get(uuid) else {
            return out;
        };
        let mut push = |i: Issue| {
            if !out.contains(&i) {
                out.push(i);
            }
        };
        for a in dev.adverts.values() {
            for i in &a.issues {
                push(i.clone());
            }
        }
        let udn = format!("uuid:{uuid}");
        let states = self.description_states(uuid);
        // Multi-homed devices also advertise link-local v6 URLs that
        // cannot be fetched without a zone: only a total failure counts.
        let any_ready = states
            .iter()
            .any(|(_, st)| matches!(st, DescState::Ready(_)));
        for (loc, st) in states {
            match st {
                DescState::Failed(e) if !any_ready => {
                    push(Issue::error(format!("description {loc}: {e}")))
                }
                DescState::Ready(f) if f.description.root.find(&udn).is_none() => push(
                    Issue::error(format!("{udn} not found in description {loc}")),
                ),
                _ => {}
            }
        }
        out.sort_by_key(|i| i.severity);
        out
    }

    /// Device rows as a tree: embedded devices under their parent when
    /// the parent's description lists them and the parent is present.
    pub fn rows(&self) -> Vec<Row> {
        let mut parent: HashMap<String, String> = HashMap::new();
        for st in self.descriptions.values() {
            if let DescState::Ready(f) = st {
                f.description.root.walk(None, &mut |d, p| {
                    if let (Some(c), Some(p)) = (usn_uuid(&d.udn), p.and_then(usn_uuid)) {
                        if c != p {
                            parent.entry(c).or_insert(p);
                        }
                    }
                });
            }
        }
        let names: HashMap<&str, String> = self
            .devices
            .keys()
            .map(|u| (u.as_str(), self.display_name(u).to_lowercase()))
            .collect();
        let mut children: BTreeMap<Option<&str>, Vec<&str>> = BTreeMap::new();
        for uuid in self.devices.keys() {
            let p = parent
                .get(uuid)
                .map(String::as_str)
                .filter(|p| self.devices.contains_key(*p));
            children.entry(p).or_default().push(uuid);
        }
        for list in children.values_mut() {
            list.sort_by(|a, b| names[a].cmp(&names[b]).then(a.cmp(b)));
        }
        let mut rows = vec![Row {
            key: RowKey::Searches,
            depth: 0,
        }];
        let mut visited = HashSet::new();
        fn visit<'a>(
            node: Option<&'a str>,
            depth: usize,
            children: &BTreeMap<Option<&'a str>, Vec<&'a str>>,
            visited: &mut HashSet<&'a str>,
            rows: &mut Vec<Row>,
        ) {
            for c in children.get(&node).into_iter().flatten() {
                if visited.insert(c) {
                    rows.push(Row {
                        key: RowKey::Device(c.to_string()),
                        depth,
                    });
                    visit(Some(c), depth + 1, children, visited, rows);
                }
            }
        }
        visit(None, 0, &children, &mut visited, &mut rows);
        // Parent cycles (bogus descriptions) leave nodes unreached.
        for uuid in self.devices.keys() {
            if visited.insert(uuid) {
                rows.push(Row {
                    key: RowKey::Device(uuid.clone()),
                    depth: 0,
                });
            }
        }
        rows
    }

    pub fn selected_index(&self, rows: &[Row]) -> usize {
        rows.iter()
            .position(|r| r.key == self.selected)
            .unwrap_or(0)
    }

    /// Packets for the current selection, newest first.
    pub fn visible_packets(&self) -> Vec<&PacketEntry> {
        self.packets
            .iter()
            .rev()
            .filter(|e| match &self.selected {
                RowKey::Searches => matches!(&e.packet.msg, Some(m) if m.kind == Kind::Search),
                RowKey::Device(u) => e.uuid.as_deref() == Some(u.as_str()),
            })
            .collect()
    }

    // ---- input -----------------------------------------------------

    fn move_selection(&mut self, delta: isize) {
        let rows = self.rows();
        let cur = self.selected_index(&rows) as isize;
        let next = (cur + delta).clamp(0, rows.len() as isize - 1) as usize;
        self.select(rows[next].key.clone());
    }

    fn select(&mut self, key: RowKey) {
        if key != self.selected {
            self.selected = key;
            self.scroll = 0;
            self.packet_cursor = 0;
        }
    }

    fn scroll_by(&mut self, delta: isize) {
        if self.tab == Tab::Packets {
            let max = self.visible_packets().len().saturating_sub(1) as isize;
            self.packet_cursor = (self.packet_cursor as isize + delta).clamp(0, max) as usize;
        } else {
            self.scroll = (self.scroll as isize + delta).clamp(0, u16::MAX as isize) as u16;
        }
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.scroll = 0;
    }

    fn scroll_metrics(&self, delta: isize) {
        let v = self.metrics_scroll.get() as isize + delta;
        self.metrics_scroll.set(v.max(0) as usize);
    }

    fn pan_metrics(&self, delta: isize) {
        let v = self.metrics_hscroll.get() as isize + delta;
        self.metrics_hscroll.set(v.max(0) as usize);
    }

    /// While open the overlay owns every key except Ctrl+C/Ctrl+Z:
    /// `m`/`Esc` close, `q` quits, the rest scrolls (as in mex).
    fn handle_metrics_key(&mut self, key: &KeyEvent) {
        let page = self.metrics_viewport.get().max(1) as isize;
        let step = if key.modifiers.contains(KeyModifiers::CONTROL) {
            10
        } else {
            1
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('m') | KeyCode::Char('M') => self.show_metrics = false,
            KeyCode::Char('q') => self.running = false,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => self.scroll_metrics(-1),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => self.scroll_metrics(1),
            KeyCode::PageUp | KeyCode::Char('b') => self.scroll_metrics(-page),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll_metrics(page),
            KeyCode::Home | KeyCode::Char('g') => self.metrics_scroll.set(0),
            KeyCode::End | KeyCode::Char('G') => self.metrics_scroll.set(usize::MAX / 2),
            KeyCode::Left | KeyCode::Char('h') => self.pan_metrics(-step),
            KeyCode::Right | KeyCode::Char('l') => self.pan_metrics(step),
            KeyCode::Char('0') => self.metrics_hscroll.set(0),
            _ => {}
        }
    }

    pub fn handle_key(&mut self, key: &KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }
        if self.show_metrics {
            self.handle_metrics_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('m') | KeyCode::Char('M') => {
                self.show_metrics = true;
                self.metrics_scroll.set(0);
                self.metrics_hscroll.set(0);
            }
            KeyCode::Char('c') if ctrl => self.running = false,
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX / 2),
            KeyCode::Char('J') => self.scroll_by(1),
            KeyCode::Char('K') => self.scroll_by(-1),
            KeyCode::PageDown => self.scroll_by(10),
            KeyCode::PageUp => self.scroll_by(-10),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.set_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()])
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.set_tab(Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()])
            }
            KeyCode::Char('1') => self.set_tab(Tab::Adverts),
            KeyCode::Char('2') => self.set_tab(Tab::Description),
            KeyCode::Char('3') => self.set_tab(Tab::Packets),
            KeyCode::Char('r') => {
                if self.passive {
                    self.set_status("passive mode: no searches".into());
                } else {
                    self.start_burst();
                    self.set_status("rescanning".into());
                }
            }
            KeyCode::Char('f') => {
                if let RowKey::Device(uuid) = &self.selected {
                    let locs: Vec<String> = self
                        .description_states(uuid)
                        .into_iter()
                        .map(|(l, _)| l.to_string())
                        .collect();
                    for l in &locs {
                        self.request_description(l, true);
                    }
                    self.set_status(format!("refetching {} description(s)", locs.len()));
                }
            }
            KeyCode::Char('c') => {
                self.packets.clear();
                self.searches.clear();
                self.packet_cursor = 0;
                self.set_status("packet log cleared".into());
            }
            _ => {}
        }
    }
}

fn packet_summary(m: &Message) -> String {
    match m.kind {
        Kind::Notify => format!(
            "NOTIFY {} {}",
            m.header("NTS").unwrap_or("?"),
            short_type(m.header("NT").unwrap_or("?"))
        ),
        Kind::Response => format!(
            "{} {}",
            m.status().map_or("???".into(), |s| s.to_string()),
            short_type(m.header("ST").unwrap_or("?"))
        ),
        Kind::Search => format!(
            "M-SEARCH {} MX={}",
            short_type(m.header("ST").unwrap_or("?")),
            m.header("MX").unwrap_or("-")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssdp::Via;

    fn test_app() -> (App, mpsc::Sender<Packet>) {
        let (tx, rx) = mpsc::channel();
        let (ftx, frx) = mpsc::channel();
        (App::with_channels(rx, ftx, frx, true, false), tx)
    }

    fn packet(text: &str, src: &str) -> Packet {
        Packet {
            at: SystemTime::now(),
            received: Instant::now(),
            src: src.parse().unwrap(),
            dst: "239.255.255.250".parse().unwrap(),
            iface: "eth0".into(),
            ifindex: 0,
            via: Via::Listener,
            raw: text.as_bytes().to_vec(),
            msg: ssdp::parse(text.as_bytes()),
        }
    }

    fn alive(uuid: &str, nt: &str, max_age: u32) -> String {
        let usn = if nt.starts_with("uuid:") {
            nt.to_string()
        } else {
            format!("uuid:{uuid}::{nt}")
        };
        format!(
            "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
             CACHE-CONTROL: max-age={max_age}\r\n\
             LOCATION: ftp://10.0.0.2/d.xml\r\nNT: {nt}\r\nNTS: ssdp:alive\r\n\
             SERVER: Linux/5 UPnP/1.0 test/1\r\nUSN: {usn}\r\n\r\n"
        )
    }

    #[test]
    fn usn_and_max_age_helpers() {
        assert_eq!(
            usn_uuid("uuid:ABC::upnp:rootdevice").as_deref(),
            Some("abc")
        );
        assert_eq!(usn_uuid("UUID:x").as_deref(), Some("x"));
        assert_eq!(usn_uuid("abc"), None);
        assert_eq!(usn_uuid("uuid:"), None);
        assert_eq!(parse_max_age("max-age=1800"), Some(1800));
        assert_eq!(parse_max_age("no-cache, MAX-AGE = \"60\""), Some(60));
        assert_eq!(parse_max_age("no-cache"), None);
    }

    #[test]
    fn alive_then_byebye_then_linger_eviction() {
        let (mut app, _tx) = test_app();
        app.ingest(packet(
            &alive("d1", "upnp:rootdevice", 1800),
            "10.0.0.2:1900",
        ));
        app.ingest(packet(&alive("d1", "uuid:d1", 1800), "10.0.0.2:1900"));
        let dev = &app.devices["d1"];
        assert_eq!(dev.adverts.len(), 2);
        assert!(dev.live());

        let bye = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: uuid:d1\r\n\
                   NTS: ssdp:byebye\r\nUSN: uuid:d1\r\n\r\n";
        app.ingest(packet(bye, "10.0.0.2:1900"));
        let dev = &app.devices["d1"];
        assert_eq!(dev.adverts.values().filter(|a| a.gone.is_some()).count(), 1);
        assert!(dev.live());

        let later = Instant::now() + BYEBYE_LINGER + Duration::from_secs(1);
        app.evict(later);
        assert_eq!(app.devices["d1"].adverts.len(), 1);
    }

    #[test]
    fn alternating_locations_do_not_force_refetch() {
        let (mut app, _tx) = test_app();
        let v4 =
            alive("m", "uuid:m", 1800).replace("ftp://10.0.0.2/d.xml", "http://10.0.0.2/d.xml");
        let v6 = v4.replace("http://10.0.0.2/d.xml", "http://[fe80::2]/d.xml");
        app.ingest(packet(&v4, "10.0.0.2:1900"));
        app.ingest(packet(&v6, "[fe80::2]:1900"));
        app.on_fetched("http://10.0.0.2/d.xml".into(), Err("x".into()));
        app.ingest(packet(&v4, "10.0.0.2:1900"));
        // Settled result kept, not reset to Pending by the flip back.
        assert!(matches!(
            app.descriptions.get("http://10.0.0.2/d.xml"),
            Some(DescState::Failed(_))
        ));
        assert_eq!(app.device_issues("m").len(), 1);
        let xml = "<root><device><UDN>uuid:m</UDN></device></root>";
        let ok = Fetched {
            description: describe::parse(xml).unwrap(),
            server: None,
            content_type: None,
            bytes: xml.len(),
            elapsed: Duration::ZERO,
        };
        app.on_fetched("http://[fe80::2]/d.xml".into(), Ok(ok));
        // One working LOCATION hides the other's failure.
        assert!(
            app.device_issues("m").is_empty(),
            "{:?}",
            app.device_issues("m")
        );
    }

    #[test]
    fn adverts_expire_at_max_age() {
        let (mut app, _tx) = test_app();
        app.ingest(packet(
            &alive("d2", "upnp:rootdevice", 100),
            "10.0.0.2:1900",
        ));
        app.evict(Instant::now() + Duration::from_secs(99));
        assert!(app.devices.contains_key("d2"));
        app.evict(Instant::now() + Duration::from_secs(101));
        assert!(!app.devices.contains_key("d2"));
    }

    #[test]
    fn own_search_is_flagged_and_listed() {
        let (mut app, _tx) = test_app();
        app.search_ports = vec![40000];
        app.local_ips.insert("10.0.0.5".parse().unwrap());
        let s = ssdp::encode_search(
            &SearchRequest {
                st: "ssdp:all".into(),
                mx: 2,
            },
            ssdp::Family::V4,
        );
        app.ingest(packet(&s, "10.0.0.5:40000"));
        app.ingest(packet(&s, "10.0.0.6:40000"));
        assert!(app.searches[0].own);
        assert!(!app.searches[1].own);
        assert!(
            app.searches[1].issues.is_empty(),
            "{:?}",
            app.searches[1].issues
        );
        assert_eq!(app.visible_packets().len(), 2);
    }

    #[test]
    fn rows_nest_embedded_devices() {
        let (mut app, _tx) = test_app();
        for (u, loc) in [("root", "http://h/d.xml"), ("wan", "http://h/d.xml")] {
            let text = alive(u, &format!("uuid:{u}"), 1800).replace("ftp://10.0.0.2/d.xml", loc);
            app.ingest(packet(&text, "10.0.0.2:1900"));
        }
        let xml = "<root><device><friendlyName>R</friendlyName><UDN>uuid:root</UDN>\
                   <deviceList><device><friendlyName>W</friendlyName><UDN>uuid:wan</UDN>\
                   </device></deviceList></device></root>";
        let fetched = Fetched {
            description: describe::parse(xml).unwrap(),
            server: None,
            content_type: None,
            bytes: xml.len(),
            elapsed: Duration::ZERO,
        };
        app.on_fetched("http://h/d.xml".into(), Ok(fetched));
        let rows = app.rows();
        let keys: Vec<(RowKey, usize)> = rows.into_iter().map(|r| (r.key, r.depth)).collect();
        assert_eq!(
            keys,
            vec![
                (RowKey::Searches, 0),
                (RowKey::Device("root".into()), 0),
                (RowKey::Device("wan".into()), 1),
            ]
        );
        assert_eq!(app.display_name("wan"), "W");
        assert!(app.device_issues("wan").is_empty());
    }
}

#[cfg(test)]
mod render_tests {
    use super::tests_support::*;
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn every_tab_renders_without_panic() {
        let mut app = populated_app();
        for (w, h) in [(160, 40), (60, 12), (20, 6)] {
            let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
            for key in app.rows().into_iter().map(|r| r.key) {
                app.selected = key;
                for tab in Tab::ALL {
                    app.tab = tab;
                    term.draw(|f| ui::draw(f, &app)).unwrap();
                }
            }
        }
        let mut term = ratatui::Terminal::new(TestBackend::new(160, 40)).unwrap();
        app.selected = RowKey::Device("root".into());
        app.tab = Tab::Description;
        term.draw(|f| ui::draw(f, &app)).unwrap();
        let screen: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(screen.contains("InternetGatewayDevice"), "{screen}");
        assert!(screen.contains("http://h/ctl"));
    }

    #[test]
    fn metrics_overlay_lists_sections_and_findings() {
        let mut app = populated_app();
        let rows = app.metrics_rows();
        let keys: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
        for s in [
            "Session",
            "Traffic",
            "Discovery",
            "Descriptions",
            "Searching",
            "Control points",
            "Links",
            "Issues",
        ] {
            assert!(keys.contains(&s), "missing section {s}: {keys:?}");
        }
        let summary = &rows.iter().find(|(k, _)| k == "summary").unwrap().1;
        // max-age=60 warnings on the devices, MX=9 + unquoted MAN on the
        // control point; the garbage packet is counted, not a finding.
        assert!(summary.contains("warnings"), "{summary}");
        assert!(app
            .findings()
            .iter()
            .any(|f| f.scope.starts_with("control point 10.0.0.7")));
        assert_eq!(app.metrics.searches_foreign, 1);
        assert_eq!(app.metrics.notify_alive, 3);
        assert_eq!(app.metrics.devices_seen_total, 2);

        app.handle_key(&KeyEvent::from(KeyCode::Char('m')));
        assert!(app.show_metrics);
        // Overlay swallows navigation keys; scrolling clamps on render.
        app.handle_key(&KeyEvent::from(KeyCode::End));
        let mut term = ratatui::Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| ui::draw(f, &app)).unwrap();
        let max = rows.len().saturating_sub(app.metrics_viewport.get());
        assert_eq!(app.metrics_scroll.get(), max);
        app.handle_key(&KeyEvent::from(KeyCode::Esc));
        assert!(!app.show_metrics);
        assert!(app.running);
        for (w, h) in [(160, 40), (40, 8), (12, 4)] {
            app.show_metrics = true;
            let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| ui::draw(f, &app)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;
    use crate::ssdp::Via;

    pub fn populated_app() -> App {
        let (_tx, rx) = mpsc::channel();
        let (ftx, frx) = mpsc::channel();
        let mut app = App::with_channels(rx, ftx, frx, false, false);
        let mk = |text: String, src: &str| Packet {
            at: SystemTime::now(),
            received: Instant::now(),
            src: src.parse().unwrap(),
            dst: "239.255.255.250".parse().unwrap(),
            iface: "eth0".into(),
            ifindex: 0,
            via: Via::Listener,
            msg: ssdp::parse(text.as_bytes()),
            raw: text.into_bytes(),
        };
        for (u, nt) in [
            ("root", "upnp:rootdevice"),
            ("root", "uuid:root"),
            ("wan", "uuid:wan"),
        ] {
            let usn = if nt.starts_with("uuid:") {
                nt.to_string()
            } else {
                format!("uuid:{u}::{nt}")
            };
            app.ingest(mk(
                format!(
                    "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=60\r\n\
                     LOCATION: http://h/d.xml\r\nNT: {nt}\r\nNTS: ssdp:alive\r\nSERVER: x\r\nUSN: {usn}\r\n\r\n"
                ),
                "[fe80::1]:1900",
            ));
        }
        app.ingest(mk(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ssdp:discover\r\nMX: 9\r\nST: ssdp:all\r\n\r\n".into(),
            "10.0.0.7:5000",
        ));
        app.ingest(mk("garbage".into(), "10.0.0.8:1"));
        let xml = "<root><specVersion><major>1</major><minor>0</minor></specVersion><device>\
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
            <friendlyName>R</friendlyName><UDN>uuid:root</UDN>\
            <iconList><icon><url>/i.png</url></icon></iconList>\
            <serviceList><service><serviceType>t</serviceType><controlURL>/ctl</controlURL></service></serviceList>\
            <deviceList><device><friendlyName>W</friendlyName><UDN>uuid:wan</UDN></device></deviceList>\
            </device></root>";
        let f = Fetched {
            description: describe::parse(xml).unwrap(),
            server: Some("srv".into()),
            content_type: Some("text/xml".into()),
            bytes: xml.len(),
            elapsed: Duration::from_millis(3),
        };
        app.on_fetched("http://h/d.xml".into(), Ok(f));
        app.warnings.push("test warning".into());
        app
    }
}
