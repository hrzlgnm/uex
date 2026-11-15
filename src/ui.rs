// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! ratatui rendering only: reads `App`, never mutates it.

use std::io;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    Tabs, Wrap,
};
use ratatui::Frame;

use crate::app::{short_type, source_label, AdvertVia, App, DescState, RowKey, Tab};
use crate::describe::{self, Device};
use crate::issues::{worst_mark, Issue, Severity};

pub type Terminal = ratatui::Terminal<CrosstermBackend<io::Stdout>>;

pub fn try_init() -> io::Result<Option<Terminal>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(None);
    }
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout)).map(Some)
}

pub fn try_restore(initialized: bool) -> io::Result<()> {
    if !initialized {
        return Ok(());
    }
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Leave the terminal, stop the foreground job, re-enter on resume.
/// Raw mode delivers Ctrl+Z as a key, so SIGTSTP never fires.
#[cfg(unix)]
pub fn suspend(term: &mut Terminal) -> io::Result<bool> {
    use nix::unistd::{getpgrp, getsid, Pid};
    let _ = term.show_cursor();
    try_restore(true)?;
    let group = getpgrp();
    // Stop the whole job unless we share the shell's group (then only
    // ourselves, or the shell would freeze with nobody left to `fg`).
    let target = match getsid(None) {
        Ok(sid) if sid != group => Pid::from_raw(-group.as_raw()),
        _ => Pid::this(),
    };
    if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGSTOP) {
        eprintln!("uex: failed to suspend: {e}");
    }
    let Some(restored) = try_init()? else {
        return Ok(false);
    };
    *term = restored;
    term.clear()?;
    Ok(true)
}

const DIM: Style = Style::new().fg(Color::DarkGray);
const KEY: Style = Style::new().fg(Color::Cyan);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red);
const INFO: Style = Style::new().fg(Color::Blue);

fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Error => BAD,
        Severity::Warning => WARN,
        Severity::Info => INFO,
    }
}

/// `!` in the worst marking severity's color, or nothing.
fn mark_span(issues: &[Issue]) -> Span<'static> {
    match worst_mark(issues) {
        Some(s) => Span::styled("!", severity_style(s)),
        None => Span::raw(""),
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(frame.area());
    draw_header(frame, chunks[0], app);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(chunks[1]);
    draw_device_list(frame, body[0], app);
    draw_detail(frame, body[1], app);
    if app.show_metrics {
        draw_metrics_overlay(frame, app);
    }
    if let Some(text) = app.status_text() {
        draw_popup(frame, text);
    }
}

fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let w = area.width * pct_x / 100;
    let h = area.height * pct_y / 100;
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Metrics overlay (`m`), laid out like mex's: frozen key column sized
/// to the longest key, values pan horizontally, rows scroll.
fn draw_metrics_overlay(frame: &mut Frame, app: &App) {
    let area = centered_rect(85, 85, frame.area());
    frame.render_widget(Clear, area);
    let rows = app.metrics_rows();
    let viewport = (area.height as usize).saturating_sub(4);
    app.metrics_viewport.set(viewport);
    let max_offset = rows.len().saturating_sub(viewport);
    let offset = app.metrics_scroll.get().min(max_offset);
    app.metrics_scroll.set(offset);

    let key_cap = area.width.saturating_sub(12).clamp(10, 40) as usize;
    let key_w = rows
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, _)| k.chars().count() + 2)
        .max()
        .unwrap_or(10)
        .clamp(10, 40)
        .min(key_cap) as u16;
    let value_w = (area.width as usize).saturating_sub(key_w as usize + 5);
    let longest = rows
        .iter()
        .map(|(_, v)| v.chars().count())
        .max()
        .unwrap_or(0);
    let hscroll = app
        .metrics_hscroll
        .get()
        .min(longest.saturating_sub(value_w.max(1)));
    app.metrics_hscroll.set(hscroll);

    let section = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let body: Vec<Row> = rows
        .into_iter()
        .map(|(k, v)| {
            if v.is_empty() {
                return Row::new(vec![Cell::from(k).style(section), Cell::from("")]);
            }
            let key_style = match k.chars().next() {
                Some(c) if c == Severity::Error.icon() => BAD,
                Some(c) if c == Severity::Warning.icon() => WARN,
                Some(c) if c == Severity::Info.icon() => INFO,
                _ => Style::new().fg(Color::Gray),
            };
            let shifted: String = v.chars().skip(hscroll).collect();
            Row::new(vec![
                Cell::from(format!(" {k}")).style(key_style),
                Cell::from(shifted),
            ])
        })
        .collect();
    let table = Table::new(body, [Constraint::Length(key_w), Constraint::Min(0)])
        .header(Row::new(["METRIC", "VALUE"]).style(section))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Metrics (m/Esc close · j/k ↕ · h/l ↔) "),
        );
    let mut state = TableState::default().with_offset(offset);
    frame.render_stateful_widget(table, area, &mut state);
}

fn fmt_secs(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let adverts: usize = app.devices.values().map(|d| d.adverts.len()).sum();
    let search = if app.passive {
        Span::styled("passive (no searches)", WARN)
    } else {
        Span::raw(format!(
            "searches sent {}  next in {}",
            app.searches_sent,
            app.next_search_in()
                .map(fmt_secs)
                .unwrap_or_else(|| "-".into())
        ))
    };
    let stats = Line::from(vec![
        Span::raw(format!(
            "devices {}  adverts {}  packets {}",
            app.devices.len(),
            adverts,
            app.packet_total
        )),
        if app.unparsed > 0 {
            Span::styled(format!(" ({} unparsed)", app.unparsed), WARN)
        } else {
            Span::raw("")
        },
        Span::raw("  │  "),
        search,
        Span::raw(format!(
            "  │  ST {}  MX {}  │  up {}",
            app.targets.join(","),
            app.mx,
            fmt_secs(app.start.elapsed())
        )),
    ]);
    let hints = app.hints();
    let second = if hints.is_empty() {
        let keys = [
            ("↑↓", "select"),
            ("Tab/1-3", "view"),
            ("PgUp/PgDn J/K", "scroll"),
            ("r", "rescan"),
            ("f", "refetch"),
            ("c", "clear log"),
            ("m", "metrics"),
            ("q", "quit"),
        ];
        Line::from(
            keys.iter()
                .flat_map(|(k, v)| [Span::styled(*k, KEY), Span::raw(format!(" {v}  "))])
                .collect::<Vec<_>>(),
        )
    } else {
        Line::styled(format!("⚠ {}", hints.join("; ")), WARN)
    };
    let title = format!(
        " {} {} — SSDP/UPnP ",
        crate::APP_NAME,
        env!("CARGO_PKG_VERSION")
    );
    frame.render_widget(
        Paragraph::new(vec![stats, second])
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_device_list(frame: &mut Frame, area: Rect, app: &App) {
    let rows = app.rows();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| match &r.key {
            RowKey::Searches => ListItem::new(Line::from(vec![
                Span::styled(
                    "(control points)",
                    Style::new().add_modifier(Modifier::ITALIC),
                ),
                Span::styled(format!("  {} M-SEARCH", app.searches.len()), DIM),
            ])),
            RowKey::Device(uuid) => {
                let dev = &app.devices[uuid];
                let mut spans = vec![Span::raw("  ".repeat(r.depth))];
                if r.depth > 0 {
                    spans.push(Span::styled("└ ", DIM));
                }
                let name_style = if dev.live() { Style::new() } else { DIM };
                spans.push(Span::styled(app.display_name(uuid), name_style));
                spans.push(Span::styled(format!("  {}", dev.adverts.len()), DIM));
                let issues = app.device_issues(uuid);
                if worst_mark(&issues).is_some() {
                    spans.push(Span::raw(" "));
                    spans.push(mark_span(&issues));
                }
                ListItem::new(Line::from(spans))
            }
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(app.selected_index(&rows)));
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Devices ({}) ", app.devices.len())),
        )
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(match &app.selected {
            RowKey::Searches => " Control points ".to_string(),
            RowKey::Device(u) => format!(" uuid:{u} "),
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(inner);
    let first = match app.selected {
        RowKey::Searches => "1 Searches",
        RowKey::Device(_) => "1 Adverts",
    };
    let tabs = Tabs::new(vec![first, "2 Description", "3 Packets"])
        .select(app.tab.index())
        .highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan))
        .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(tabs, parts[0]);
    let content = parts[1];
    match (&app.selected, app.tab) {
        (RowKey::Searches, Tab::Adverts) => draw_searches(frame, content, app),
        (RowKey::Searches, Tab::Description) => frame.render_widget(
            Paragraph::new("Control points have no description: they only search.").style(DIM),
            content,
        ),
        (RowKey::Device(u), Tab::Adverts) => draw_adverts(frame, content, app, u),
        (RowKey::Device(u), Tab::Description) => draw_description(frame, content, app, u),
        (_, Tab::Packets) => draw_packets(frame, content, app),
    }
}

fn draw_searches(frame: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<Row> = app
        .searches
        .iter()
        .rev()
        .map(|s| {
            let src = if s.own {
                Cell::from(Span::styled("(uex)", DIM))
            } else {
                Cell::from(source_label(&s.src, &s.iface))
            };
            let ua = match worst_mark(&s.issues) {
                None => Cell::from(s.user_agent.clone()),
                Some(sev) => {
                    let text: Vec<&str> = s.issues.iter().map(|i| i.text.as_str()).collect();
                    Cell::from(Line::from(vec![
                        Span::styled(format!("! {} ", text.join("; ")), severity_style(sev)),
                        Span::raw(s.user_agent.clone()),
                    ]))
                }
            };
            Row::new(vec![
                Cell::from(
                    chrono::DateTime::<chrono::Local>::from(s.at)
                        .format("%H:%M:%S")
                        .to_string(),
                ),
                src,
                Cell::from(short_type(&s.st).to_string()),
                Cell::from(s.mx.clone()),
                ua,
            ])
        })
        .collect();
    let mut state = TableState::default().with_offset(app.scroll as usize);
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(28),
            Constraint::Percentage(30),
            Constraint::Length(3),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(["Time", "Source", "ST", "MX", "User-Agent"])
            .style(Style::new().add_modifier(Modifier::BOLD)),
    );
    frame.render_stateful_widget(table, area, &mut state);
}

fn kv<'a>(k: &'a str, v: impl Into<String>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{k:<14}"), DIM),
        Span::raw(v.into()),
    ])
}

fn draw_adverts(frame: &mut Frame, area: Rect, app: &App, uuid: &str) {
    let Some(dev) = app.devices.get(uuid) else {
        return;
    };
    let now = Instant::now();
    let issues = app.device_issues(uuid);
    let first = dev.adverts.values().next();
    let mut summary = vec![
        kv("Name", app.display_name(uuid)),
        kv(
            "Server",
            first.and_then(|a| a.server.clone()).unwrap_or_default(),
        ),
        kv(
            "Location",
            first.and_then(|a| a.location.clone()).unwrap_or_default(),
        ),
    ];
    let boot = first.and_then(|a| a.boot_id.clone());
    let config = first.and_then(|a| a.config_id.clone());
    if boot.is_some() || config.is_some() {
        summary.push(kv(
            "BOOTID/CONFIG",
            format!(
                "{} / {}",
                boot.unwrap_or_else(|| "-".into()),
                config.unwrap_or_else(|| "-".into())
            ),
        ));
    }
    summary.push(kv(
        "First seen",
        format!("{} ago", fmt_secs(now - dev.first_seen)),
    ));
    let issue_h = if issues.is_empty() {
        0
    } else {
        issues.len().min(8) as u16 + 1
    };
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(summary.len() as u16 + 1),
            Constraint::Min(3),
            Constraint::Length(issue_h),
        ])
        .split(area);
    frame.render_widget(Paragraph::new(summary), parts[0]);

    let rows: Vec<Row> = dev
        .adverts
        .values()
        .map(|a| {
            let (via, via_style) = match (a.gone, a.via) {
                (Some(_), _) => ("byebye", DIM),
                (None, AdvertVia::Notify) => ("NOTIFY", Style::new()),
                (None, AdvertVia::Response) => ("200", Style::new()),
            };
            let rem = a.remaining(now);
            let ttl_style = if a.gone.is_some() {
                DIM
            } else if rem.as_secs() * 10 < a.lifetime().as_secs() {
                BAD
            } else if rem.as_secs() * 4 < a.lifetime().as_secs() {
                WARN
            } else {
                Style::new()
            };
            let ttl = match a.max_age {
                Some(_) => fmt_secs(rem),
                None => format!("{}?", fmt_secs(rem)),
            };
            Row::new(vec![
                Cell::from(mark_span(&a.issues)),
                Cell::from(short_type(&a.target).to_string()),
                Cell::from(Span::styled(via, via_style)),
                Cell::from(Span::styled(ttl, ttl_style)),
                Cell::from(source_label(&a.src, &a.iface)),
                Cell::from(a.count.to_string()),
                Cell::from(fmt_secs(now - a.first_seen)),
            ])
        })
        .collect();
    let mut state = TableState::default().with_offset(app.scroll as usize);
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(26),
            Constraint::Length(5),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(["", "NT / ST", "Via", "Expires", "Source", "Seen", "Age"])
            .style(Style::new().add_modifier(Modifier::BOLD)),
    );
    frame.render_stateful_widget(table, parts[1], &mut state);

    if !issues.is_empty() {
        let mut lines = vec![Line::styled("Issues", WARN.add_modifier(Modifier::BOLD))];
        lines.extend(issues.iter().map(|i| {
            Line::styled(
                format!("{} {}", i.severity.icon(), i.text),
                severity_style(i.severity),
            )
        }));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), parts[2]);
    }
}

fn device_lines(lines: &mut Vec<Line<'static>>, d: &Device, loc: &str, base: &str) {
    let url = |rel: &str| describe::resolve(loc, base, rel);
    for (k, v) in [
        ("deviceType", d.device_type.clone()),
        ("friendlyName", d.friendly_name.clone()),
        ("manufacturer", d.manufacturer.clone()),
        ("manufacturerURL", d.manufacturer_url.clone()),
        ("modelName", d.model_name.clone()),
        ("modelNumber", d.model_number.clone()),
        ("modelDescr.", d.model_description.clone()),
        ("modelURL", d.model_url.clone()),
        ("serialNumber", d.serial_number.clone()),
        ("UDN", d.udn.clone()),
        ("presentation", url(&d.presentation_url)),
    ] {
        if !v.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(format!("{k:<16}"), DIM),
                Span::raw(v),
            ]));
        }
    }
    if !d.icons.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("Icons ({})", d.icons.len()),
            Style::new().add_modifier(Modifier::BOLD),
        ));
        for i in &d.icons {
            lines.push(Line::raw(format!(
                "  {}x{}x{} {}  {}",
                i.width,
                i.height,
                i.depth,
                i.mimetype,
                url(&i.url)
            )));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("Services ({})", d.services.len()),
        Style::new().add_modifier(Modifier::BOLD),
    ));
    for s in &d.services {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(short_type(&s.service_type).to_string(), KEY),
            Span::styled(format!("  {}", s.service_id), DIM),
        ]));
        for (k, v) in [
            ("SCPD", &s.scpd_url),
            ("control", &s.control_url),
            ("events", &s.event_sub_url),
        ] {
            lines.push(Line::from(vec![
                Span::styled(format!("    {k:<8}"), DIM),
                Span::raw(url(v)),
            ]));
        }
    }
    if !d.devices.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("Embedded devices ({})", d.devices.len()),
            Style::new().add_modifier(Modifier::BOLD),
        ));
        fn tree(lines: &mut Vec<Line<'static>>, ds: &[Device], depth: usize) {
            for d in ds {
                lines.push(Line::from(vec![
                    Span::raw(format!("{}└ ", "  ".repeat(depth + 1))),
                    Span::raw(d.friendly_name.clone()),
                    Span::styled(format!("  {}  {}", short_type(&d.device_type), d.udn), DIM),
                ]));
                tree(lines, &d.devices, depth + 1);
            }
        }
        tree(lines, &d.devices, 0);
    }
}

/// What the server sent instead of a description, so a wrong endpoint
/// or an error page is recognizable at a glance.
fn body_preview_lines(lines: &mut Vec<Line<'static>>, b: &describe::BodyPreview) {
    let mut meta = vec![format!("HTTP {}", b.status)];
    meta.push(
        b.content_type
            .clone()
            .unwrap_or_else(|| "no Content-Type".into()),
    );
    meta.push(format!("{} bytes", b.bytes));
    if let Some(server) = &b.server {
        meta.push(format!("server {server}"));
    }
    lines.push(Line::styled(format!("  {}", meta.join(" · ")), DIM));
    if b.lines.is_empty() {
        lines.push(Line::styled("  │ (empty body)", DIM));
    }
    for l in &b.lines {
        lines.push(Line::from(vec![
            Span::styled("  │ ", DIM),
            Span::raw(l.clone()),
        ]));
    }
    if b.more_lines > 0 {
        lines.push(Line::styled(
            format!("  │ … {} more line(s)", b.more_lines),
            DIM,
        ));
    }
}

fn draw_description(frame: &mut Frame, area: Rect, app: &App, uuid: &str) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let states = app.description_states(uuid);
    if states.is_empty() {
        lines.push(Line::styled("No http LOCATION advertised.", DIM));
    }
    for (loc, st) in &states {
        let status = match st {
            DescState::Pending => Span::styled("fetching…", WARN),
            DescState::Failed(e) => Span::styled(format!("failed: {e}"), BAD),
            DescState::Ready(f) => Span::styled(
                format!(
                    "{} bytes in {} ms{}{}",
                    f.bytes,
                    f.elapsed.as_millis(),
                    f.content_type
                        .as_deref()
                        .map(|c| format!(", {c}"))
                        .unwrap_or_default(),
                    f.server
                        .as_deref()
                        .map(|s| format!(", server {s}"))
                        .unwrap_or_default(),
                ),
                DIM,
            ),
        };
        lines.push(Line::from(vec![Span::raw(format!("{loc}  ")), status]));
        if let DescState::Failed(describe::FetchError { body: Some(b), .. }) = st {
            body_preview_lines(&mut lines, b);
        }
    }
    if let Some((loc, f, dev)) = app.described(uuid) {
        let d = &f.description;
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled(format!("{:<16}", "specVersion"), DIM),
            Span::raw(d.spec_version.clone()),
        ]));
        if !d.url_base.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<16}", "URLBase"), DIM),
                Span::raw(d.url_base.clone()),
            ]));
        }
        if !d.root.udn.eq_ignore_ascii_case(&dev.udn) {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<16}", "root device"), DIM),
                Span::raw(format!("{} ({})", d.root.friendly_name, d.root.udn)),
            ]));
        }
        lines.push(Line::raw(""));
        device_lines(&mut lines, dev, loc, &d.url_base);
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0)),
        area,
    );
}

fn draw_packets(frame: &mut Frame, area: Rect, app: &App) {
    let packets = app.visible_packets();
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);
    let items: Vec<ListItem> = packets
        .iter()
        .map(|e| {
            let p = &e.packet;
            let src = if e.own {
                "(uex)".to_string()
            } else {
                source_label(&p.src, &p.iface)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    chrono::DateTime::<chrono::Local>::from(p.at)
                        .format("%H:%M:%S%.3f ")
                        .to_string(),
                    DIM,
                ),
                Span::raw(format!("{src:<28} ")),
                Span::raw(e.summary.clone()),
            ]))
        })
        .collect();
    let cursor = app.packet_cursor.min(packets.len().saturating_sub(1));
    let mut state = ListState::default().with_selected((!packets.is_empty()).then_some(cursor));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .title(format!("{} packet(s), newest first", packets.len())),
            )
            .highlight_style(Style::new().bg(Color::DarkGray)),
        parts[0],
        &mut state,
    );
    let Some(e) = packets.get(cursor) else {
        return;
    };
    let p = &e.packet;
    let mut lines = vec![Line::styled(
        format!(
            "{} → {}  via {:?} on {}  {} bytes",
            p.src,
            p.dst,
            p.via,
            if p.iface.is_empty() { "?" } else { &p.iface },
            p.raw.len()
        ),
        DIM,
    )];
    let text = String::from_utf8_lossy(&p.raw);
    lines.extend(
        text.split('\n')
            .map(|l| Line::raw(l.strip_suffix('\r').unwrap_or(l).to_string())),
    );
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), parts[1]);
}

fn draw_popup(frame: &mut Frame, text: &str) {
    let area = frame.area();
    let w = (text.chars().count() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + area.height.saturating_sub(4),
        width: w,
        height: 3.min(area.height),
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        rect,
    );
}
