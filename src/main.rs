// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

mod app;
mod describe;
mod ssdp;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::str::FromStr;

/// Program name, from Cargo: CLI name, log directory and file names.
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
    version,
    about = "Terminal UI to browse and debug SSDP/UPnP on the local network — live devices, advertisements, descriptions, and raw packets"
)]
struct Args {
    /// Listen only: never send M-SEARCH, just observe NOTIFY traffic
    #[arg(long)]
    passive: bool,

    /// Network interfaces to use for SSDP discovery (e.g., br0, eth0)
    #[arg(long, short, value_delimiter = ',')]
    interfaces: Option<Vec<String>>,

    /// Search target(s) for M-SEARCH (e.g. ssdp:all, upnp:rootdevice,
    /// urn:schemas-upnp-org:device:MediaServer:1)
    #[arg(long, short = 't', value_delimiter = ',', default_value = "ssdp:all")]
    search_target: Vec<String>,

    /// M-SEARCH MX: seconds devices may delay their responses (1-5)
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=5))]
    mx: u8,

    /// Local UDP port for M-SEARCH and its unicast replies. Default 1900
    /// (the SSDP port, already allowed by typical firewall rules);
    /// 0 picks an ephemeral port.
    #[arg(long, value_name = "PORT", default_value_t = ssdp::SSDP_PORT)]
    search_port: u16,

    /// Override the default log file. Appended; rotated past 5 MiB
    /// with 3 backups kept.
    #[arg(long, value_name = "PATH")]
    log_file: Option<String>,

    /// Minimum log level recorded by every active sink (off, error,
    /// warn, info, debug, trace)
    #[arg(long, value_name = "LEVEL", value_parser = parse_log_level)]
    log_level: Option<log::LevelFilter>,
}

/// Minimal log sink with no new dependencies. The file sink (if
/// `--log-file` is given) records Info and above; headless stderr gets
/// Warn and above so routine traffic stays quiet. TUI mode without a
/// file installs no logger at all — writing to the terminal would
/// corrupt the interface.
/// Mutable logger state. Held in a global so `init_logging` can reconfigure
/// thresholds and sinks even after the (process-wide, first-wins) logger has
/// been installed; this keeps level changes observable in tests.
struct LoggerState {
    file: Option<std::sync::Mutex<RotatingLog>>,
    file_level: log::LevelFilter,
    stderr: bool,
    stderr_level: log::LevelFilter,
}

static LOGGER_STATE: std::sync::Mutex<LoggerState> = std::sync::Mutex::new(LoggerState {
    file: None,
    file_level: log::LevelFilter::Info,
    stderr: false,
    stderr_level: log::LevelFilter::Warn,
});

struct Logger;

static LOGGER: Logger = Logger;

impl Logger {
    fn install(file: Option<RotatingLog>, stderr: bool, log_level: Option<log::LevelFilter>) {
        let (file_level, stderr_level) = match log_level {
            Some(level) => (level, level),
            None => (log::LevelFilter::Info, log::LevelFilter::Warn),
        };
        let max_level = log_level.unwrap_or(log::LevelFilter::Info);
        if let Ok(mut state) = LOGGER_STATE.lock() {
            state.file = file.map(std::sync::Mutex::new);
            state.file_level = file_level;
            state.stderr = stderr;
            state.stderr_level = stderr_level;
        }
        // A test binary shares one process-wide logger: first install
        // wins, later ones are ignored, but the state above is always
        // updated.
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(max_level);
    }
}

/// Last retained log write failure, if any. Global because the logger
/// is a leaked static and cannot be downcast through `dyn log::Log`.
static LAST_LOG_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Take the last retained write failure, if any.
pub fn take_log_error() -> Option<String> {
    LAST_LOG_ERROR.lock().ok().and_then(|mut e| e.take())
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if let Ok(state) = LOGGER_STATE.lock() {
            (state.file.is_some() && metadata.level() <= state.file_level)
                || (state.stderr && metadata.level() <= state.stderr_level)
        } else {
            false
        }
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} [{}] {}\n",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
            record.level(),
            record.args()
        );
        if let Ok(state) = LOGGER_STATE.lock() {
            if state.file.is_some() && record.metadata().level() <= state.file_level {
                if let Some(f) = &state.file {
                    if let Ok(mut f) = f.lock() {
                        if let Err(e) = f.write_line(&line) {
                            if let Ok(mut le) = LAST_LOG_ERROR.lock() {
                                *le = Some(format!("log write failed: {e}"));
                            }
                        }
                    }
                }
            }
            if state.stderr && record.metadata().level() <= state.stderr_level {
                eprint!("{line}");
            }
        }
    }

    fn flush(&self) {}
}

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const KEEP_LOG_GENERATIONS: u32 = 3;

/// Size-based log rotation: `uex.log` plus `uex.log.1..N` backups.
struct RotatingLog {
    /// `None` only while closed for renaming: Windows cannot rename an
    /// open file, so `rotate` drops the handle first.
    file: Option<std::fs::File>,
    path: std::path::PathBuf,
    written: u64,
    max_bytes: u64,
    keep: u32,
}

impl RotatingLog {
    fn open(path: &std::path::Path, max_bytes: u64, keep: u32) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut log = Self {
            file: Some(Self::append(path)?),
            path: path.to_path_buf(),
            written: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            max_bytes,
            keep,
        };
        if log.written >= max_bytes {
            log.rotate()?;
        }
        Ok(log)
    }

    fn append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }

    /// Backup path `uex.log.N` for generation `n`.
    fn backup_path(&self, n: u32) -> std::path::PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{n}"));
        self.path.with_file_name(name)
    }

    /// Append one line, rotating first when it would exceed the cap, so
    /// the live file stays bounded.
    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        if self.written + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        if let Some(f) = self.file.as_mut() {
            use std::io::Write;
            f.write_all(line.as_bytes())?;
            self.written += line.len() as u64;
        }
        Ok(())
    }

    /// Shift generations down (`uex.log` -> `.1` -> `.2` ...) and reopen a
    /// fresh live file. Missing generations are skipped; rename targets
    /// are removed first for Windows, where rename will not replace.
    fn rotate(&mut self) -> std::io::Result<()> {
        // Close before renaming: Windows cannot rename an open file.
        self.file.take();
        for i in (1..=self.keep).rev() {
            let from = if i == 1 {
                self.path.clone()
            } else {
                self.backup_path(i - 1)
            };
            if from.exists() {
                let to = self.backup_path(i);
                let _ = std::fs::remove_file(&to);
                std::fs::rename(&from, &to)?;
            }
        }
        self.file = Some(Self::append(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

/// Default log directory: XDG state dir on Linux
/// (`$XDG_STATE_HOME/uex`, else `~/.local/state/uex`), `~/Library/Logs`
/// on macOS, `%LOCALAPPDATA%` on Windows, temp dir as a last resort.
fn default_log_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        return std::path::PathBuf::from(dir).join(APP_NAME).join("logs");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join("Library")
            .join("Logs")
            .join(APP_NAME);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        if !state.is_empty() {
            return std::path::PathBuf::from(state).join(APP_NAME);
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(APP_NAME);
    }
    std::env::temp_dir().join(APP_NAME)
}

/// Install logging before the app runs: an explicit `--log-file`
/// overrides the default `uex.log` in the platform log directory;
/// headless mode also keeps stderr warnings. A bad explicit path fails
/// fast; an unusable default directory degrades to stderr-only
/// (headless) or silent (TUI, where printing would corrupt the UI).
fn init_logging(
    log_file: Option<&str>,
    has_tui: bool,
    log_level: Option<log::LevelFilter>,
) -> Result<()> {
    let (path, stderr) = match log_file {
        Some(p) => (std::path::PathBuf::from(p), false),
        None => (default_log_dir().join(format!("{APP_NAME}.log")), !has_tui),
    };
    match RotatingLog::open(&path, MAX_LOG_BYTES, KEEP_LOG_GENERATIONS) {
        Ok(log) => {
            Logger::install(Some(log), stderr, log_level);
            Ok(())
        }
        Err(e) if log_file.is_some() => Err(anyhow::anyhow!(
            "cannot open log file {}: {e}",
            path.display()
        )),
        Err(e) => {
            if stderr {
                eprintln!(
                    "{APP_NAME}: cannot open log file {}: {e}; continuing with stderr only",
                    path.display()
                );
                Logger::install(None, true, log_level);
            }
            Ok(())
        }
    }
}

fn parse_log_level(value: &str) -> Result<log::LevelFilter, String> {
    log::LevelFilter::from_str(value).map_err(|_| format!("invalid log level: {value}"))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let selection = match args.interfaces.as_ref() {
        Some(ifs) => Some(ssdp::validate_selection(
            ifs,
            &ssdp::available_interfaces(),
        )?),
        None => None,
    };
    let mut terminal = ui::try_init()?;
    let has_tui = terminal.is_some();
    if let Err(e) = init_logging(args.log_file.as_deref(), has_tui, args.log_level) {
        ui::try_restore(has_tui)?;
        return Err(e);
    }
    log::info!(
        "{APP_NAME}: starting (tui={has_tui}, passive={}, interfaces={:?})",
        args.passive,
        args.interfaces
    );
    let opts = app::Options {
        passive: args.passive,
        selection,
        mx: args.mx,
        targets: args.search_target,
        search_port: args.search_port,
    };
    let res = app::App::new(opts, !has_tui).and_then(|mut app| app.run(&mut terminal));
    ui::try_restore(has_tui)?;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse() {
        let a = Args::try_parse_from(["uex"]).unwrap();
        assert!(!a.passive);
        assert_eq!(a.search_target, vec!["ssdp:all"]);
        assert_eq!(a.mx, 2);
        let a = Args::try_parse_from([
            "uex",
            "--passive",
            "-i",
            "eth0,br0",
            "-t",
            "upnp:rootdevice,ssdp:all",
            "--mx",
            "5",
            "--log-level",
            "debug",
        ])
        .unwrap();
        assert!(a.passive);
        assert_eq!(a.interfaces.unwrap(), vec!["eth0", "br0"]);
        assert_eq!(a.search_target, vec!["upnp:rootdevice", "ssdp:all"]);
        assert_eq!(a.mx, 5);
        assert_eq!(a.log_level, Some(log::LevelFilter::Debug));
        assert!(Args::try_parse_from(["uex", "--mx", "0"]).is_err());
        assert!(Args::try_parse_from(["uex", "--mx", "6"]).is_err());
    }

    #[test]
    fn rotating_log_caps_size_and_generations() {
        let dir = std::env::temp_dir().join(format!("uex-logrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("uex.log");
        let mut log = RotatingLog::open(&path, 200, 2).unwrap();
        for i in 0..50 {
            log.write_line(&format!("line {i:02} with padding 0123456789012345678\n"))
                .unwrap();
        }
        drop(log);
        assert!(std::fs::metadata(&path).unwrap().len() <= 200);
        assert!(dir.join("uex.log.1").exists());
        assert!(!dir.join("uex.log.3").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
