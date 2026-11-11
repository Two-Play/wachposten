//! `wachposten`: command line access to events, decisions and the quarantine.
//! The Slint window follows in a later stage.

use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use wachposten_core::i18n;
use wachposten_core::ipc::{self, Reply, Request};
use wachposten_core::settings::settings_path;
use wachposten_core::{Config, Entry, Event, Guard, Outcome, Settings};
use wachposten_scan::{HashDb, MalwareScanner, YaraEngine, bazaar, hash_db_path};

#[derive(Parser)]
#[command(
    name = "wachposten",
    version,
    about = "Guard for persistence locations on Linux desktops"
)]
struct Cli {
    /// Talk to the root daemon (system-wide events) instead of your own agent's data.
    #[arg(long, global = true)]
    system: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the window (also what `wachposten` without a command does on a desktop).
    Window {
        /// Page to show first.
        #[arg(long, value_parser = ["overview", "alerts", "history", "quarantine", "allowed", "settings"])]
        tab: Option<String>,
    },
    /// Show whether the agent runs and how many entries and events there are.
    Status,
    /// List events (open ones by default).
    Events {
        /// Show all recent events, not only open ones.
        #[arg(long)]
        all: bool,
        /// Number of events with --all.
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Show one event with its added lines and findings.
    Show { id: i64 },
    /// Accept a change; it becomes part of the baseline.
    Allow { id: i64 },
    /// Undo a change and move the new version into quarantine.
    Remove { id: i64 },
    /// List the quarantine.
    Quarantine,
    /// Put a quarantined version back.
    Restore {
        id: i64,
        /// Replace what is at the original path now.
        #[arg(long)]
        force: bool,
    },
    /// Compare everything with the baseline now and record changes.
    Scan,
    /// Check files for known malware (YARA-X and the hash list) without recording anything.
    ScanFile {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Show the YARA-X rule files and whether they compiled.
    Rules,
    /// Manage the local list of known malware hashes (MalwareBazaar).
    Hashes {
        #[command(subcommand)]
        action: HashAction,
    },
    /// Show or change settings.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand)]
enum HashAction {
    /// Number of hashes and the time of the last update.
    Status,
    /// Download the hashes of the last 48 hours now (needs an Auth-Key).
    Update,
    /// Import a list downloaded by hand (CSV, plain text or ZIP).
    Import { file: PathBuf },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the settings file.
    Show,
    /// Store your MalwareBazaar Auth-Key from https://auth.abuse.ch/ (enables hash list updates).
    SetKey { key: String },
    /// Remove the Auth-Key; no more downloads from MalwareBazaar.
    UnsetKey,
    /// Also look up single files online. This sends their SHA-256 hash to MalwareBazaar.
    OnlineLookup {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Switch download scanning on or off.
    Downloads {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

fn date(ts: i64) -> String {
    // Avoids a date crate: let `date` format the timestamp in the local time zone.
    std::process::Command::new("date")
        .args(["-d", &format!("@{ts}"), "+%Y-%m-%d %H:%M"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| ts.to_string(), |s| s.trim().to_string())
}

fn pretty(home: &Path, path: &str) -> String {
    if home == Path::new("/") {
        return path.to_string();
    }
    match Path::new(path).strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.to_string(),
    }
}

pub(crate) fn agent_running(config: &Config) -> bool {
    let Ok(file) = File::open(config.lock_path()) else {
        return false;
    };
    matches!(file.try_lock(), Err(TryLockError::WouldBlock))
}

fn print_event_line(home: &Path, ev: &Event) {
    println!(
        "{:>5}  {}  {:<10} {:<9} {:<10} {}",
        ev.id,
        date(ev.updated_at),
        ev.severity.as_str(),
        ev.change.as_str(),
        ev.status.as_str(),
        pretty(home, &ev.path)
    );
}

fn show(guard: &Guard, id: i64) -> Result<()> {
    let Some(ev) = guard.store().event(id)? else {
        bail!("event {id} does not exist");
    };
    show_event(&guard.config().home, &ev);
    Ok(())
}

fn show_event(home: &Path, ev: &Event) {
    let ev = ev.clone();
    println!("Event {}: {}", ev.id, i18n::event_title(&ev));
    println!("  {}", i18n::event_sentence(&ev));
    println!("  path:     {}", pretty(home, &ev.path));
    println!("  kind:     {} ({})", ev.kind, i18n::kind_label(ev.kind));
    println!("  change:   {}", ev.change.as_str());
    println!("  severity: {}", ev.severity.as_str());
    println!("  status:   {}", ev.status.as_str());
    println!("  seen:     {}", date(ev.created_at));
    if let Some(q) = ev.quarantine_id {
        println!("  quarantine: {q}");
    }
    if let Some(actor) = &ev.actor {
        println!("  changed by: {actor}");
    }
    match &ev.new_entry {
        Some(Entry::Symlink { target, .. }) => println!("  link to:  {target}"),
        Some(Entry::File {
            content: None,
            size,
            ..
        }) => println!("  content:  {size} bytes, too large to keep"),
        _ => {}
    }
    if !ev.findings.is_empty() {
        println!("\nFindings:");
        for f in &ev.findings {
            println!("  ⚠ {}", i18n::rule_label(&f.rule));
            if !f.line.is_empty() {
                println!("      {}", f.line);
            }
        }
    }
    if !ev.added_lines.is_empty() {
        println!("\nAdded lines:");
        for l in &ev.added_lines {
            println!("  + {l}");
        }
    }
}

fn hash_status(config: &Config) -> Result<()> {
    let db = HashDb::open(&hash_db_path(&config.data_dir))?;
    println!("known hashes: {}", db.count()?);
    for (key, label) in [
        ("updated_at", "last update"),
        ("imported_at", "last import"),
    ] {
        if let Some(ts) = db.meta(key)?.and_then(|v| v.parse().ok()) {
            println!("{label}: {}", date(ts));
        }
    }
    Ok(())
}

const PRIVACY_NOTE: &str = "Wachposten only downloads lists from MalwareBazaar; it sends nothing about your files.\n\
abuse.ch allows free use for non-commercial purposes only.";

fn config_cmd(config: &Config, action: Option<ConfigAction>) -> Result<()> {
    let home = &config.home;
    let mut settings = Settings::load(home)?;
    let on = |s: &str| s == "on";
    match action.unwrap_or(ConfigAction::Show) {
        ConfigAction::Show => {
            println!("# {}", settings_path(home).display());
            let mut shown = settings.clone();
            if let Some(k) = &mut shown.hashes.malwarebazaar_auth_key {
                *k = format!("{}…", k.chars().take(4).collect::<String>());
            }
            print!("{}", toml::to_string_pretty(&shown)?);
            return Ok(());
        }
        ConfigAction::SetKey { key } => {
            settings.hashes.malwarebazaar_auth_key = Some(key.trim().to_string());
            println!("{PRIVACY_NOTE}");
        }
        ConfigAction::UnsetKey => settings.hashes.malwarebazaar_auth_key = None,
        ConfigAction::OnlineLookup { state } => {
            settings.hashes.online_lookup = on(&state);
            if on(&state) {
                println!(
                    "Online lookups send the SHA-256 hash of scanned files (never the files) to MalwareBazaar."
                );
                if settings.hashes.malwarebazaar_auth_key.is_none() {
                    println!("They need an Auth-Key: wachposten config set-key <key>");
                }
            }
        }
        ConfigAction::Downloads { state } => settings.downloads.enabled = on(&state),
    }
    settings.save(home)?;
    println!("saved; restart the agent to apply: systemctl --user restart wachposten-agent");
    Ok(())
}

mod gui;

fn has_display() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

fn socket_path() -> PathBuf {
    std::env::var_os("WACHPOSTEN_SOCKET").map_or_else(|| PathBuf::from(ipc::SOCKET), PathBuf::from)
}

fn daemon(request: &Request) -> Result<Reply> {
    let reply = ipc::call(&socket_path(), request).map_err(|e| {
        anyhow::anyhow!(
            "cannot reach wachposten-daemon at {}: {e}",
            socket_path().display()
        )
    })?;
    if let Reply::Error { message } = reply {
        bail!(message);
    }
    Ok(reply)
}

/// Commands with `--system`, answered by the daemon.
fn system_cmd(command: Command) -> Result<()> {
    let root = Path::new("/");
    match command {
        Command::Status => {
            if let Reply::Status {
                baseline,
                open,
                exec_watch,
                blocking,
                yara_rules,
                known_hashes,
                clamav,
                ebpf,
                ransomware,
                home_btrfs,
                snapshots,
            } = daemon(&Request::Status)?
            {
                println!("daemon:         running");
                println!("baseline:       {baseline} entries");
                println!("open events:    {open}");
                println!(
                    "program starts: {}",
                    if exec_watch { "watched" } else { "not watched" }
                );
                println!(
                    "blocking:       {}",
                    if blocking {
                        "known malware is blocked"
                    } else {
                        "off"
                    }
                );
                println!("YARA-X rules:   {yara_rules}");
                println!("known hashes:   {known_hashes}");
                println!(
                    "ClamAV:         {}",
                    if clamav { "in use" } else { "not available" }
                );
                println!(
                    "eBPF:           {}",
                    if ebpf {
                        "scripts, memory programs and writers watched"
                    } else {
                        "off"
                    }
                );
                println!(
                    "ransomware:     {}",
                    if ransomware {
                        "watched, such programs are stopped"
                    } else {
                        "off"
                    }
                );
                println!(
                    "snapshots:      {}",
                    match (&snapshots, home_btrfs) {
                        (Some(tool), _) => format!("/home by {tool}"),
                        (None, true) => "none – set up snapper for /home (see README)".into(),
                        (None, false) => "none – keep backups of your files (see README)".into(),
                    }
                );
            }
        }
        Command::Events { all, limit } => {
            if let Reply::Events { events } = daemon(&Request::Events { all, limit })? {
                if events.is_empty() {
                    println!("no events");
                }
                for ev in &events {
                    print_event_line(root, ev);
                }
            }
        }
        Command::Show { id } => {
            if let Reply::Event { event, can_decide } = daemon(&Request::Show { id })? {
                show_event(root, &event);
                if !can_decide && event.decidable() {
                    println!("\n(an admin decides about this event)");
                }
            }
        }
        Command::Allow { id } | Command::Remove { id } => {
            let decision = if matches!(command, Command::Allow { .. }) {
                ipc::Decision::Allow
            } else {
                ipc::Decision::Remove
            };
            if let Reply::Done { message } = daemon(&Request::Decide {
                id,
                hash: None,
                decision,
            })? {
                println!("{message}");
            }
        }
        Command::Quarantine => {
            if let Reply::Quarantine { items } = daemon(&Request::Quarantine)? {
                print_quarantine(root, &items);
            }
        }
        Command::Restore { id, force } => {
            if let Reply::Done { message } = daemon(&Request::Restore { id, force })? {
                println!("{message}");
            }
        }
        _ => bail!("this command does not work with --system"),
    }
    Ok(())
}

fn print_quarantine(home: &Path, items: &[wachposten_core::QuarantineItem]) {
    if items.is_empty() {
        println!("quarantine is empty");
    }
    for q in items {
        println!(
            "{:>5}  {}  {:<14} {:<9} {}{}",
            q.id,
            date(q.created_at),
            q.kind.as_str(),
            q.entry_type,
            pretty(home, &q.original_path),
            if q.restored_at.is_some() {
                "  (restored)"
            } else {
                ""
            }
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() && !cli.system && has_display() {
        return gui::run(None);
    }
    if cli.system {
        return system_cmd(cli.command.unwrap_or(Command::Status));
    }
    let config = Config::from_env()?;
    let mut guard = Guard::open(config.clone())?;
    let home = config.home.clone();

    match cli.command.unwrap_or(Command::Status) {
        Command::Window { tab } => return gui::run(tab.as_deref()),
        Command::Status => {
            let open = guard.store().open_events()?;
            println!(
                "agent:       {}",
                if agent_running(&config) {
                    "running"
                } else {
                    "not running"
                }
            );
            println!(
                "baseline:    {}",
                if guard.is_initialized()? {
                    format!("{} entries", guard.store().baseline_count()?)
                } else {
                    "not recorded yet (start wachposten-agent)".into()
                }
            );
            println!("open events: {}", open.len());
            for ev in &open {
                print_event_line(&home, ev);
            }
        }
        Command::Events { all, limit } => {
            let events = if all {
                guard.store().recent_events(limit)?
            } else {
                guard.store().open_events()?
            };
            if events.is_empty() {
                println!("no events");
            }
            for ev in &events {
                print_event_line(&home, ev);
            }
        }
        Command::Show { id } => show(&guard, id)?,
        Command::Allow { id } => {
            guard.allow(id, None)?;
            println!("event {id} allowed");
        }
        Command::Remove { id } => {
            if let Outcome::Removed {
                quarantine_id: Some(q),
            } = guard.remove(id, None)?
            {
                println!("event {id} removed; quarantine item {q} (wachposten restore {q})");
            }
        }
        Command::Quarantine => print_quarantine(&home, &guard.store().quarantine_items()?),
        Command::Restore { id, force } => {
            let path = guard.restore(id, force)?;
            println!("restored {}", pretty(&home, &path));
        }
        Command::ScanFile { paths } => {
            let settings = Settings::load(&home)?;
            let scanner = MalwareScanner::from_settings(&settings, &config.data_dir);
            let mut hits = 0;
            for path in &paths {
                let detections = scanner.scan_path(path);
                if detections.is_empty() {
                    println!("clean     {}", path.display());
                }
                for d in detections {
                    hits += 1;
                    println!("MALWARE   {}  {}", path.display(), d.label());
                }
            }
            if hits > 0 {
                std::process::exit(1);
            }
        }
        Command::Rules => {
            let settings = Settings::load(&home)?;
            let engine = YaraEngine::new(&settings.yara.extra_rule_dirs);
            for src in &engine.sources {
                let place = src
                    .path
                    .as_ref()
                    .map_or("built in".into(), |p| p.display().to_string());
                match &src.result {
                    Ok(()) => println!("ok       {:<24} {place}", src.name),
                    Err(e) => println!("skipped  {:<24} {place}\n         {e}", src.name),
                }
            }
            println!("{} rules loaded", engine.rule_count());
        }
        Command::Hashes { action } => match action {
            HashAction::Status => hash_status(&config)?,
            HashAction::Update => {
                let settings = Settings::load(&home)?;
                let Some(key) = settings.hashes.malwarebazaar_auth_key else {
                    bail!(
                        "no Auth-Key; get one at https://auth.abuse.ch/ and run: wachposten config set-key <key>"
                    );
                };
                let db = HashDb::open(&hash_db_path(&config.data_dir))?;
                let (got, new) = bazaar::update_recent(&db, &key)?;
                println!("received {got} hashes, {new} new");
            }
            HashAction::Import { file } => {
                let db = HashDb::open(&hash_db_path(&config.data_dir))?;
                let (got, new) = bazaar::import_file(&db, &file)?;
                println!("read {got} hashes, {new} new");
            }
        },
        Command::Config { action } => config_cmd(&config, action)?,
        Command::Scan => {
            if !guard.is_initialized()? {
                let n = guard.initialize()?;
                println!("baseline recorded with {n} entries");
                return Ok(());
            }
            let events = guard.rescan()?;
            let open: Vec<_> = events.iter().filter(|e| e.decidable()).collect();
            if open.is_empty() {
                println!("no new changes");
            }
            for ev in open {
                print_event_line(&home, ev);
            }
        }
    }
    Ok(())
}
