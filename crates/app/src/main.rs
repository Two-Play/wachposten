//! `wachposten`: command line access to events, decisions and the quarantine.
//! The Slint window follows in a later stage.

use std::fs::{File, TryLockError};
use std::path::Path;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use wachposten_core::i18n;
use wachposten_core::{Config, Entry, Event, Guard, Outcome, Status};

#[derive(Parser)]
#[command(
    name = "wachposten",
    version,
    about = "Guard for persistence locations on Linux desktops"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
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
    match Path::new(path).strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.to_string(),
    }
}

fn agent_running(config: &Config) -> bool {
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
    let home = &guard.config().home;
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
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::from_env()?;
    let mut guard = Guard::open(config.clone())?;
    let home = config.home.clone();

    match cli.command.unwrap_or(Command::Status) {
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
        Command::Quarantine => {
            let items = guard.store().quarantine_items()?;
            if items.is_empty() {
                println!("quarantine is empty");
            }
            for q in items {
                println!(
                    "{:>5}  {}  {:<12} {:<9} {}{}",
                    q.id,
                    date(q.created_at),
                    q.kind.as_str(),
                    q.entry_type,
                    pretty(&home, &q.original_path),
                    if q.restored_at.is_some() {
                        "  (restored)"
                    } else {
                        ""
                    }
                );
            }
        }
        Command::Restore { id, force } => {
            let path = guard.restore(id, force)?;
            println!("restored {}", pretty(&home, &path));
        }
        Command::Scan => {
            if !guard.is_initialized()? {
                let n = guard.initialize()?;
                println!("baseline recorded with {n} entries");
                return Ok(());
            }
            let events = guard.rescan()?;
            let open: Vec<_> = events.iter().filter(|e| e.status == Status::Open).collect();
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
