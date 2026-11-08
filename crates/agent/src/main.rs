//! `wachposten-agent`: watches the persistence locations in the home directory and asks the
//! person at the computer about every new or changed entry.

mod notify;
mod tray;

use std::fs::{File, TryLockError};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use wachposten_core::i18n::tr;
use wachposten_core::{
    Config, DecisionError, Event, FileScanner, Finding, Guard, Kind, Outcome, Settings,
};
use wachposten_scan::MalwareScanner;

/// How often everything is checked even without inotify events (crontab, missed events).
const TICK: Duration = Duration::from_secs(60);
/// At most this many questions are shown at once at start-up.
const MAX_STARTUP_QUESTIONS: usize = 5;

#[derive(Debug, Clone, Copy)]
pub enum Decision {
    Allow,
    Remove,
}

#[derive(Debug)]
pub enum Msg {
    Changed,
    Tick,
    Rescan,
    ShowOpen,
    /// A file in a download folder matched a malware signature or hash.
    Detection {
        path: PathBuf,
        findings: Vec<Finding>,
    },
    Decide {
        id: i64,
        hash: String,
        decision: Decision,
    },
    Quit,
}

struct Agent {
    guard: Guard,
    tx: Sender<Msg>,
    tray: Option<ksni::blocking::Handle<tray::Tray>>,
    watch: wachposten_watch::WatchHandle,
}

impl Agent {
    fn ask(&self, events: &[Event]) {
        for ev in events {
            notify::ask(&self.guard.config().home, ev, self.tx.clone());
        }
    }

    fn refresh(&self) -> Result<()> {
        let open = self.guard.store().open_events()?;
        if let Some(tray) = &self.tray {
            tray.update(|t| t.open = open.iter().map(tray::OpenItem::from_event).collect());
        }
        self.watch.set_specs(self.guard.watch_specs());
        Ok(())
    }

    fn rescan(&mut self) -> Result<()> {
        let events = self.guard.rescan()?;
        for ev in &events {
            log::info!(
                "event {}: {} {} ({})",
                ev.id,
                ev.change.as_str(),
                ev.path,
                ev.severity.as_str()
            );
        }
        self.ask(&events);
        self.refresh()
    }

    fn detection(&mut self, path: &std::path::Path, findings: &[Finding]) -> Result<()> {
        if let Some(ev) = self.guard.record_detection(path, findings)? {
            log::warn!("malware in {}: {:?}", path.display(), ev.findings);
            self.ask(std::slice::from_ref(&ev));
        }
        self.refresh()
    }

    fn show_open(&self) -> Result<()> {
        let open = self.guard.store().open_events()?;
        if open.len() > MAX_STARTUP_QUESTIONS {
            notify::info(
                &format!("{} {}", open.len(), tr("offene Meldungen", "open alerts")),
                tr(
                    "Die Liste findest du im Tray-Menü oder mit „wachposten events“.",
                    "See the tray menu or run \"wachposten events\".",
                ),
                "security-medium",
            );
            self.ask(&open[open.len() - MAX_STARTUP_QUESTIONS..]);
        } else {
            self.ask(&open);
        }
        Ok(())
    }

    fn decide(&mut self, id: i64, hash: &str, decision: Decision) -> Result<()> {
        let kind = self.guard.store().event(id)?.map(|e| e.kind);
        let result = match decision {
            Decision::Allow => self.guard.allow(id, Some(hash)),
            Decision::Remove => self.guard.remove(id, Some(hash)),
        };
        match result {
            Ok(Outcome::Allowed) => log::info!("event {id} allowed"),
            Ok(Outcome::Removed { quarantine_id }) => {
                log::info!("event {id} removed, quarantine {quarantine_id:?}");
                let mut body = String::new();
                if let Some(q) = quarantine_id {
                    body.push_str(&format!(
                        "{} {q}. {} „wachposten restore {q}“.",
                        tr("In Quarantäne als Nr.", "Quarantined as no."),
                        tr("Zurückholen mit", "Bring it back with")
                    ));
                }
                if kind == Some(Kind::Autostart) {
                    body.push_str(tr(
                        "\nEin schon laufendes Programm läuft bis zur Abmeldung weiter.",
                        "\nA program that already runs keeps running until you log out.",
                    ));
                }
                notify::info(tr("Entfernt", "Removed"), &body, "security-high");
            }
            Err(e) => match e.downcast_ref::<DecisionError>() {
                Some(DecisionError::AlreadyResolved(_)) => {}
                Some(DecisionError::Stale) => {
                    notify::info(
                        tr("Erneut geändert", "Changed again"),
                        tr(
                            "Der Eintrag hat sich seit der Meldung geändert. Bitte entscheide anhand der neuen Meldung.",
                            "The entry changed since this message. Please decide on the new message.",
                        ),
                        "security-medium",
                    );
                    self.rescan()?;
                }
                _ => {
                    log::error!("decision on event {id} failed: {e:#}");
                    notify::info(tr("Fehler", "Error"), &format!("{e:#}"), "dialog-error");
                }
            },
        }
        self.refresh()
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = Config::from_env()?;
    let mut guard = Guard::open(config.clone())?;

    let lock = File::create(config.lock_path()).context("cannot create lock file")?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            log::info!("another wachposten-agent is running");
            return Ok(());
        }
        Err(TryLockError::Error(e)) => return Err(e).context("cannot lock"),
    }

    let settings = Settings::load(&config.home).unwrap_or_else(|e| {
        log::error!("{e:#}; using default settings");
        notify::info(
            tr("Einstellungen fehlerhaft", "Settings invalid"),
            &format!("{e:#}"),
            "dialog-error",
        );
        Settings::default()
    });
    let scanner = Arc::new(MalwareScanner::from_settings(&settings, &config.data_dir));
    if let Some(yara) = &scanner.yara {
        log::info!("YARA-X: {} rules", yara.rule_count());
    }
    guard.set_scanner(scanner.clone());

    let first_run = !guard.is_initialized()?;
    if first_run {
        let count = guard.initialize()?;
        log::info!("baseline recorded with {count} entries");
        notify::info(
            tr("Wachposten ist aktiv", "Wachposten is active"),
            &format!(
                "{count} {}",
                tr(
                    "Einträge in Autostart, Diensten, Shell-Dateien, SSH und cron werden jetzt überwacht.",
                    "entries in autostart, services, shell files, SSH and cron are now watched.",
                )
            ),
            "security-high",
        );
    }

    let (tx, rx) = mpsc::channel();
    let watch_tx = tx.clone();
    let watch = wachposten_watch::spawn(move || {
        let _ = watch_tx.send(Msg::Changed);
    })?;
    watch.set_specs(guard.watch_specs());

    if settings.downloads.enabled {
        spawn_download_scanner(&settings, &config, scanner.clone(), tx.clone())?;
    }
    if let Some(key) = settings.hashes.malwarebazaar_auth_key.clone() {
        spawn_hash_updates(scanner.clone(), key, settings.hashes.update_hours);
    }

    let tick_tx = tx.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(TICK);
            if tick_tx.send(Msg::Tick).is_err() {
                break;
            }
        }
    });

    let tray = match (tray::Tray {
        open: Vec::new(),
        tx: tx.clone(),
    })
    .spawn()
    {
        Ok(h) => Some(h),
        Err(e) => {
            log::warn!("no tray icon: {e}");
            None
        }
    };

    let mut agent = Agent {
        guard,
        tx,
        tray,
        watch,
    };
    // Changes made while the agent was not running.
    let offline = agent.guard.rescan()?;
    if !first_run {
        agent.show_open()?;
    } else {
        agent.ask(&offline);
    }
    agent.refresh()?;

    for msg in rx {
        let result = match msg {
            Msg::Changed | Msg::Tick | Msg::Rescan => agent.rescan(),
            Msg::ShowOpen => agent.show_open(),
            Msg::Detection { path, findings } => agent.detection(&path, &findings),
            Msg::Decide { id, hash, decision } => agent.decide(id, &hash, decision),
            Msg::Quit => break,
        };
        if let Err(e) = result {
            log::error!("{e:#}");
        }
    }
    if let Some(tray) = agent.tray.take() {
        tray.shutdown().wait();
    }
    Ok(())
}

/// Scan finished downloads in a worker thread; detections go to the main loop.
fn spawn_download_scanner(
    settings: &Settings,
    config: &Config,
    scanner: Arc<MalwareScanner>,
    tx: Sender<Msg>,
) -> Result<()> {
    let (file_tx, file_rx) = mpsc::channel::<PathBuf>();
    thread::Builder::new().name("scan".into()).spawn(move || {
        for path in file_rx {
            let findings = scanner.scan(&path);
            log::info!("scanned {}: {} findings", path.display(), findings.len());
            if !findings.is_empty() && tx.send(Msg::Detection { path, findings }).is_err() {
                break;
            }
        }
    })?;
    wachposten_watch::files::spawn_files(settings.download_dirs(&config.home), move |path| {
        let _ = file_tx.send(path);
    })?;
    Ok(())
}

/// Fetch the recent MalwareBazaar hashes now and then. The list covers 48 hours, so an
/// interval below that loses nothing.
fn spawn_hash_updates(scanner: Arc<MalwareScanner>, key: String, hours: u64) {
    let interval = Duration::from_secs(hours.clamp(1, 24) * 3600);
    thread::spawn(move || {
        let Some(db) = scanner.hashes.as_ref() else {
            return;
        };
        loop {
            let last: i64 = db
                .meta("updated_at")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let now = wachposten_core::store::now();
            let due = last + interval.as_secs() as i64;
            if now >= due {
                match wachposten_scan::bazaar::update_recent(db, &key) {
                    Ok((got, new)) => log::info!("MalwareBazaar: {got} hashes, {new} new"),
                    Err(e) => log::warn!("{e:#}"),
                }
                thread::sleep(interval);
            } else {
                thread::sleep(Duration::from_secs((due - now) as u64));
            }
        }
    });
}
