//! `wachposten-agent`: watches the persistence locations in the home directory and asks the
//! person at the computer about every new or changed entry.

mod decoys;
mod notify;
mod tray;

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, TryLockError};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use wachposten_core::i18n::tr;
use wachposten_core::ipc::{self, Reply, Request};
use wachposten_core::{
    Config, DecisionError, Event, FileScanner, Finding, Guard, Kind, Outcome, Settings, Status,
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
    OpenWindow,
    /// A file in a download folder matched a malware signature or hash.
    Detection {
        path: PathBuf,
        findings: Vec<Finding>,
    },
    Decide {
        id: i64,
        hash: String,
        decision: Decision,
        /// The event belongs to the root daemon.
        system: bool,
    },
    /// An event from the root daemon, new or changed.
    Remote {
        event: Box<Event>,
        can_decide: bool,
    },
    DaemonConnected {
        admin: bool,
    },
    DaemonLost,
    /// Answer of the daemon to a decision.
    RemoteResult {
        decision: Decision,
        reply: Box<Reply>,
    },
    Quit,
}

struct Agent {
    guard: Guard,
    tx: Sender<Msg>,
    tray: Option<ksni::blocking::Handle<tray::Tray>>,
    watch: wachposten_watch::WatchHandle,
    /// Open events of the root daemon and whether this person may decide on them.
    remote: BTreeMap<i64, (Event, bool)>,
    /// Daemon events already shown, by id and state, so a reconnect does not repeat them.
    remote_seen: HashSet<(i64, String)>,
    weekly_report: bool,
}

const WEEK: i64 = 7 * 86400;
const LAST_REPORT: &str = "last_weekly_report";

impl Agent {
    /// Once a week, a short summary of what happened. The first week starts with the agent.
    fn weekly_report(&self) -> Result<()> {
        if !self.weekly_report {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let store = self.guard.store();
        let Some(last) = store.meta(LAST_REPORT)?.and_then(|v| v.parse::<i64>().ok()) else {
            store.set_meta(LAST_REPORT, &now.to_string())?;
            return Ok(());
        };
        if now - last < WEEK {
            return Ok(());
        }
        let mut summary = wachposten_core::report::Summary::of(&store.events_since(last)?);
        summary.open += self.remote.len();
        let (title, text) = summary.weekly_text();
        notify::info(&title, &text, "security-high");
        store.set_meta(LAST_REPORT, &now.to_string())?;
        Ok(())
    }

    /// Tell the person about new or changed events, as loud as each one deserves.
    fn ask(&self, events: &[Event]) {
        for ev in events {
            self.tell(ev, false, true);
        }
    }

    fn tell(&self, ev: &Event, system: bool, can_decide: bool) {
        let home = &self.guard.config().home;
        if ev.wants_popup() {
            notify::ask(home, ev, self.tx.clone(), system, can_decide);
        } else if ev.decidable() {
            notify::passive(home, ev, self.tx.clone(), system);
        }
    }

    fn refresh(&self) -> Result<()> {
        let open = self.guard.store().open_events()?;
        let mut items: Vec<tray::OpenItem> = self
            .remote
            .values()
            .map(|(ev, can)| tray::OpenItem::from_event(ev, true, *can))
            .collect();
        items.extend(
            open.iter()
                .map(|ev| tray::OpenItem::from_event(ev, false, true)),
        );
        if let Some(tray) = &self.tray {
            tray.update(|t| t.open = items);
        }
        self.watch.set_specs(self.guard.watch_specs());
        Ok(())
    }

    fn rescan(&mut self) -> Result<()> {
        let mut events = self.guard.rescan()?;
        self.attribute(&mut events);
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

    fn remote_event(&mut self, ev: Event, can_decide: bool) -> Result<()> {
        let key = (ev.id, ev.new_hash().to_string());
        if ev.status != Status::Open {
            if ev.status == Status::Noted && self.remote_seen.insert(key) {
                self.tell(&ev, true, can_decide);
            }
            self.remote.remove(&ev.id);
            return self.refresh();
        }
        if self.remote_seen.insert(key) {
            self.tell(&ev, true, can_decide);
        }
        self.remote.insert(ev.id, (ev, can_decide));
        self.refresh()
    }

    /// Send a decision to the daemon without blocking the main loop.
    fn decide_remote(&self, id: i64, hash: String, decision: Decision) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            let request = Request::Decide {
                id,
                hash: Some(hash),
                decision: match decision {
                    Decision::Allow => ipc::Decision::Allow,
                    Decision::Remove => ipc::Decision::Remove,
                },
            };
            let reply = ipc::call(&socket_path(), &request).unwrap_or_else(|e| Reply::Error {
                message: format!("{e}"),
            });
            let _ = tx.send(Msg::RemoteResult {
                decision,
                reply: Box::new(reply),
            });
        });
    }

    fn remote_result(&self, decision: Decision, reply: &Reply) {
        match reply {
            Reply::Done { message } => {
                log::info!("daemon: {message}");
                if let Decision::Remove = decision {
                    notify::info(tr("Entfernt", "Removed"), message, "security-high");
                }
            }
            Reply::Error { message } if message.contains("already handled") => {}
            Reply::Error { message } => {
                notify::info(tr("Fehler", "Error"), message, "dialog-error");
            }
            _ => {}
        }
    }

    /// Ask the daemon which programs made these changes. Without a daemon nothing happens.
    fn attribute(&self, events: &mut [Event]) {
        let paths: Vec<String> = events
            .iter()
            .filter(|e| e.actor.is_none() && !e.path.starts_with("crontab:"))
            .map(|e| e.path.clone())
            .collect();
        if paths.is_empty() {
            return;
        }
        let Ok(Reply::Writers { writers }) = ipc::call(
            &socket_path(),
            &Request::WhoWrote {
                paths: paths.clone(),
            },
        ) else {
            return;
        };
        for (path, writer) in paths.iter().zip(writers) {
            let Some(actor) = writer else { continue };
            for ev in events.iter_mut().filter(|e| &e.path == path) {
                if self.guard.store().set_actor(ev.id, &actor).is_ok() {
                    ev.actor = Some(actor.clone());
                }
            }
        }
    }

    /// Ask again about open events: questions only for the dangerous ones, a single line for
    /// the rest that waits in the tray.
    fn show_open(&self) -> Result<()> {
        let home = &self.guard.config().home;
        let mut quiet = 0;
        for (ev, can) in self.remote.values() {
            if ev.wants_popup() {
                notify::ask(home, ev, self.tx.clone(), true, *can);
            } else {
                quiet += 1;
            }
        }
        let (loud, rest): (Vec<Event>, Vec<Event>) = self
            .guard
            .store()
            .open_events()?
            .into_iter()
            .partition(Event::wants_popup);
        quiet += rest.len();
        let skipped = loud.len().saturating_sub(MAX_STARTUP_QUESTIONS);
        for ev in &loud[skipped..] {
            notify::ask(home, ev, self.tx.clone(), false, true);
        }
        if quiet + skipped > 0 {
            notify::info(
                &format!(
                    "{} {}",
                    quiet + skipped,
                    tr("offene Meldungen", "open alerts")
                ),
                tr(
                    "Die Liste findest du im Tray-Menü oder mit „wachposten events“.",
                    "See the tray menu or run \"wachposten events\".",
                ),
                "security-medium",
            );
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
    match decoys::apply(&config.home, settings.decoys) {
        Ok(0) => {}
        Ok(n) => log::info!("{n} decoy files in place"),
        Err(e) => log::warn!("cannot set up decoy files: {e:#}"),
    }
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
        wachposten_scan::spawn_hash_updates(scanner.clone(), key, settings.hashes.update_hours);
    }
    wachposten_scan::spawn_clamav_rechecks(scanner.clone());

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

    spawn_daemon_client(tx.clone());

    let mut agent = Agent {
        guard,
        tx,
        tray,
        watch,
        remote: BTreeMap::new(),
        remote_seen: HashSet::new(),
        weekly_report: settings.weekly_report,
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
            Msg::Tick => agent.weekly_report().and_then(|()| agent.rescan()),
            Msg::Changed | Msg::Rescan => agent.rescan(),
            Msg::ShowOpen => agent.show_open(),
            Msg::OpenWindow => {
                let alerts =
                    !agent.remote.is_empty() || !agent.guard.store().open_events()?.is_empty();
                open_window(alerts);
                Ok(())
            }
            Msg::Detection { path, findings } => agent.detection(&path, &findings),
            Msg::Decide {
                id,
                hash,
                decision,
                system: true,
            } => {
                agent.decide_remote(id, hash, decision);
                Ok(())
            }
            Msg::Decide {
                id, hash, decision, ..
            } => agent.decide(id, &hash, decision),
            Msg::Remote { event, can_decide } => agent.remote_event(*event, can_decide),
            Msg::DaemonConnected { admin } => {
                log::info!(
                    "connected to the daemon{}",
                    if admin { " as admin" } else { "" }
                );
                Ok(())
            }
            Msg::DaemonLost => {
                agent.remote.clear();
                agent.refresh()
            }
            Msg::RemoteResult { decision, reply } => {
                agent.remote_result(decision, &reply);
                Ok(())
            }
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

fn socket_path() -> PathBuf {
    std::env::var_os("WACHPOSTEN_SOCKET").map_or_else(|| PathBuf::from(ipc::SOCKET), PathBuf::from)
}

/// Stay subscribed to the root daemon, reconnecting when it restarts. Without a daemon the
/// agent works on its own.
fn spawn_daemon_client(tx: Sender<Msg>) {
    thread::spawn(move || {
        let mut announced_missing = false;
        loop {
            match follow_daemon(&tx) {
                Ok(()) => log::info!("daemon connection closed"),
                Err(e) if !announced_missing => {
                    log::info!("no daemon ({e}); system-wide watching is off");
                    announced_missing = true;
                }
                Err(_) => {}
            }
            if tx.send(Msg::DaemonLost).is_err() {
                return;
            }
            thread::sleep(Duration::from_secs(15));
        }
    });
}

fn follow_daemon(tx: &Sender<Msg>) -> std::io::Result<()> {
    let stream = UnixStream::connect(socket_path())?;
    let mut writer = stream.try_clone()?;
    ipc::write_line(&mut writer, &Request::Subscribe)?;
    let mut reader = BufReader::new(stream);
    while let Some(reply) = ipc::read_line::<Reply>(&mut reader)? {
        let msg = match reply {
            Reply::Hello { admin, .. } => Msg::DaemonConnected { admin },
            Reply::Event { event, can_decide } => Msg::Remote {
                event: Box::new(event),
                can_decide,
            },
            _ => continue,
        };
        if tx.send(msg).is_err() {
            break;
        }
    }
    Ok(())
}

/// Start the window (`wachposten` next to this program, or from `PATH`).
fn open_window(alerts: bool) {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wachposten")))
        .filter(|p| p.exists());
    let program = beside.unwrap_or_else(|| PathBuf::from("wachposten"));
    let mut cmd = std::process::Command::new(&program);
    cmd.arg("window");
    if alerts {
        cmd.args(["--tab", "alerts"]);
    }
    if let Err(e) = cmd.spawn() {
        log::error!("cannot open the window ({}): {e}", program.display());
    }
}
