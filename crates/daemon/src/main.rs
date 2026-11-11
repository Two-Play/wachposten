//! `wachposten-daemon`: runs as root. Watches system-wide persistence locations and program
//! starts from temporary folders, and tells the agents of logged-in people about them.

mod ebpf;
mod exec;
mod proc;
mod ransom;
mod server;
mod users;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use wachposten_core::i18n::tr;
use wachposten_core::ipc::{self, Decision, Reply, Request};
use wachposten_core::settings::{DAEMON_SETTINGS, DaemonSettings, ExecPopup, RansomAction};
use wachposten_core::{Config, Event, FileReport, Finding, Guard, Kind, Outcome, Severity, Status};
use wachposten_scan::{HashDb, MalwareScanner, YaraEngine, hash_db_path};

use crate::exec::{ExecReport, ExecStatus};
use crate::server::Client;

const TICK: Duration = Duration::from_secs(60);
/// While a package transaction runs, checks are retried this often.
const BUSY_RETRY: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    name = "wachposten-daemon",
    version,
    about = "Wachposten system daemon (runs as root)"
)]
struct Args {
    #[arg(long, default_value = DAEMON_SETTINGS)]
    config: PathBuf,
    #[arg(long, default_value = "/var/lib/wachposten")]
    state_dir: PathBuf,
    #[arg(long, default_value = ipc::SOCKET)]
    socket: PathBuf,
    /// Do not watch program starts (no fanotify).
    #[arg(long)]
    no_exec: bool,
}

pub enum Msg {
    Rescan,
    Tick,
    Exec(ExecReport),
    /// A process seems to encrypt files (from the eBPF part).
    Ransom(ransom::Alarm),
    Subscribe(Client),
    Request {
        uid: u32,
        admin: bool,
        request: Request,
        reply: Sender<Reply>,
    },
}

struct Daemon {
    guard: Guard,
    scanner: Arc<MalwareScanner>,
    settings: DaemonSettings,
    clients: Vec<Client>,
    exec: ExecStatus,
    rescan_waiting: Arc<AtomicBool>,
    tx: Sender<Msg>,
    ticks: u64,
    writers: ebpf::SharedWriters,
    ebpf: bool,
}

fn can_see(ev: &Event, uid: u32, admin: bool) -> bool {
    admin || ev.uid.is_none() || ev.uid == Some(uid)
}

fn can_decide(ev: &Event, uid: u32, admin: bool) -> bool {
    admin || (ev.kind.is_program() && ev.uid == Some(uid))
}

fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

impl Daemon {
    fn open_ids(&self) -> BTreeSet<i64> {
        self.guard
            .store()
            .open_events()
            .map(|v| v.into_iter().map(|e| e.id).collect())
            .unwrap_or_default()
    }

    /// Send an event to every subscribed agent that may see it; drop agents that went away.
    fn push(&mut self, ev: &Event) {
        let ev = ipc::strip(ev.clone());
        self.clients.retain_mut(|c| {
            if !can_see(&ev, c.uid, c.admin) {
                return true;
            }
            c.send(&Reply::Event {
                event: ev.clone(),
                can_decide: can_decide(&ev, c.uid, c.admin),
            })
        });
    }

    fn push_ids(&mut self, ids: impl IntoIterator<Item = i64>) {
        for id in ids {
            if let Ok(Some(ev)) = self.guard.store().event(id) {
                self.push(&ev);
            }
        }
    }

    fn rescan(&mut self) -> Result<()> {
        if wachposten_core::pkg::manager_busy() {
            if !self.rescan_waiting.swap(true, Ordering::SeqCst) {
                log::info!("package transaction running; checking again later");
                let tx = self.tx.clone();
                let flag = self.rescan_waiting.clone();
                thread::spawn(move || {
                    thread::sleep(BUSY_RETRY);
                    flag.store(false, Ordering::SeqCst);
                    let _ = tx.send(Msg::Rescan);
                });
            }
            return Ok(());
        }
        let before = self.open_ids();
        let mut events = self.guard.rescan()?;
        let after = self.open_ids();
        for ev in &mut events {
            let writer = self
                .writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recent(Path::new(&ev.path))
                .map(ebpf::Writer::describe);
            if let Some(actor) = writer {
                self.guard.store().set_actor(ev.id, &actor)?;
                ev.actor = Some(actor);
            }
        }
        for ev in &events {
            log::info!(
                "event {}: {} {} ({})",
                ev.id,
                ev.change.as_str(),
                ev.path,
                ev.severity.as_str()
            );
            self.push(ev);
        }
        // Events closed without a decision (undone, deleted) reach the agents as well.
        self.push_ids(before.difference(&after).copied().collect::<Vec<_>>());
        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        self.ticks += 1;
        if self.ticks % (24 * 60) == 1 {
            let days = self.settings.exec.history_days.max(1) as i64;
            let n = self
                .guard
                .store()
                .prune_history(Kind::TempExec, days * 86400)?;
            if n > 0 {
                log::info!("removed {n} old program start records");
            }
        }
        self.rescan()
    }

    /// Stop a process that seems to encrypt files, together with the other processes of the
    /// same program or script, and ask its owner.
    fn ransom(&mut self, alarm: ransom::Alarm) -> Result<()> {
        let pid = alarm.pid as i32;
        let info = proc::info(pid);
        if info.comm.is_empty() {
            return Ok(()); // already gone
        }
        let mut target = proc::target_of(pid);
        // A program of the system (gpg, openssl, 7z …) is not removed or allowed as a whole:
        // decide on this one process.
        if !target.starts_with("/proc") && wachposten_core::pkg::installed_unchanged(&target) {
            target = PathBuf::from(format!("/proc/{pid}/exe"));
        }
        let decoy = matches!(alarm.reason, ransom::Reason::Decoy(_));
        let cfg = &self.settings.ransomware;
        if !decoy && cfg.ignore.iter().any(|p| p == &target) {
            log::info!("ransomware check: {} is ignored", target.display());
            return Ok(());
        }
        let mut pids = vec![pid];
        if !target.starts_with("/proc") {
            pids.extend(
                proc::processes_of(&target)
                    .into_iter()
                    .filter(|p| *p != pid),
            );
        }
        let protected = pids.iter().any(|p| proc::is_protected(*p));
        let stop = cfg.action == RansomAction::Stop && !protected;
        // Stop first: every second counts. An allowed program is continued right after.
        if stop {
            proc::signal_all(&pids, nix::sys::signal::Signal::SIGSTOP);
        }
        let mut details = vec![alarm.reason.describe()];
        details.push(if stop {
            format!(
                "{}: {}",
                tr("Angehalten", "Stopped"),
                pids.iter()
                    .map(|p| format!("PID {p}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            tr(
                "Läuft weiter (nur gemeldet)",
                "Still running (only reported)",
            )
            .to_string()
        });
        let mut who = format!(
            "{} (PID {pid}, {})",
            info.comm,
            info.uid.map(users::name).unwrap_or_default()
        );
        if !info.cmdline.is_empty() {
            who.push_str(&format!(" – {}", shorten(&info.cmdline, 160)));
        }
        if let (Some(ppid), Some(parent)) = (info.ppid, &info.parent_comm) {
            who.push_str(&format!(" ← {parent} (PID {ppid})"));
        }
        details.push(format!("{}: {who}", tr("Prozess", "Process")));
        details.push(format!(
            "{} ({}):",
            tr("Betroffene Dateien", "Affected files"),
            alarm.count
        ));
        details.extend(
            alarm
                .files
                .iter()
                .take(5)
                .map(|f| format!("  {}", f.display())),
        );
        let findings = [Finding {
            rule: if decoy { "decoy" } else { "ransomware" }.into(),
            line: alarm.reason.describe(),
        }];
        let event = self.guard.record_file(&FileReport {
            path: &target,
            kind: Kind::Ransomware,
            severity: Severity::Malicious,
            ask: true,
            findings: &findings,
            details: &details,
            uid: info.uid,
            even_if_allowed: decoy,
        })?;
        match event {
            Some(ev) => {
                log::warn!(
                    "ransomware {}: {} ({}), stopped: {stop}",
                    ev.id,
                    target.display(),
                    alarm.reason.describe()
                );
                self.push(&ev);
            }
            None if stop
                && self
                    .guard
                    .store()
                    .open_event_for(&target.to_string_lossy())?
                    .is_none() =>
            {
                // Allowed before (a backup tool, say): let it go on.
                log::info!("ransomware check: {} was allowed before", target.display());
                proc::signal_all(&pids, nix::sys::signal::Signal::SIGCONT);
            }
            None => {}
        }
        Ok(())
    }

    fn exec(&mut self, report: ExecReport) -> Result<()> {
        // A program started from memory has no folder; it is reported through /proc/<pid>/exe.
        let from_memory = report
            .via
            .as_deref()
            .is_some_and(|v| v.starts_with("/memfd:"));
        let Some(root) =
            exec::temp_root(&report.path).or_else(|| from_memory.then(|| PathBuf::from("/proc")))
        else {
            return Ok(());
        };
        let mut findings = report.findings.clone();
        for reason in exec::suspicious(&report.path, &root) {
            findings.push(Finding {
                rule: reason.into(),
                line: report.path.display().to_string(),
            });
        }
        let severity = wachposten_core::severity_for(&findings);
        let severity = if severity == Severity::Notice {
            Severity::Info
        } else {
            severity
        };
        let ask = report.blocked
            || match self.settings.exec.popup {
                ExecPopup::Always => true,
                ExecPopup::Suspicious => severity >= Severity::Suspicious,
                ExecPopup::Malware => severity == Severity::Malicious,
            };
        let p = &report.proc;
        let mut details = Vec::new();
        if let Some(via) = &report.via {
            if via.starts_with("/memfd:") {
                details.push(format!(
                    "{}: {via}",
                    tr("Aus dem Arbeitsspeicher gestartet", "Started from memory")
                ));
            } else {
                details.push(format!(
                    "{}: {via}",
                    tr("Über Interpreter", "Through interpreter")
                ));
            }
        }
        if report.blocked {
            details.push(tr("Der Start wurde blockiert.", "The start was blocked.").to_string());
        }
        if !p.comm.is_empty() {
            details.push(format!(
                "{} {} (PID {}), {} {}",
                tr("Prozess", "Process"),
                p.comm,
                p.pid,
                tr("Benutzer", "user"),
                p.uid.map_or_else(|| "?".into(), users::name)
            ));
        }
        if !p.cmdline.is_empty() {
            details.push(format!(
                "{}: {}",
                tr("Befehl", "Command"),
                shorten(&p.cmdline, 200)
            ));
        }
        if let (Some(ppid), Some(parent)) = (p.ppid, &p.parent_comm) {
            details.push(format!(
                "{}: {parent} (PID {ppid})",
                tr("Gestartet von", "Started by")
            ));
        }
        let uid = p.uid.or_else(|| {
            std::fs::metadata(&report.path)
                .ok()
                .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        });
        let event = self.guard.record_file(&FileReport {
            path: &report.path,
            kind: Kind::TempExec,
            severity,
            ask,
            findings: &findings,
            details: &details,
            uid,
            even_if_allowed: false,
        })?;
        if let Some(ev) = event {
            if ev.status == Status::Open {
                log::warn!(
                    "program start {}: {} ({})",
                    ev.id,
                    ev.path,
                    ev.severity.as_str()
                );
                self.push(&ev);
            } else {
                log::debug!("program start recorded: {}", ev.path);
            }
        }
        Ok(())
    }

    fn subscribe(&mut self, mut client: Client) {
        let hello = Reply::Hello {
            version: env!("CARGO_PKG_VERSION").into(),
            admin: client.admin,
        };
        if !client.send(&hello) {
            return;
        }
        for ev in self.guard.store().open_events().unwrap_or_default() {
            if can_see(&ev, client.uid, client.admin)
                && !client.send(&Reply::Event {
                    can_decide: can_decide(&ev, client.uid, client.admin),
                    event: ipc::strip(ev),
                })
            {
                return;
            }
        }
        log::info!(
            "agent of {} connected{}",
            users::name(client.uid),
            if client.admin { " (admin)" } else { "" }
        );
        self.clients.push(client);
    }

    fn request(&mut self, uid: u32, admin: bool, request: Request) -> Reply {
        match self.request_inner(uid, admin, request) {
            Ok(reply) => reply,
            Err(e) => Reply::Error {
                message: format!("{e:#}"),
            },
        }
    }

    fn request_inner(&mut self, uid: u32, admin: bool, request: Request) -> Result<Reply> {
        Ok(match request {
            Request::Subscribe => Reply::Error {
                message: "subscribe on a connection of its own".into(),
            },
            Request::Status => {
                let snapshots = ransom::home_snapshots();
                Reply::Status {
                    baseline: self.guard.store().baseline_count()?,
                    open: self
                        .guard
                        .store()
                        .open_events()?
                        .iter()
                        .filter(|e| can_see(e, uid, admin))
                        .count() as i64,
                    exec_watch: self.exec.watching,
                    blocking: self.exec.blocking,
                    yara_rules: self.scanner.yara.as_ref().map_or(0, YaraEngine::rule_count),
                    known_hashes: self
                        .scanner
                        .hashes
                        .as_ref()
                        .and_then(|h| h.count().ok())
                        .unwrap_or(0),
                    clamav: self
                        .scanner
                        .clamav
                        .as_ref()
                        .is_some_and(|c| c.ping().is_ok()),
                    ebpf: self.ebpf,
                    ransomware: self.ebpf && self.settings.ransomware.enabled,
                    home_btrfs: snapshots.0,
                    snapshots: snapshots.1.map(str::to_string),
                }
            }
            Request::WhoWrote { paths } => {
                let home = users::home(uid);
                let writers = self.writers.lock().unwrap_or_else(|e| e.into_inner());
                Reply::Writers {
                    writers: paths
                        .iter()
                        .map(|p| {
                            let path = Path::new(p);
                            let mine = home.as_ref().is_some_and(|h| path.starts_with(h));
                            (admin || mine)
                                .then(|| writers.recent(path).map(ebpf::Writer::describe))
                                .flatten()
                        })
                        .collect(),
                }
            }
            Request::Allowlist => Reply::Allowlist {
                items: if admin {
                    self.guard.store().allowlist()?
                } else {
                    Vec::new()
                },
            },
            Request::Revoke { hash } => {
                if !admin {
                    return Ok(Reply::Error {
                        message: "only admins may change the system allowlist".into(),
                    });
                }
                if self.guard.store().revoke_hash(&hash)? {
                    log::info!("allowed hash {hash} revoked by {}", users::name(uid));
                }
                Reply::Done {
                    message: "revoked".into(),
                }
            }
            Request::Events { all, limit } => {
                let events = if all {
                    self.guard.store().recent_events(limit.clamp(1, 1000))?
                } else {
                    self.guard.store().open_events()?
                };
                Reply::Events {
                    events: events
                        .into_iter()
                        .filter(|e| can_see(e, uid, admin))
                        .map(ipc::strip)
                        .collect(),
                }
            }
            Request::Show { id } => match self.guard.store().event(id)? {
                Some(ev) if can_see(&ev, uid, admin) => Reply::Event {
                    can_decide: can_decide(&ev, uid, admin),
                    event: ipc::strip(ev),
                },
                _ => Reply::Error {
                    message: format!("event {id} does not exist"),
                },
            },
            Request::Decide { id, hash, decision } => {
                let Some(ev) = self.guard.store().event(id)? else {
                    return Ok(Reply::Error {
                        message: format!("event {id} does not exist"),
                    });
                };
                if !can_decide(&ev, uid, admin) {
                    return Ok(Reply::Error {
                        message: "only admins may decide on this".into(),
                    });
                }
                let outcome = match decision {
                    Decision::Allow => {
                        let outcome = self.guard.allow(id, hash.as_deref())?;
                        if ev.kind == Kind::Ransomware {
                            let pids = proc::processes_of(Path::new(&ev.path));
                            let n = proc::signal_all(&pids, nix::sys::signal::Signal::SIGCONT);
                            log::info!("continued {n} processes of {}", ev.path);
                        }
                        outcome
                    }
                    Decision::Remove => {
                        if ev.kind == Kind::Ransomware {
                            let pids = proc::processes_of(Path::new(&ev.path));
                            let n = proc::signal_all(&pids, nix::sys::signal::Signal::SIGKILL);
                            log::info!("ended {n} processes of {}", ev.path);
                        } else if ev.kind == Kind::TempExec {
                            let n = proc::kill_program(Path::new(&ev.path));
                            log::info!("ended {n} processes of {}", ev.path);
                        }
                        self.guard.remove(id, hash.as_deref())?
                    }
                };
                log::info!("event {id} {:?} by {}", decision, users::name(uid));
                self.push_ids([id]);
                Reply::Done {
                    message: match outcome {
                        Outcome::Allowed => format!("event {id} allowed"),
                        Outcome::Removed {
                            quarantine_id: Some(q),
                        } => format!("event {id} removed; quarantine item {q}"),
                        Outcome::Removed {
                            quarantine_id: None,
                        } => {
                            format!("event {id} removed")
                        }
                    },
                }
            }
            Request::Quarantine => {
                if !admin {
                    return Ok(Reply::Error {
                        message: "only admins may see the system quarantine".into(),
                    });
                }
                Reply::Quarantine {
                    items: self.guard.store().quarantine_items()?,
                }
            }
            Request::Restore { id, force } => {
                if !admin {
                    return Ok(Reply::Error {
                        message: "only admins may restore".into(),
                    });
                }
                let path = self.guard.restore(id, force)?;
                log::info!("quarantine item {id} restored by {}", users::name(uid));
                Reply::Done {
                    message: format!("restored {path}"),
                }
            }
        })
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let settings = DaemonSettings::load(&args.config)?;

    let mut guard = Guard::open(Config::system(args.state_dir.clone()))?;
    let hashes = match HashDb::open(&hash_db_path(&args.state_dir)) {
        Ok(db) => Some(db),
        Err(e) => {
            log::error!("hash list unavailable: {e:#}");
            None
        }
    };
    let yara = settings
        .yara
        .enabled
        .then(|| YaraEngine::new(&settings.yara.extra_rule_dirs));
    let online_key = settings
        .hashes
        .online_lookup
        .then(|| settings.hashes.malwarebazaar_auth_key.clone())
        .flatten();
    let scanner =
        Arc::new(MalwareScanner::new(yara, hashes, online_key, 256).with_clamav(&settings.clamav));
    guard.set_scanner(scanner.clone());

    if !guard.is_initialized()? {
        let n = guard.initialize()?;
        log::info!("baseline recorded with {n} system entries");
    }

    let (tx, rx) = mpsc::channel();
    let watch_tx = tx.clone();
    let watch = wachposten_watch::spawn(move || {
        let _ = watch_tx.send(Msg::Rescan);
    })?;
    watch.set_specs(guard.watch_specs());

    let exec = if settings.exec.enabled && !args.no_exec {
        match exec::start(&settings.exec, scanner.clone(), tx.clone()) {
            Ok(status) => status,
            Err(e) => {
                log::error!("{e:#}; program starts are not watched");
                ExecStatus::default()
            }
        }
    } else {
        ExecStatus::default()
    };
    log::info!(
        "program starts: {}, blocking known malware: {}",
        exec.watching,
        exec.blocking
    );

    let writers = ebpf::SharedWriters::default();
    let ebpf_on = settings.exec.ebpf
        && !args.no_exec
        && match ebpf::start(
            tx.clone(),
            scanner.clone(),
            writers.clone(),
            settings.ransomware.enabled.then(|| ransom::Limits {
                files: settings.ransomware.files.max(5),
                window: Duration::from_secs(settings.ransomware.window_secs.max(2)),
            }),
        ) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("{e:#}; scripts, memory programs and writers are not watched");
                false
            }
        };

    if let Some(key) = settings.hashes.malwarebazaar_auth_key.clone() {
        wachposten_scan::spawn_hash_updates(scanner.clone(), key, settings.hashes.update_hours);
    }

    server::listen(&args.socket, settings.admin_groups.clone(), tx.clone())?;

    let tick_tx = tx.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(TICK);
            if tick_tx.send(Msg::Tick).is_err() {
                break;
            }
        }
    });

    let mut daemon = Daemon {
        guard,
        scanner,
        settings,
        clients: Vec::new(),
        exec,
        rescan_waiting: Arc::default(),
        tx,
        ticks: 0,
        writers,
        ebpf: ebpf_on,
    };
    daemon.rescan()?;
    log::info!("listening on {}", args.socket.display());

    for msg in rx {
        let rescanned = matches!(msg, Msg::Rescan | Msg::Tick);
        let result = match msg {
            Msg::Rescan => daemon.rescan(),
            Msg::Tick => daemon.tick(),
            Msg::Exec(report) => daemon.exec(report),
            Msg::Ransom(alarm) => daemon.ransom(alarm),
            Msg::Subscribe(client) => {
                daemon.subscribe(client);
                Ok(())
            }
            Msg::Request {
                uid,
                admin,
                request,
                reply,
            } => {
                let answer = daemon.request(uid, admin, request);
                let _ = reply.send(answer);
                Ok(())
            }
        };
        if let Err(e) = result {
            log::error!("{e:#}");
        }
        if rescanned {
            watch.set_specs(daemon.guard.watch_specs());
        }
    }
    Ok(())
}
