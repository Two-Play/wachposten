//! The Slint window: status, alerts, history, quarantine, allowed files and settings. It reads
//! the agent's database directly and asks the root daemon over its socket.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Result;
use chrono::{Local, TimeZone};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use wachposten_core::i18n::{self, Lang, tr};
use wachposten_core::ipc::{self, Reply, Request};
use wachposten_core::scanner::MALWARE_RULE;
use wachposten_core::settings::Decoys;
use wachposten_core::{Config, Event, Guard, Outcome, Settings, Status};
use wachposten_scan::{ClamState, HashDb, MalwareScanner, YaraEngine, hash_db_path};

slint::include_modules!();

/// An event and where it came from.
#[derive(Clone)]
struct Item {
    event: Event,
    system: bool,
    can_decide: bool,
}

struct State {
    guard: Guard,
    home: PathBuf,
    open: HashMap<(bool, i64), Item>,
    history: HashMap<(bool, i64), Item>,
    open_pick: Option<(bool, i64)>,
    history_pick: Option<(bool, i64)>,
    yara_rules: usize,
    local_clamav: ClamState,
}

/// The more useful of the window's own and the daemon's view of ClamAV.
fn best_clam_state(a: ClamState, b: ClamState) -> ClamState {
    let rank = |s: ClamState| match s {
        ClamState::Off => 0,
        ClamState::NotInstalled => 1,
        ClamState::NotRunning => 2,
        ClamState::Running => 3,
    };
    if rank(a) >= rank(b) { a } else { b }
}

fn socket() -> PathBuf {
    std::env::var_os("WACHPOSTEN_SOCKET").map_or_else(|| PathBuf::from(ipc::SOCKET), PathBuf::from)
}

fn daemon(request: &Request) -> Option<Reply> {
    match ipc::call(&socket(), request) {
        Ok(Reply::Error { message }) => {
            log_err(&message);
            None
        }
        Ok(reply) => Some(reply),
        Err(_) => None,
    }
}

fn log_err(message: &str) {
    eprintln!("wachposten: {message}");
}

fn when(ts: i64) -> String {
    Local.timestamp_opt(ts, 0).single().map_or_else(
        || ts.to_string(),
        |t| t.format("%Y-%m-%d %H:%M").to_string(),
    )
}

/// Short time for lists: the time today, day and month this year, the date before.
fn when_short(ts: i64) -> String {
    let Some(t) = Local.timestamp_opt(ts, 0).single() else {
        return ts.to_string();
    };
    let now = Local::now();
    if t.date_naive() == now.date_naive() {
        t.format("%H:%M").to_string()
    } else if t.format("%Y").to_string() == now.format("%Y").to_string() {
        t.format("%d.%m.").to_string()
    } else {
        t.format("%d.%m.%Y").to_string()
    }
}

/// Labels are written for running text; at the start of a line they begin with a capital.
fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Open => tr("offen", "open"),
        Status::Allowed => tr("erlaubt", "allowed"),
        Status::Removed => tr("entfernt", "removed"),
        Status::Reverted => tr("rückgängig gemacht", "undone"),
        Status::Accepted => tr("aufgezeichnet", "recorded"),
        Status::Noted => tr("übernommen", "accepted"),
    }
}

fn pretty(home: &Path, path: &str, system: bool) -> String {
    if system {
        return path.to_string();
    }
    match Path::new(path).strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => i18n::display_name(path),
    }
}

fn row(state: &State, item: &Item) -> EventRow {
    let ev = &item.event;
    EventRow {
        id: ev.id as i32,
        system: item.system,
        title: i18n::event_title(ev).into(),
        path: pretty(&state.home, &ev.path, item.system).into(),
        severity: ev.severity.as_str().into(),
        level: if ev.wants_popup() {
            "danger"
        } else if ev.status == Status::Open {
            "warning"
        } else if ev.status == Status::Noted {
            "hint"
        } else {
            "done"
        }
        .into(),
        kind: capitalized(i18n::kind_label(ev.kind)).into(),
        ransomware: ev.kind == wachposten_core::Kind::Ransomware,
        status: status_label(ev.status).into(),
        when: when_short(ev.updated_at).into(),
        when_full: when(ev.updated_at).into(),
        can_decide: item.can_decide,
        open: ev.decidable(),
        noted: ev.status == Status::Noted,
    }
}

fn strings(v: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        v.into_iter().map(SharedString::from).collect::<Vec<_>>(),
    ))
}

fn detail(state: &State, item: Option<&Item>) -> EventDetail {
    let Some(item) = item else {
        return EventDetail::default();
    };
    let ev = &item.event;
    let findings = ev
        .findings
        .iter()
        .map(|f| {
            if f.rule == MALWARE_RULE {
                f.line.split(" – ").next().unwrap_or(&f.line).to_string()
            } else {
                i18n::rule_label(&f.rule).to_string()
            }
        })
        .collect();
    let lines: Vec<String> = ev
        .added_lines
        .iter()
        .map(|l| {
            if ev.kind.is_file_report() {
                l.clone()
            } else {
                format!("+ {l}")
            }
        })
        .collect();
    EventDetail {
        valid: true,
        row: row(state, item),
        sentence: i18n::event_sentence(ev).into(),
        kind: capitalized(i18n::kind_label(ev.kind)).into(),
        findings: strings(findings),
        lines: strings(lines),
        actor: ev
            .actor
            .as_deref()
            .map_or_else(String::new, |a| {
                format!("{}: {a}", tr("Geändert von", "Changed by"))
            })
            .into(),
        lines_title: if ev.kind.is_file_report() {
            tr("Einzelheiten", "Details")
        } else {
            tr("Neue Zeilen", "Added lines")
        }
        .into(),
    }
}

/// Dangerous events first, then waiting ones, each newest first.
fn order_key(i: &Item) -> (u8, std::cmp::Reverse<(i64, i64)>) {
    let rank = if i.event.wants_popup() {
        0
    } else if i.event.status == Status::Open {
        1
    } else {
        2
    };
    (rank, std::cmp::Reverse((i.event.updated_at, i.event.id)))
}

fn sorted_rows(state: &State, items: &HashMap<(bool, i64), Item>) -> ModelRc<EventRow> {
    let mut v: Vec<&Item> = items.values().collect();
    v.sort_by_key(|i| order_key(i));
    ModelRc::new(VecModel::from(
        v.into_iter().map(|i| row(state, i)).collect::<Vec<_>>(),
    ))
}

fn load(state: &mut State, ui: &AppWindow) -> Result<()> {
    let store = state.guard.store();
    let mut open = HashMap::new();
    let mut history = HashMap::new();
    for ev in store.open_events()? {
        open.insert(
            (false, ev.id),
            Item {
                event: ev,
                system: false,
                can_decide: true,
            },
        );
    }
    for ev in store.recent_events(300)? {
        history.insert(
            (false, ev.id),
            Item {
                event: ev,
                system: false,
                can_decide: true,
            },
        );
    }

    let daemon_status = daemon(&Request::Status);
    let daemon_up = daemon_status.is_some();
    let mut admin = false;
    if daemon_up {
        for (all, target) in [(false, &mut open), (true, &mut history)] {
            if let Some(Reply::Events { events }) = daemon(&Request::Events { all, limit: 300 }) {
                for ev in events {
                    // `Show` tells whether this person may decide.
                    let can_decide = ev.decidable()
                        && matches!(
                            daemon(&Request::Show { id: ev.id }),
                            Some(Reply::Event {
                                can_decide: true,
                                ..
                            })
                        );
                    admin |= can_decide && ev.uid.is_none();
                    target.insert(
                        (true, ev.id),
                        Item {
                            event: ev,
                            system: true,
                            can_decide,
                        },
                    );
                }
            }
        }
    }
    state.open = open;
    state.history = history;

    let local_hashes = HashDb::open(&hash_db_path(&state.guard.config().data_dir))
        .and_then(|h| h.count())
        .unwrap_or(0);
    let settings = Settings::load(&state.home).unwrap_or_default();
    let (exec_watch, blocking, sys_rules, sys_hashes, sys_clam, ebpf) = match &daemon_status {
        Some(Reply::Status {
            exec_watch,
            blocking,
            yara_rules,
            known_hashes,
            clamav,
            ebpf,
            ..
        }) => (
            *exec_watch,
            *blocking,
            *yara_rules,
            *known_hashes,
            *clamav,
            *ebpf,
        ),
        _ => (false, false, 0, 0, false, false),
    };
    let sys_clam_state = match &daemon_status {
        Some(Reply::Status { clamav_state, .. }) => ClamState::parse(clamav_state),
        _ => ClamState::Off,
    };
    let clam_state = best_clam_state(state.local_clamav, sys_clam_state);
    let (ransomware, home_btrfs, snapshots) = match &daemon_status {
        Some(Reply::Status {
            ransomware,
            home_btrfs,
            snapshots,
            ..
        }) => (*ransomware, *home_btrfs, snapshots.clone()),
        _ => (false, false, None),
    };
    ui.set_status(StatusInfo {
        agent: crate::agent_running(state.guard.config()),
        daemon: daemon_up,
        admin,
        exec_watch,
        blocking,
        ebpf,
        ransomware,
        home_btrfs,
        snapshots: snapshots.unwrap_or_default().into(),
        decoys: settings.decoys != Decoys::Off,
        yara_rules: state.yara_rules.max(sys_rules) as i32,
        known_hashes: local_hashes.max(sys_hashes) as i32,
        hash_updates: settings.hashes.malwarebazaar_auth_key.is_some(),
        clamav: clam_state == ClamState::Running || sys_clam,
        clamav_state: match clam_state {
            ClamState::Off => 0,
            ClamState::NotInstalled => 1,
            ClamState::NotRunning => 2,
            ClamState::Running => 3,
        },
        clamav_setup: wachposten_scan::clamav::setup_commands().into(),
        baseline: state.guard.store().baseline_count()? as i32,
        open: state.open.len() as i32,
        danger: state
            .open
            .values()
            .filter(|i| i.event.wants_popup())
            .count() as i32,
    });

    // Without a choice, or when the chosen entry is gone, show the first one of the list.
    if state.open_pick.is_none_or(|k| !state.open.contains_key(&k)) {
        state.open_pick = state
            .open
            .values()
            .min_by_key(|i| order_key(i))
            .map(|i| (i.system, i.event.id));
    }
    if state
        .history_pick
        .is_none_or(|k| !state.history.contains_key(&k))
    {
        state.history_pick = state
            .history
            .values()
            .min_by_key(|i| std::cmp::Reverse((i.event.updated_at, i.event.id)))
            .map(|i| (i.system, i.event.id));
    }
    ui.set_open_rows(sorted_rows(state, &state.open));
    ui.set_history_rows(sorted_rows(state, &state.history));
    let mut recent: Vec<&Item> = state.history.values().collect();
    recent.sort_by_key(|i| std::cmp::Reverse((i.event.updated_at, i.event.id)));
    ui.set_recent_rows(ModelRc::new(VecModel::from(
        recent
            .into_iter()
            .take(5)
            .map(|i| row(state, i))
            .collect::<Vec<_>>(),
    )));
    let open_pick = state.open_pick.and_then(|k| state.open.get(&k));
    ui.set_open_detail(detail(state, open_pick));
    let history_pick = state.history_pick.and_then(|k| state.history.get(&k));
    ui.set_history_detail(detail(state, history_pick));

    let mut quarantine: Vec<(i64, QuarantineRow)> = store_quarantine(state, false)?;
    if let Some(Reply::Quarantine { items }) =
        daemon_up.then(|| daemon(&Request::Quarantine)).flatten()
    {
        quarantine.extend(items.into_iter().map(|q| {
            (
                q.created_at,
                QuarantineRow {
                    id: q.id as i32,
                    system: true,
                    path: q.original_path.into(),
                    kind: i18n::kind_label(q.kind).into(),
                    when: when(q.created_at).into(),
                    restored: q.restored_at.is_some(),
                },
            )
        }));
    }
    quarantine.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    ui.set_quarantine_rows(ModelRc::new(VecModel::from(
        quarantine.into_iter().map(|(_, r)| r).collect::<Vec<_>>(),
    )));

    let mut allowed: Vec<(i64, AllowedRow)> = state
        .guard
        .store()
        .allowlist()?
        .into_iter()
        .map(|a| {
            (
                a.added_at,
                AllowedRow {
                    hash: a.hash.into(),
                    system: false,
                    path: pretty(&state.home, &a.path, false).into(),
                    when: when(a.added_at).into(),
                },
            )
        })
        .collect();
    if let Some(Reply::Allowlist { items }) =
        daemon_up.then(|| daemon(&Request::Allowlist)).flatten()
    {
        allowed.extend(items.into_iter().map(|a| {
            (
                a.added_at,
                AllowedRow {
                    hash: a.hash.into(),
                    system: true,
                    path: a.path.into(),
                    when: when(a.added_at).into(),
                },
            )
        }));
    }
    allowed.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    ui.set_allowed_rows(ModelRc::new(VecModel::from(
        allowed.into_iter().map(|(_, r)| r).collect::<Vec<_>>(),
    )));
    Ok(())
}

fn store_quarantine(state: &State, _system: bool) -> Result<Vec<(i64, QuarantineRow)>> {
    Ok(state
        .guard
        .store()
        .quarantine_items()?
        .into_iter()
        .map(|q| {
            (
                q.created_at,
                QuarantineRow {
                    id: q.id as i32,
                    system: false,
                    path: pretty(&state.home, &q.original_path, false).into(),
                    kind: i18n::kind_label(q.kind).into(),
                    when: when(q.created_at).into(),
                    restored: q.restored_at.is_some(),
                },
            )
        })
        .collect())
}

fn settings_data(settings: &Settings) -> SettingsData {
    SettingsData {
        weekly: settings.weekly_report,
        decoys: match settings.decoys {
            Decoys::Off => 0,
            Decoys::Visible => 1,
            Decoys::Hidden => 2,
        },
        downloads: settings.downloads.enabled,
        yara: settings.yara.enabled,
        rule_dirs: settings
            .yara
            .extra_rule_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .into(),
        key: settings
            .hashes
            .malwarebazaar_auth_key
            .clone()
            .unwrap_or_default()
            .into(),
        online: settings.hashes.online_lookup,
        clamav: settings.clamav.enabled,
    }
}

fn show(ui: &AppWindow, message: impl Into<String>, error: bool) {
    ui.set_message(message.into().into());
    ui.set_message_error(error);
    // Clear after a while; a newer message simply replaces it.
    let weak = ui.as_weak();
    let text = ui.get_message();
    Timer::single_shot(Duration::from_secs(10), move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_message() == text
        {
            ui.set_message("".into());
        }
    });
}

fn reply_message(reply: Option<Reply>) -> (String, bool) {
    match reply {
        Some(Reply::Done { message }) => (message, false),
        Some(Reply::Error { message }) => (message, true),
        Some(_) => (String::new(), false),
        None => (
            tr(
                "Der System-Daemon antwortet nicht.",
                "The system daemon does not answer.",
            )
            .into(),
            true,
        ),
    }
}

/// Like [`daemon`], but keeps the daemon's error text for the message bar.
fn daemon_raw(request: &Request) -> Option<Reply> {
    ipc::call(&socket(), request).ok()
}

pub fn run(tab: Option<&str>, screenshot: Option<&Path>, dark: bool) -> Result<()> {
    let config = Config::from_env()?;
    let home = config.home.clone();
    let guard = Guard::open(config)?;
    let offscreen = screenshot
        .map(|_| {
            let (w, h) = std::env::var("WACHPOSTEN_SHOT_SIZE")
                .ok()
                .and_then(|v| {
                    let (w, h) = v.split_once('x')?;
                    Some((w.parse().ok()?, h.parse().ok()?))
                })
                .unwrap_or((1000, 680));
            crate::shot::install(w, h)
        })
        .transpose()?;
    let ui = AppWindow::new()?;
    if offscreen.is_some() {
        ui.set_force_dark(dark);
    }
    if i18n::lang() == Lang::De {
        let _ = slint::select_bundled_translation("de");
    }
    let pages = [
        "overview",
        "alerts",
        "history",
        "quarantine",
        "allowed",
        "settings",
    ];
    if let Some(i) = tab.and_then(|t| pages.iter().position(|p| *p == t)) {
        ui.set_tab(i as i32);
    }

    let settings = Settings::load(&home).unwrap_or_default();
    let yara_rules = if settings.yara.enabled {
        YaraEngine::new(&settings.yara.extra_rule_dirs).rule_count()
    } else {
        0
    };
    let local_clamav = MalwareScanner::probe_clamav(&settings.clamav);
    ui.set_settings(settings_data(&settings));

    let state = Rc::new(RefCell::new(State {
        guard,
        home,
        open: HashMap::new(),
        history: HashMap::new(),
        open_pick: None,
        history_pick: None,
        yara_rules,
        local_clamav,
    }));

    let refresh = {
        let state = state.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            if let Err(e) = load(&mut state.borrow_mut(), &ui) {
                show(&ui, format!("{e:#}"), true);
            }
        }
    };
    refresh();
    ui.on_refresh(refresh.clone());

    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_pick_open(move |r| {
            state.borrow_mut().open_pick = Some((r.system, r.id as i64));
            refresh();
            let _ = weak;
        });
    }
    {
        let state = state.clone();
        let refresh = refresh.clone();
        ui.on_pick_history(move |r| {
            state.borrow_mut().history_pick = Some((r.system, r.id as i64));
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_decide(move |id, system, allow| {
            let Some(ui) = weak.upgrade() else { return };
            let key = (system, id as i64);
            let hash = {
                let st = state.borrow();
                st.open
                    .get(&key)
                    .or_else(|| st.history.get(&key))
                    .map(|i| i.event.new_hash().to_string())
            };
            let (message, error) = if system {
                reply_message(daemon_raw(&Request::Decide {
                    id: id as i64,
                    hash,
                    decision: if allow {
                        ipc::Decision::Allow
                    } else {
                        ipc::Decision::Remove
                    },
                }))
            } else {
                let mut st = state.borrow_mut();
                let result = if allow {
                    st.guard.allow(id as i64, hash.as_deref())
                } else {
                    st.guard.remove(id as i64, hash.as_deref())
                };
                match result {
                    Ok(Outcome::Allowed) => (tr("Erlaubt.", "Allowed.").into(), false),
                    Ok(Outcome::Removed { quarantine_id }) => (
                        match quarantine_id {
                            Some(q) => format!(
                                "{} {q}.",
                                tr(
                                    "Entfernt, in Quarantäne als Nr.",
                                    "Removed, quarantined as no."
                                )
                            ),
                            None => tr("Entfernt.", "Removed.").into(),
                        },
                        false,
                    ),
                    Err(e) => (format!("{e:#}"), true),
                }
            };
            show(&ui, message, error);
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_restore(move |id, system| {
            let Some(ui) = weak.upgrade() else { return };
            let (message, error) = if system {
                reply_message(daemon_raw(&Request::Restore {
                    id: id as i64,
                    force: false,
                }))
            } else {
                match state.borrow_mut().guard.restore(id as i64, false) {
                    Ok(path) => (
                        format!("{} {path}", tr("Zurückgeholt:", "Put back:")),
                        false,
                    ),
                    Err(e) => (format!("{e:#}"), true),
                }
            };
            show(&ui, message, error);
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_revoke(move |hash, system| {
            let Some(ui) = weak.upgrade() else { return };
            let (message, error) = if system {
                reply_message(daemon_raw(&Request::Revoke {
                    hash: hash.to_string(),
                }))
            } else {
                match state.borrow().guard.store().revoke_hash(&hash) {
                    Ok(_) => (
                        tr("Erlaubnis zurückgenommen.", "Permission revoked.").into(),
                        false,
                    ),
                    Err(e) => (format!("{e:#}"), true),
                }
            };
            show(&ui, message, error);
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.on_export_history(move || {
            let Some(ui) = weak.upgrade() else { return };
            let state = state.borrow();
            let dir = wachposten_core::settings::xdg_download_dir(&state.home);
            let name = format!(
                "wachposten-{}-{}.csv",
                tr("verlauf", "history"),
                Local::now().format("%Y-%m-%d-%H%M")
            );
            let path = dir.join(name);
            let result = crate::export(&state.guard, "csv")
                .and_then(|text| Ok(std::fs::write(&path, text)?));
            match result {
                Ok(()) => show(
                    &ui,
                    format!("{}: {}", tr("Gespeichert", "Saved"), path.display()),
                    false,
                ),
                Err(e) => show(&ui, format!("{e:#}"), true),
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_scan_home(move || {
            let Some(ui) = weak.upgrade() else { return };
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wachposten"));
            match Command::new(exe)
                .args(["scan-file", "--notify", "--home"])
                .stdout(std::process::Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    std::thread::spawn(move || child.wait());
                    show(
                    &ui,
                    tr(
                        "Die Prüfung läuft im Hintergrund. Das Ergebnis kommt als Benachrichtigung.",
                        "The check runs in the background. The result comes as a notification.",
                    ),
                    false,
                    )
                }
                Err(e) => show(&ui, format!("{e:#}"), true),
            }
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_recheck_clamav(move || {
            let Some(ui) = weak.upgrade() else { return };
            let settings = Settings::load(&state.borrow().home).unwrap_or_default();
            state.borrow_mut().local_clamav = MalwareScanner::probe_clamav(&settings.clamav);
            let system = match daemon(&Request::RecheckClamav) {
                Some(Reply::Done { message }) => ClamState::parse(&message),
                _ => ClamState::Off,
            };
            let found = best_clam_state(state.borrow().local_clamav, system);
            show(
                &ui,
                match found {
                    ClamState::Running => {
                        tr("ClamAV läuft und wird genutzt.", "ClamAV runs and is used.")
                    }
                    ClamState::NotRunning => tr(
                        "clamd ist installiert, antwortet aber nicht.",
                        "clamd is installed but does not answer.",
                    ),
                    ClamState::NotInstalled => {
                        tr("clamd ist nicht installiert.", "clamd is not installed.")
                    }
                    ClamState::Off => tr(
                        "ClamAV ist in den Einstellungen aus.",
                        "ClamAV is off in the settings.",
                    ),
                }
                .to_string(),
                found != ClamState::Running,
            );
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let refresh = refresh.clone();
        ui.on_check_now(move || {
            let Some(ui) = weak.upgrade() else { return };
            let result = state.borrow_mut().guard.rescan();
            match result {
                Ok(events) if events.is_empty() => {
                    show(&ui, tr("Keine neuen Änderungen.", "No new changes."), false);
                }
                Ok(events) => {
                    show(
                        &ui,
                        format!("{} {}", events.len(), tr("neue Meldungen.", "new alerts.")),
                        false,
                    );
                    ui.set_tab(1);
                }
                Err(e) => show(&ui, format!("{e:#}"), true),
            }
            refresh();
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.on_save_settings(move |data| {
            let Some(ui) = weak.upgrade() else { return };
            let home = state.borrow().home.clone();
            let result = (|| -> Result<bool> {
                let mut s = Settings::load(&home)?;
                s.downloads.enabled = data.downloads;
                s.yara.enabled = data.yara;
                s.yara.extra_rule_dirs = data
                    .rule_dirs
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
                    .collect();
                let key = data.key.trim().to_string();
                s.hashes.malwarebazaar_auth_key = (!key.is_empty()).then_some(key);
                s.hashes.online_lookup = data.online;
                s.clamav.enabled = data.clamav;
                s.weekly_report = data.weekly;
                s.decoys = match data.decoys {
                    1 => Decoys::Visible,
                    2 => Decoys::Hidden,
                    _ => Decoys::Off,
                };
                s.save(&home)?;
                Ok(restart_agent())
            })();
            match result {
                Ok(true) => show(
                    &ui,
                    tr(
                        "Gespeichert. Der Agent wurde neu gestartet.",
                        "Saved. The agent was restarted.",
                    ),
                    false,
                ),
                Ok(false) => show(
                    &ui,
                    tr(
                        "Gespeichert. Starte den Agenten neu, damit es wirkt.",
                        "Saved. Restart the agent to apply.",
                    ),
                    false,
                ),
                Err(e) => show(&ui, format!("{e:#}"), true),
            }
        });
    }

    if let (Some(window), Some(path)) = (offscreen, screenshot) {
        ui.show()?;
        return crate::shot::save(&window, path);
    }
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_secs(5), refresh);
    ui.run()?;
    drop(timer);
    Ok(())
}

/// Restart the agent if it runs as a systemd user service.
fn restart_agent() -> bool {
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "wachposten-agent"])
        .status()
        .is_ok_and(|s| s.success());
    active
        && Command::new("systemctl")
            .args(["--user", "restart", "wachposten-agent"])
            .status()
            .is_ok_and(|s| s.success())
}
