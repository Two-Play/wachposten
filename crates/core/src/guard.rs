//! The persistence guard: compares the current state with the baseline, records events and
//! carries out the person's decisions.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use crate::analyze;
use crate::crontab::{CrontabBackend, NoCrontab, SystemCrontab};
use crate::model::{
    Change, Entry, Event, Finding, Kind, QuarantineItem, Severity, Status, hash_of,
};
use crate::scanner::{FileScanner, MALWARE_RULE};
use crate::store::{NewEvent, Store};
use crate::targets::{self, CRONTAB_PATH, Target};

/// Where the guard looks and where it keeps its data.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub crontab: bool,
    /// Run `systemctl` after removing a unit. Off in tests.
    pub systemctl: bool,
    /// Watch the system-wide locations (root daemon) instead of a home directory.
    pub system: bool,
    /// Accept files that a package installed unchanged without asking.
    pub verify_packages: bool,
}

impl Config {
    /// Read `$HOME` and `$XDG_DATA_HOME`. `WACHPOSTEN_NO_CRONTAB=1` switches crontab watching off.
    pub fn from_env() -> Result<Config> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let data_base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/share"));
        let crontab = std::env::var("WACHPOSTEN_NO_CRONTAB").map_or(true, |v| v != "1");
        Ok(Config {
            home,
            data_dir: data_base.join("wachposten"),
            crontab,
            systemctl: true,
            system: false,
            verify_packages: false,
        })
    }

    /// Settings of the root daemon: system-wide locations, data in `data_dir`.
    pub fn system(data_dir: PathBuf) -> Config {
        Config {
            home: PathBuf::from("/"),
            data_dir,
            crontab: false,
            systemctl: true,
            system: true,
            verify_packages: true,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("state.db")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.data_dir.join("quarantine")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.data_dir.join("agent.lock")
    }
}

/// Result of a decision that the caller should tell the person about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    /// Removed; the optional quarantine id holds the removed version.
    Removed {
        quarantine_id: Option<i64>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    #[error("event {0} does not exist")]
    NotFound(i64),
    #[error("event {0} was already handled")]
    AlreadyResolved(i64),
    #[error("the entry changed again since this message was shown")]
    Stale,
    #[error("the old version is too large to restore; please fix {0} by hand")]
    CannotRestore(String),
}

pub struct Guard {
    config: Config,
    store: Store,
    targets: Vec<Target>,
    crontab: Box<dyn CrontabBackend>,
    scanner: Option<Arc<dyn FileScanner>>,
}

/// A single file to record, see [`Guard::record_file`].
pub struct FileReport<'a> {
    pub path: &'a Path,
    pub kind: Kind,
    pub severity: Severity,
    pub ask: bool,
    pub findings: &'a [Finding],
    /// Extra lines shown with the event, such as the process that started a program.
    pub details: &'a [String],
    pub uid: Option<u32>,
    /// Report it even if the person allowed this file before (a changed decoy file).
    pub even_if_allowed: bool,
}

pub fn severity_for(findings: &[Finding]) -> Severity {
    if findings.iter().any(|f| f.rule == MALWARE_RULE) {
        Severity::Malicious
    } else if findings.is_empty() {
        Severity::Notice
    } else {
        Severity::Suspicious
    }
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Guard {
    pub fn open(config: Config) -> Result<Guard> {
        let crontab: Box<dyn CrontabBackend> = if config.crontab {
            Box::new(SystemCrontab)
        } else {
            Box::new(NoCrontab)
        };
        Self::with_crontab(config, crontab)
    }

    pub fn with_crontab(config: Config, crontab: Box<dyn CrontabBackend>) -> Result<Guard> {
        create_private_dir(&config.data_dir)
            .with_context(|| format!("cannot create {}", config.data_dir.display()))?;
        create_private_dir(&config.quarantine_dir())?;
        let store = Store::open(&config.db_path())
            .with_context(|| format!("cannot open {}", config.db_path().display()))?;
        let targets = if config.system {
            targets::system_targets()
        } else {
            targets::home_targets(&config.home, config.crontab)
        };
        Ok(Guard {
            config,
            store,
            targets,
            crontab,
            scanner: None,
        })
    }

    /// Check new persistence entries and the programs they start with this scanner.
    pub fn set_scanner(&mut self, scanner: Arc<dyn FileScanner>) {
        self.scanner = Some(scanner);
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn is_initialized(&self) -> Result<bool> {
        Ok(self.store.meta("initialized_at")?.is_some())
    }

    /// Record the current state as the baseline without asking. Returns the number of entries.
    pub fn initialize(&mut self) -> Result<usize> {
        let current = targets::snapshot(&self.targets, self.crontab.as_ref());
        let count = current.len();
        self.store.transaction(|s| {
            for (path, (kind, entry)) in &current {
                s.set_baseline(path, *kind, Some(entry))?;
            }
            s.set_meta("initialized_at", &crate::store::now().to_string())?;
            Ok(())
        })?;
        Ok(count)
    }

    /// Directories to watch, with the names that matter in each (`None` = all names).
    pub fn watch_specs(&self) -> Vec<(PathBuf, Option<Vec<String>>)> {
        targets::watch_specs(&self.config.home, &self.targets)
    }

    /// Compare the current state with the baseline. Returns events that are new or describe a
    /// new state and need a decision.
    pub fn rescan(&mut self) -> Result<Vec<Event>> {
        let current = targets::snapshot(&self.targets, self.crontab.as_ref());
        let baseline = self.store.baseline()?;
        self.prune_downloads()?;
        let open_paths: BTreeSet<String> = self
            .store
            .open_events()?
            .into_iter()
            .filter(|e| !e.kind.is_file_report())
            .map(|e| e.path)
            .collect();
        let paths: BTreeSet<&String> = current
            .keys()
            .chain(baseline.keys())
            .chain(open_paths.iter())
            .collect();

        let mut changed_ids = Vec::new();
        self.store.transaction(|s| {
            for path in paths {
                let cur = current.get(path);
                let base = baseline.get(path);
                let cur_entry = cur.map(|(_, e)| e);
                let base_entry = base.map(|(_, e)| e);
                let open = s.open_event_for(path)?;

                if hash_of(cur_entry) == hash_of(base_entry) {
                    if let Some(ev) = open {
                        s.resolve_event(ev.id, Status::Reverted, None)?;
                    }
                    continue;
                }
                s.close_noted(path)?;

                let kind = cur
                    .or(base)
                    .map(|(k, _)| *k)
                    .or_else(|| targets::kind_for(&self.targets, path))
                    .unwrap_or(Kind::ShellRc);

                let Some(cur_entry) = cur_entry else {
                    // Deleting a persistence entry does not install anything: record and accept.
                    if let Some(ev) = open {
                        s.resolve_event(ev.id, Status::Reverted, None)?;
                    }
                    s.insert_event(&NewEvent {
                        path,
                        kind,
                        change: Change::Deleted,
                        severity: Severity::Info,
                        status: Status::Accepted,
                        old_hash: hash_of(base_entry),
                        new_entry: None,
                        findings: &[],
                        added_lines: &[],
                        uid: None,
                    })?;
                    s.set_baseline(path, kind, None)?;
                    continue;
                };

                if open
                    .as_ref()
                    .is_some_and(|ev| ev.new_hash() == cur_entry.hash())
                {
                    continue;
                }

                if self.config.verify_packages
                    && matches!(cur_entry, Entry::File { .. })
                    && crate::pkg::installed_unchanged(Path::new(path))
                {
                    if let Some(ev) = &open {
                        s.resolve_event(ev.id, Status::Accepted, None)?;
                    }
                    s.insert_event(&NewEvent {
                        path,
                        kind,
                        change: if base_entry.is_some() {
                            Change::Modified
                        } else {
                            Change::Created
                        },
                        severity: Severity::Info,
                        status: Status::Accepted,
                        old_hash: hash_of(base_entry),
                        new_entry: Some(cur_entry),
                        findings: &[],
                        added_lines: &["(package file, unchanged)".to_string()],
                        uid: None,
                    })?;
                    s.set_baseline(path, kind, Some(cur_entry))?;
                    continue;
                }

                let added = analyze::added_lines(base_entry, cur_entry);
                let mut findings = analyze::findings(kind, cur_entry, &added);
                if path == "/etc/ld.so.preload" && !added.is_empty() {
                    // Every library listed there is loaded into every program.
                    findings.push(Finding {
                        rule: "preload".into(),
                        line: added[0].chars().take(300).collect(),
                    });
                }
                if let Some(scanner) = &self.scanner {
                    if path != CRONTAB_PATH && matches!(cur_entry, Entry::File { .. }) {
                        findings.extend(scanner.scan(Path::new(path)));
                    }
                    for program in analyze::referenced_programs(cur_entry, &self.config.home) {
                        findings.extend(scanner.scan(&program));
                    }
                }
                let severity = severity_for(&findings);
                // Nothing looked dangerous: accept it right away, keep the old state so the
                // person can still undo it, and only show a short hint.
                let noted =
                    findings.is_empty() && analyze::may_note(kind, path, base_entry.is_none());
                if noted && let Some(ev) = &open {
                    // The dangerous part of an earlier version is gone again.
                    s.resolve_event(ev.id, Status::Reverted, None)?;
                }
                let new = NewEvent {
                    path,
                    kind,
                    change: if base_entry.is_some() {
                        Change::Modified
                    } else {
                        Change::Created
                    },
                    severity,
                    status: if noted { Status::Noted } else { Status::Open },
                    old_hash: hash_of(base_entry),
                    new_entry: Some(cur_entry),
                    findings: &findings,
                    added_lines: &added,
                    uid: None,
                };
                let id = match open {
                    Some(ev) if !noted => {
                        s.update_event(ev.id, &new)?;
                        ev.id
                    }
                    _ => s.insert_event(&new)?,
                };
                if noted {
                    s.set_old_entry(id, base_entry)?;
                    s.set_baseline(path, kind, Some(cur_entry))?;
                }
                changed_ids.push(id);
            }
            Ok(())
        })?;

        let mut events = Vec::new();
        for id in changed_ids {
            if let Some(ev) = self.store.event(id)? {
                events.push(ev);
            }
        }
        Ok(events)
    }

    /// Record a file in a download folder that a malware scanner flagged. Returns the event if
    /// it is new; files the person allowed before and repeats are ignored.
    pub fn record_detection(&mut self, path: &Path, findings: &[Finding]) -> Result<Option<Event>> {
        self.record_flagged(path, Kind::Download, findings)
    }

    /// Like [`record_detection`](Self::record_detection) for a file the person had checked.
    pub fn record_checked(&mut self, path: &Path, findings: &[Finding]) -> Result<Option<Event>> {
        self.record_flagged(path, Kind::Checked, findings)
    }

    fn record_flagged(
        &mut self,
        path: &Path,
        kind: Kind,
        findings: &[Finding],
    ) -> Result<Option<Event>> {
        if findings.is_empty() {
            return Ok(None);
        }
        self.record_file(&FileReport {
            path,
            kind,
            severity: severity_for(findings),
            ask: true,
            findings,
            details: &[],
            uid: None,
            even_if_allowed: false,
        })
    }

    /// Record a single file (a download or a program start). With `ask` the event stays open
    /// for a decision; without, it is only kept in the history. Returns the event if it is new.
    /// Files whose hash the person allowed before and repeats of an open event are ignored.
    pub fn record_file(&mut self, report: &FileReport<'_>) -> Result<Option<Event>> {
        let Some(mut entry) = targets::read_entry(report.path)? else {
            return Ok(None);
        };
        if let Entry::File { content, .. } = &mut entry {
            // Programs and malware are not kept in the database.
            *content = None;
        }
        if !report.even_if_allowed && self.store.is_allowed_for(entry.hash(), report.uid)? {
            return Ok(None);
        }
        let path_str = report.path.to_string_lossy().into_owned();
        let open = self.store.open_event_for(&path_str)?;
        if open
            .as_ref()
            .is_some_and(|ev| ev.new_hash() == entry.hash())
        {
            return Ok(None);
        }
        let new = NewEvent {
            path: &path_str,
            kind: report.kind,
            change: Change::Created,
            severity: report.severity,
            status: if report.ask {
                Status::Open
            } else {
                Status::Accepted
            },
            old_hash: crate::model::ABSENT,
            new_entry: Some(&entry),
            findings: report.findings,
            added_lines: report.details,
            uid: report.uid,
        };
        let id = match open {
            Some(ev) if report.ask => {
                self.store.update_event(ev.id, &new)?;
                ev.id
            }
            _ => self.store.insert_event(&new)?,
        };
        Ok(self.store.event(id)?)
    }

    /// Close download events whose file was deleted or replaced in the meantime. Program starts
    /// stay open: malware often deletes itself after starting, and its process may still run.
    fn prune_downloads(&mut self) -> Result<()> {
        for ev in self.store.open_events()? {
            if !matches!(ev.kind, Kind::Download | Kind::Checked) {
                continue;
            }
            let current = targets::read_entry(Path::new(&ev.path)).ok().flatten();
            if hash_of(current.as_ref()) != ev.new_hash() {
                self.store.resolve_event(ev.id, Status::Reverted, None)?;
            }
        }
        Ok(())
    }

    fn current_entry(&self, path: &str) -> Result<Option<Entry>> {
        if path == CRONTAB_PATH {
            return Ok(self
                .crontab
                .read()?
                .map(|c| targets::entry_from_bytes(c, 0o600)));
        }
        Ok(targets::read_entry(Path::new(path))?)
    }

    /// Load an open event and check that the entry on disk still is what the person saw.
    fn check_decision(&self, id: i64, seen_hash: Option<&str>) -> Result<Event> {
        let ev = self.store.event(id)?.ok_or(DecisionError::NotFound(id))?;
        if !ev.decidable() {
            bail!(DecisionError::AlreadyResolved(id));
        }
        if seen_hash.is_some_and(|h| h != ev.new_hash()) {
            bail!(DecisionError::Stale);
        }
        let current = self.current_entry(&ev.path)?;
        let gone_program = ev.kind.is_program() && current.is_none();
        if hash_of(current.as_ref()) != ev.new_hash() && !gone_program {
            bail!(DecisionError::Stale);
        }
        Ok(ev)
    }

    /// Accept the change: the described state becomes the baseline.
    pub fn allow(&mut self, id: i64, seen_hash: Option<&str>) -> Result<Outcome> {
        let ev = self.check_decision(id, seen_hash)?;
        self.store.transaction(|s| {
            // A process without a file of its own (`/proc/<pid>/exe`) may be an interpreter
            // or a program from memory: allowing it must not allow that program everywhere.
            let own_file = !(ev.kind == Kind::Ransomware && ev.path.starts_with("/proc/"));
            if ev.kind.is_file_report() {
                match (own_file, ev.uid) {
                    // The daemon: a program of one user is allowed for that user only.
                    (true, Some(uid)) if self.config.system => {
                        s.allow_hash_for(ev.new_hash(), &ev.path, uid)?
                    }
                    (true, _) => s.allow_hash(ev.new_hash(), &ev.path)?,
                    (false, _) => {}
                }
            } else {
                s.set_baseline(&ev.path, ev.kind, ev.new_entry.as_ref())?;
            }
            s.resolve_event(ev.id, Status::Allowed, None)?;
            Ok(())
        })?;
        Ok(Outcome::Allowed)
    }

    /// Undo the change: move the new version into quarantine and put the baseline back.
    pub fn remove(&mut self, id: i64, seen_hash: Option<&str>) -> Result<Outcome> {
        let ev = self.check_decision(id, seen_hash)?;
        if self.config.system && !ev.path.starts_with("/proc/") {
            // As root, never act through a symbolic link in the path: a user could point a
            // folder of theirs at /etc and have root delete or overwrite files there.
            no_symlinked_dirs(Path::new(&ev.path))?;
            if ev.kind.is_file_report()
                && fs::symlink_metadata(&ev.path).is_ok_and(|m| !m.file_type().is_file())
            {
                bail!("{} is not a regular file", ev.path);
            }
        }
        let new_entry = ev.new_entry.clone().context("event has no new state")?;
        let baseline = if ev.kind.is_file_report() {
            None
        } else if ev.status == Status::Noted {
            // The change is already in the baseline; go back to what was there before.
            self.store
                .old_entry(ev.id)?
                .ok_or_else(|| DecisionError::CannotRestore(ev.path.clone()))?
        } else {
            self.store.baseline_entry(&ev.path)?
        };
        if let Some(Entry::File { content: None, .. }) = &baseline {
            bail!(DecisionError::CannotRestore(ev.path.clone()));
        }

        // The program deleted itself, or ran from memory (/proc/<pid>/exe): there is no file to
        // keep, and the caller ended its processes.
        if ev.kind.is_program()
            && (fs::symlink_metadata(&ev.path).is_err() || ev.path.starts_with("/proc/"))
        {
            self.store.resolve_event(ev.id, Status::Removed, None)?;
            return Ok(Outcome::Removed {
                quarantine_id: None,
            });
        }
        let qid = self.quarantine(&ev, &new_entry)?;
        if ev.path == CRONTAB_PATH {
            let old = baseline.as_ref().and_then(|b| match b {
                Entry::File { content, .. } => content.clone(),
                Entry::Symlink { .. } => None,
            });
            self.crontab.write(old.as_deref())?;
        } else {
            let path = Path::new(&ev.path);
            match &baseline {
                None => remove_path(path)?,
                Some(entry) => write_entry(path, entry)?,
            }
            if self.config.systemctl
                && matches!(ev.kind, Kind::SystemdUser | Kind::SystemdSystem)
                && path
                    .extension()
                    .is_some_and(|e| e != "rules" && e != "local")
            {
                systemd_cleanup(path, baseline.is_none(), !self.config.system);
            }
        }
        self.store.transaction(|s| {
            if ev.status == Status::Noted {
                s.set_baseline(&ev.path, ev.kind, baseline.as_ref())?;
            }
            s.resolve_event(ev.id, Status::Removed, Some(qid))?;
            Ok(())
        })?;
        Ok(Outcome::Removed {
            quarantine_id: Some(qid),
        })
    }

    fn quarantine(&self, ev: &Event, entry: &Entry) -> Result<i64> {
        let (entry_type, mode, link_target) = match entry {
            Entry::File { mode, .. } => ("file", *mode, None),
            Entry::Symlink { target, .. } => ("symlink", 0o777, Some(target.clone())),
        };
        let owner = fs::symlink_metadata(&ev.path)
            .ok()
            .map(|m| (m.uid(), m.gid()));
        let qid = self.store.insert_quarantine(&QuarantineItem {
            id: 0,
            created_at: 0,
            original_path: ev.path.clone(),
            kind: ev.kind,
            entry_type: entry_type.into(),
            mode,
            link_target,
            hash: entry.hash().to_string(),
            event_id: Some(ev.id),
            restored_at: None,
            owner,
        })?;
        if let Entry::File { .. } = entry {
            let data = self.quarantine_data(qid);
            // Copy from disk, not from the event, so large files are kept as well.
            if ev.path == CRONTAB_PATH {
                let content = match entry {
                    Entry::File {
                        content: Some(c), ..
                    } => c.clone(),
                    _ => Vec::new(),
                };
                fs::write(&data, content)?;
            } else {
                fs::copy(&ev.path, &data)
                    .with_context(|| format!("cannot copy {} to quarantine", ev.path))?;
            }
            fs::set_permissions(&data, fs::Permissions::from_mode(0o400))?;
        }
        Ok(qid)
    }

    fn quarantine_data(&self, id: i64) -> PathBuf {
        self.config.quarantine_dir().join(format!("{id}.bin"))
    }

    /// Put a quarantined version back and make it the baseline. Fails if something is in the way
    /// unless `force` is set.
    pub fn restore(&mut self, id: i64, force: bool) -> Result<String> {
        let item = self
            .store
            .quarantine_item(id)?
            .with_context(|| format!("quarantine item {id} does not exist"))?;
        if item.restored_at.is_some() {
            bail!("quarantine item {id} was already restored");
        }
        let entry = match item.entry_type.as_str() {
            "symlink" => Entry::Symlink {
                hash: item.hash.clone(),
                target: item.link_target.clone().unwrap_or_default(),
            },
            _ => {
                let content = fs::read(self.quarantine_data(id))?;
                let mut e = targets::entry_from_bytes(content, item.mode);
                if let Entry::File { content, size, .. } = &mut e
                    && *size > targets::MAX_CONTENT
                {
                    *content = None;
                }
                e
            }
        };

        if item.original_path == CRONTAB_PATH {
            if !force && self.crontab.read()?.is_some_and(|c| !c.is_empty()) {
                bail!("a crontab exists; use --force to replace it");
            }
            let data = fs::read(self.quarantine_data(id))?;
            self.crontab.write(Some(&data))?;
        } else {
            let path = Path::new(&item.original_path);
            if self.config.system {
                no_symlinked_dirs(path)?;
            }
            if !force && fs::symlink_metadata(path).is_ok() {
                bail!("{} exists; use --force to replace it", path.display());
            }
            match &entry {
                Entry::File { .. } => {
                    let data = fs::read(self.quarantine_data(id))?;
                    write_file(path, &data, item.mode, item.owner)?;
                }
                Entry::Symlink { .. } => write_entry(path, &entry)?,
            }
        }
        let stored = self.current_entry(&item.original_path)?;
        self.store.transaction(|s| {
            if item.kind.is_file_report() {
                s.allow_hash(&item.hash, &item.original_path)?;
            } else {
                s.set_baseline(&item.original_path, item.kind, stored.as_ref())?;
            }
            s.mark_restored(id)?;
            Ok(())
        })?;
        Ok(item.original_path)
    }
}

/// Fail if a folder on the way to `path` is a symbolic link (or `path` has no real parent).
fn no_symlinked_dirs(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent folder"))?;
    // A missing folder is created later by the restore; check the part that exists.
    let mut existing = parent;
    while fs::symlink_metadata(existing).is_err() {
        existing = existing
            .parent()
            .ok_or_else(|| io::Error::other("no existing parent folder"))?;
    }
    let real = fs::canonicalize(existing)?;
    if real != existing {
        return Err(io::Error::other(format!(
            "{} goes through a symbolic link ({}); not acting on it as root",
            path.display(),
            real.display()
        )));
    }
    Ok(())
}

fn remove_path(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Write a file through a temporary name in the same directory and rename it into place.
/// The file keeps its current owner; a new file gets `owner` if given. Changing the owner needs
/// root and is skipped when it already matches.
fn write_file(path: &Path, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::other("no parent"))?;
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?;
    let tmp = dir.join(format!(".{}.wachposten-tmp", name.to_string_lossy()));
    // Never follow a link someone placed at the temporary name: create the file exclusively,
    // without following links, and set mode and owner on the open file.
    let open = || {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
    };
    let mut file = match open() {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // A leftover (or a planted link): remove the name itself, not what it points to.
            fs::remove_file(&tmp)?;
            open()?
        }
        r => r?,
    };
    file.write_all(data)?;
    let want = fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|m| (m.uid(), m.gid()))
        .or(owner);
    if let Some((uid, gid)) = want {
        let have = file.metadata()?;
        if (have.uid(), have.gid()) != (uid, gid) {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
    }
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)
}

fn write_entry(path: &Path, entry: &Entry) -> io::Result<()> {
    match entry {
        Entry::File {
            content: Some(c),
            mode,
            ..
        } => write_file(path, c, *mode, None),
        Entry::File { content: None, .. } => Err(io::Error::other("content not stored")),
        Entry::Symlink { target, .. } => {
            remove_path(path)?;
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            symlink(target, path)
        }
    }
}

/// Reload systemd after a unit was removed, and stop it if the unit itself is gone.
fn systemd_cleanup(path: &Path, removed: bool, user: bool) {
    let run = |args: &[&str]| {
        let mut cmd = Command::new("systemctl");
        if user {
            cmd.arg("--user");
        }
        if let Err(e) = cmd.args(args).status() {
            log::warn!("systemctl {args:?}: {e}");
        }
    };
    let in_wants = path.parent().and_then(Path::file_name).is_some_and(|d| {
        let d = d.to_string_lossy();
        d.ends_with(".wants") || d.ends_with(".requires") || d.ends_with(".d")
    });
    if removed
        && !in_wants
        && let Some(unit) = path.file_name().and_then(|n| n.to_str())
    {
        run(&["stop", unit]);
    }
    run(&["daemon-reload"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_file_does_not_follow_a_planted_link() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let victim = d.join("victim");
        fs::write(&victim, "keep").unwrap();
        // Someone placed a link at the temporary name.
        symlink(&victim, d.join(".restored.wachposten-tmp")).unwrap();
        write_file(&d.join("restored"), b"new", 0o644, None).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read_to_string(d.join("restored")).unwrap(), "new");
    }

    #[test]
    fn symlinked_folders_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(d.join("real")).unwrap();
        fs::write(d.join("real/file"), "x").unwrap();
        symlink(d.join("real"), d.join("link")).unwrap();
        assert!(no_symlinked_dirs(&d.join("real/file")).is_ok());
        assert!(no_symlinked_dirs(&d.join("link/file")).is_err());
        // A folder that does not exist yet is checked from the part that does.
        assert!(no_symlinked_dirs(&d.join("real/new/file")).is_ok());
        assert!(no_symlinked_dirs(&d.join("link/new/file")).is_err());
    }

    #[test]
    fn root_does_not_remove_through_a_linked_folder() {
        let dir = tempfile::tempdir().unwrap();
        let d = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(d.join("etc")).unwrap();
        fs::write(d.join("etc/passwd"), "root:x:0:0").unwrap();
        fs::create_dir_all(d.join("tmp/.d")).unwrap();
        symlink(d.join("etc"), d.join("tmp/.d/e")).unwrap();
        let config = Config {
            home: d.join("home"),
            data_dir: d.join("state"),
            crontab: false,
            systemctl: false,
            system: true,
            verify_packages: false,
        };
        let mut g = Guard::open(config).unwrap();
        let ev = g
            .record_file(&FileReport {
                path: &d.join("tmp/.d/e/passwd"),
                kind: Kind::TempExec,
                severity: Severity::Suspicious,
                ask: true,
                findings: &[],
                details: &[],
                uid: Some(1000),
                even_if_allowed: false,
            })
            .unwrap()
            .unwrap();
        assert!(g.remove(ev.id, None).is_err());
        assert_eq!(
            fs::read_to_string(d.join("etc/passwd")).unwrap(),
            "root:x:0:0"
        );
    }
}
