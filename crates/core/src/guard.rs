//! The persistence guard: compares the current state with the baseline, records events and
//! carries out the person's decisions.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::analyze;
use crate::crontab::{CrontabBackend, NoCrontab, SystemCrontab};
use crate::model::{Change, Entry, Event, Kind, QuarantineItem, Severity, Status, hash_of};
use crate::store::{NewEvent, Store};
use crate::targets::{self, CRONTAB_PATH, Target};

/// Where the guard looks and where it keeps its data.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub crontab: bool,
    /// Run `systemctl --user` after removing a unit. Off in tests.
    pub systemctl: bool,
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
        })
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
        let targets = targets::home_targets(&config.home, config.crontab);
        Ok(Guard {
            config,
            store,
            targets,
            crontab,
        })
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
        let open_paths: BTreeSet<String> = self
            .store
            .open_events()?
            .into_iter()
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

                let added = analyze::added_lines(base_entry, cur_entry);
                let findings = analyze::findings(kind, cur_entry, &added);
                let severity = if findings.is_empty() {
                    Severity::Notice
                } else {
                    Severity::Suspicious
                };
                let new = NewEvent {
                    path,
                    kind,
                    change: if base_entry.is_some() {
                        Change::Modified
                    } else {
                        Change::Created
                    },
                    severity,
                    status: Status::Open,
                    old_hash: hash_of(base_entry),
                    new_entry: Some(cur_entry),
                    findings: &findings,
                    added_lines: &added,
                };
                let id = match open {
                    Some(ev) => {
                        s.update_event(ev.id, &new)?;
                        ev.id
                    }
                    None => s.insert_event(&new)?,
                };
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
        if ev.status != Status::Open {
            bail!(DecisionError::AlreadyResolved(id));
        }
        if seen_hash.is_some_and(|h| h != ev.new_hash()) {
            bail!(DecisionError::Stale);
        }
        let current = self.current_entry(&ev.path)?;
        if hash_of(current.as_ref()) != ev.new_hash() {
            bail!(DecisionError::Stale);
        }
        Ok(ev)
    }

    /// Accept the change: the described state becomes the baseline.
    pub fn allow(&mut self, id: i64, seen_hash: Option<&str>) -> Result<Outcome> {
        let ev = self.check_decision(id, seen_hash)?;
        self.store.transaction(|s| {
            s.set_baseline(&ev.path, ev.kind, ev.new_entry.as_ref())?;
            s.resolve_event(ev.id, Status::Allowed, None)?;
            Ok(())
        })?;
        Ok(Outcome::Allowed)
    }

    /// Undo the change: move the new version into quarantine and put the baseline back.
    pub fn remove(&mut self, id: i64, seen_hash: Option<&str>) -> Result<Outcome> {
        let ev = self.check_decision(id, seen_hash)?;
        let new_entry = ev.new_entry.clone().context("event has no new state")?;
        let baseline = self.store.baseline_entry(&ev.path)?;
        if let Some(Entry::File { content: None, .. }) = &baseline {
            bail!(DecisionError::CannotRestore(ev.path.clone()));
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
            if ev.kind == Kind::SystemdUser && self.config.systemctl {
                systemd_cleanup(path, baseline.is_none());
            }
        }
        self.store.transaction(|s| {
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
            if !force && fs::symlink_metadata(path).is_ok() {
                bail!("{} exists; use --force to replace it", path.display());
            }
            match &entry {
                Entry::File { .. } => {
                    let data = fs::read(self.quarantine_data(id))?;
                    write_file(path, &data, item.mode)?;
                }
                Entry::Symlink { .. } => write_entry(path, &entry)?,
            }
        }
        let stored = self.current_entry(&item.original_path)?;
        self.store.transaction(|s| {
            s.set_baseline(&item.original_path, item.kind, stored.as_ref())?;
            s.mark_restored(id)?;
            Ok(())
        })?;
        Ok(item.original_path)
    }
}

fn remove_path(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Write a file through a temporary name in the same directory and rename it into place.
fn write_file(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::other("no parent"))?;
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?;
    let tmp = dir.join(format!(".{}.wachposten-tmp", name.to_string_lossy()));
    fs::write(&tmp, data)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
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
        } => write_file(path, c, *mode),
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
fn systemd_cleanup(path: &Path, removed: bool) {
    let run = |args: &[&str]| {
        if let Err(e) = Command::new("systemctl").arg("--user").args(args).status() {
            log::warn!("systemctl --user {args:?}: {e}");
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
