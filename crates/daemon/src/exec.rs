//! Program starts from temporary folders, seen through fanotify.
//!
//! Two groups are used. A permission group (`FAN_OPEN_EXEC_PERM`) holds starts on tmpfs file
//! systems (`/tmp`, `/dev/shm`, `/run/user/*`) until they are scanned, and refuses known
//! malware. It is only put on tmpfs, so a stuck scan can never hold up programs in `/usr`. A
//! notification group (`FAN_OPEN_EXEC`) sees the other file systems (`/var/tmp`, `~/.cache`)
//! and reports after the fact. If the daemon dies, the kernel allows all held-up starts.
//!
//! Marks are put on whole file systems, not mounts: the hardened service runs in a mount
//! namespace of its own, where mount marks would only see its private copies of the mounts.

use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::fcntl::AT_FDCWD;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyEvent, FanotifyResponse, InitFlags, MarkFlags, MaskFlags,
    Response,
};
use nix::sys::statfs::{TMPFS_MAGIC, statfs};
use wachposten_core::Finding;
use wachposten_core::settings::ExecSettings;
use wachposten_scan::MalwareScanner;

use crate::Msg;
use crate::proc::{self, ProcInfo};

/// A program start worth recording.
#[derive(Debug)]
pub struct ExecReport {
    pub path: PathBuf,
    pub proc: ProcInfo,
    pub findings: Vec<Finding>,
    pub blocked: bool,
    /// How it ran when it was not started directly: the interpreter's name, or the memfd name.
    pub via: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExecStatus {
    pub watching: bool,
    pub blocking: bool,
}

/// The same file started again within this time is not reported again.
const REPEAT: Duration = Duration::from_secs(600);
const CACHE_LIMIT: usize = 8192;

/// The temporary folder `path` lies in, if any.
pub fn temp_root(path: &Path) -> Option<PathBuf> {
    for root in ["/tmp", "/var/tmp", "/dev/shm"] {
        if path.starts_with(root) && path != Path::new(root) {
            return Some(PathBuf::from(root));
        }
    }
    let parts: Vec<_> = path.components().collect();
    let s = |i: usize| parts.get(i).map(|c| c.as_os_str().to_string_lossy());
    // /run/user/<uid>/…
    if s(1).as_deref() == Some("run") && s(2).as_deref() == Some("user") && parts.len() > 4 {
        return Some(parts[..4].iter().collect());
    }
    // /home/<user>/.cache/… and /root/.cache/…
    if s(1).as_deref() == Some("home") && s(3).as_deref() == Some(".cache") && parts.len() > 4 {
        return Some(parts[..4].iter().collect());
    }
    if s(1).as_deref() == Some("root") && s(2).as_deref() == Some(".cache") && parts.len() > 3 {
        return Some(parts[..3].iter().collect());
    }
    None
}

const MASQUERADE: [&str; 16] = [
    "kworker",
    "kthreadd",
    "ksoftirqd",
    "kswapd",
    "kdevtmpfs",
    "kauditd",
    "khugepaged",
    "migration",
    "rcu_",
    "watchdogd",
    "systemd",
    "sshd",
    "dbus-daemon",
    "crond",
    "rsyslogd",
    "udevd",
];

/// Reasons a program start looks suspicious even without a signature hit.
pub fn suspicious(path: &Path, root: &Path) -> Vec<&'static str> {
    let mut out = Vec::new();
    if root == Path::new("/dev/shm") {
        out.push("shm");
    }
    if let Ok(rel) = path.strip_prefix(root)
        && rel
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    {
        out.push("hidden-dir");
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().trim_matches(['[', ']']).to_string())
        .unwrap_or_default();
    if MASQUERADE.iter().any(|m| name.starts_with(m)) {
        out.push("masquerade");
    }
    out
}

fn fd_path(fd: BorrowedFd<'_>) -> Option<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
}

type FileKey = (u64, u64, u64, i64);

fn file_key(meta: &fs::Metadata) -> FileKey {
    (
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.mtime_nsec() + meta.mtime() * 1_000_000_000,
    )
}

/// Remembers scan results and recent reports per file version.
#[derive(Default)]
struct Memory {
    verdicts: HashMap<FileKey, Vec<Finding>>,
    reported: HashMap<FileKey, Instant>,
}

impl Memory {
    fn should_report(&mut self, key: FileKey) -> bool {
        if self.reported.len() > CACHE_LIMIT {
            self.reported.retain(|_, t| t.elapsed() < REPEAT);
        }
        match self.reported.get(&key) {
            Some(t) if t.elapsed() < REPEAT => false,
            _ => {
                self.reported.insert(key, Instant::now());
                true
            }
        }
    }

    fn remember(&mut self, key: FileKey, findings: Vec<Finding>) {
        if self.verdicts.len() > CACHE_LIMIT {
            self.verdicts.clear();
        }
        self.verdicts.insert(key, findings);
    }
}

fn mark_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Ok(dir) = fs::read_dir("/run/user") {
        roots.extend(dir.flatten().map(|e| e.path()));
    }
    roots.into_iter().filter(|p| p.is_dir()).collect()
}

fn is_tmpfs(path: &Path) -> bool {
    statfs(path).is_ok_and(|s| s.filesystem_type() == TMPFS_MAGIC)
}

/// Put marks on the file systems of all roots. Marking twice does nothing, so this also picks
/// up `/run/user/<uid>` of people who logged in later.
fn mark_all(notify: &Fanotify, perm: Option<&Fanotify>) {
    for root in mark_roots() {
        let result = match perm {
            Some(perm) if is_tmpfs(&root) => perm.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                MaskFlags::FAN_OPEN_EXEC_PERM,
                AT_FDCWD,
                Some(&root),
            ),
            _ => notify.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                MaskFlags::FAN_OPEN_EXEC,
                AT_FDCWD,
                Some(&root),
            ),
        };
        if let Err(e) = result {
            log::warn!("cannot watch program starts in {}: {e}", root.display());
        }
    }
}

/// Start watching. Needs `CAP_SYS_ADMIN`.
pub fn start(
    settings: &ExecSettings,
    scanner: Arc<MalwareScanner>,
    tx: Sender<Msg>,
) -> Result<ExecStatus> {
    let flags = EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE | EventFFlags::O_CLOEXEC;
    let notify = Arc::new(
        Fanotify::init(InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC, flags)
            .context("fanotify_init failed (the daemon needs root)")?,
    );
    let perm = if settings.block_known_malware {
        match Fanotify::init(InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC, flags) {
            Ok(f) => Some(Arc::new(f)),
            Err(e) => {
                log::warn!("blocking unavailable: {e}");
                None
            }
        }
    } else {
        None
    };
    mark_all(&notify, perm.as_deref());

    let memory = Arc::new(Mutex::new(Memory::default()));
    let budget = Duration::from_millis(settings.scan_budget_ms.max(100));

    // Background scans for starts that were not held up.
    let (scan_tx, scan_rx) = mpsc::channel::<(PathBuf, ProcInfo)>();
    {
        let scanner = scanner.clone();
        let tx = tx.clone();
        thread::Builder::new()
            .name("exec-scan".into())
            .spawn(move || {
                for (path, proc) in scan_rx {
                    let findings = wachposten_scan::findings(&path, scanner.scan_path(&path));
                    let report = ExecReport {
                        path,
                        proc,
                        findings,
                        blocked: false,
                        via: None,
                    };
                    if tx.send(Msg::Exec(report)).is_err() {
                        break;
                    }
                }
            })?;
    }

    {
        let notify = notify.clone();
        let memory = memory.clone();
        thread::Builder::new()
            .name("exec-notify".into())
            .spawn(move || {
                loop {
                    let events = match notify.read_events() {
                        Ok(ev) => ev,
                        Err(e) => {
                            log::error!("fanotify read failed: {e}");
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    };
                    for event in events {
                        handle_notify(&event, &memory, &scan_tx);
                    }
                }
            })?;
    }

    if let Some(perm) = perm.clone() {
        let memory = memory.clone();
        let tx = tx.clone();
        thread::Builder::new()
            .name("exec-perm".into())
            .spawn(move || {
                loop {
                    let events = match perm.read_events() {
                        Ok(ev) => ev,
                        Err(e) => {
                            log::error!("fanotify read failed: {e}");
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    };
                    for event in events {
                        handle_perm(&perm, &event, &scanner, &memory, budget, &tx);
                    }
                }
            })?;
    }

    {
        let notify = notify.clone();
        let perm = perm.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                mark_all(&notify, perm.as_deref());
            }
        });
    }

    Ok(ExecStatus {
        watching: true,
        blocking: perm.is_some(),
    })
}

fn handle_notify(
    event: &FanotifyEvent,
    memory: &Mutex<Memory>,
    scan_tx: &Sender<(PathBuf, ProcInfo)>,
) {
    if event.mask().contains(MaskFlags::FAN_Q_OVERFLOW) {
        log::warn!("fanotify queue overflow; some program starts were missed");
        return;
    }
    let Some(fd) = event.fd() else { return };
    let Some(path) = fd_path(fd) else { return };
    if temp_root(&path).is_none() {
        return;
    }
    let Ok(meta) = fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
        return;
    };
    let key = file_key(&meta);
    if !memory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .should_report(key)
    {
        return;
    }
    let _ = scan_tx.send((path, proc::info(event.pid())));
}

fn handle_perm(
    group: &Fanotify,
    event: &FanotifyEvent,
    scanner: &MalwareScanner,
    memory: &Mutex<Memory>,
    budget: Duration,
    tx: &Sender<Msg>,
) {
    let Some(fd) = event.fd() else { return };
    // Whatever happens below, the start must get an answer.
    let mut answer = Response::FAN_ALLOW;
    let mut report = None;

    if let Some(path) = fd_path(fd) {
        let via_fd = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        if let Ok(meta) = fs::metadata(&via_fd) {
            let key = file_key(&meta);
            let cached = memory
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .verdicts
                .get(&key)
                .cloned();
            let findings = cached.unwrap_or_else(|| {
                // Scan through the open descriptor, so a file swapped in after the start
                // cannot slip past.
                let found =
                    wachposten_scan::findings(&path, scanner.scan_path_quick(&via_fd, budget));
                memory
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remember(key, found.clone());
                found
            });
            let blocked = !findings.is_empty();
            if blocked {
                answer = Response::FAN_DENY;
                log::warn!("blocked start of {}", path.display());
            }
            let fresh = memory
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .should_report(key);
            if fresh || blocked {
                report = Some(ExecReport {
                    path,
                    proc: proc::info(event.pid()),
                    findings,
                    blocked,
                    via: None,
                });
            }
        }
    }

    if let Err(e) = group.write_response(FanotifyResponse::new(fd, answer)) {
        log::error!("fanotify response failed: {e}");
    }
    if let Some(report) = report {
        let _ = tx.send(Msg::Exec(report));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_roots() {
        let r = |p: &str| temp_root(Path::new(p)).map(|p| p.to_string_lossy().into_owned());
        assert_eq!(r("/tmp/x").as_deref(), Some("/tmp"));
        assert_eq!(r("/tmp"), None);
        assert_eq!(r("/dev/shm/.k").as_deref(), Some("/dev/shm"));
        assert_eq!(r("/run/user/1000/x").as_deref(), Some("/run/user/1000"));
        assert_eq!(
            r("/home/anna/.cache/x/y").as_deref(),
            Some("/home/anna/.cache")
        );
        assert_eq!(r("/root/.cache/y").as_deref(), Some("/root/.cache"));
        assert_eq!(r("/home/anna/bin/x"), None);
        assert_eq!(r("/usr/bin/ls"), None);
    }

    #[test]
    fn suspicion() {
        let s = |p: &str| suspicious(Path::new(p), &temp_root(Path::new(p)).unwrap());
        assert!(s("/tmp/go-build123/b001/exe/main").is_empty());
        assert_eq!(s("/tmp/.x/upd"), ["hidden-dir"]);
        assert_eq!(s("/dev/shm/kworker"), ["shm", "masquerade"]);
        assert_eq!(s("/var/tmp/[kthreadd]"), ["masquerade"]);
        // `.cache` itself is the root and does not count as hidden.
        assert!(s("/home/anna/.cache/tool/bin/run").is_empty());
    }
}
