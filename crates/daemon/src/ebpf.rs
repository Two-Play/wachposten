//! The eBPF part (see `bpf/wachposten.bpf.c`), loaded with aya.
//!
//! It reports two things fanotify cannot:
//! - scripts run through an interpreter (`sh /tmp/x.sh`, `python3 /tmp/x.py`) and programs
//!   started from memory (memfd), which become program start reports;
//! - which process wrote a path, so events can name the program behind a change.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::fd::AsFd;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use wachposten_core::Finding;
use wachposten_core::targets::{TargetPath, home_targets, system_targets};
use wachposten_scan::MalwareScanner;

use crate::Msg;
use crate::exec::{ExecReport, temp_root};
use crate::proc::{self, ProcInfo};

const KIND_EXEC: u32 = 1;
const KIND_WRITE: u32 = 2;
const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u32 = 0x1000;
const PATH_LEN: usize = 256;
const ARG_LEN: usize = 128;
const MAX_ARGS: usize = 4;
const EVENT_LEN: usize = 40 + PATH_LEN + MAX_ARGS * ARG_LEN;

/// Writers are kept this long.
const WRITER_AGE: Duration = Duration::from_secs(600);
const WRITER_LIMIT: usize = 20_000;

#[cfg(wachposten_bpf)]
static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/wachposten.bpf.o"));

/// Programs and the tracepoints they attach to. Missing tracepoints (`open`, `rename` and
/// `symlink` do not exist on every architecture) are skipped.
const PROGRAMS: [(&str, &str); 12] = [
    ("execve_enter", "sys_enter_execve"),
    ("execveat_enter", "sys_enter_execveat"),
    ("execve_exit", "sys_exit_execve"),
    ("execveat_exit", "sys_exit_execveat"),
    ("openat_enter", "sys_enter_openat"),
    ("open_enter", "sys_enter_open"),
    ("renameat2_enter", "sys_enter_renameat2"),
    ("renameat_enter", "sys_enter_renameat"),
    ("rename_enter", "sys_enter_rename"),
    ("symlinkat_enter", "sys_enter_symlinkat"),
    ("symlink_enter", "sys_enter_symlink"),
    ("linkat_enter", "sys_enter_linkat"),
];

/// One event from the ring buffer, see `struct event` in the C source.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub dirfd: i32,
    pub flags: u32,
    pub comm: String,
    pub path: String,
    pub args: Vec<String>,
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn parse(b: &[u8]) -> Option<RawEvent> {
    if b.len() < EVENT_LEN {
        return None;
    }
    let args = (0..MAX_ARGS)
        .map(|i| {
            let start = 40 + PATH_LEN + i * ARG_LEN;
            c_string(&b[start..start + ARG_LEN])
        })
        .take_while(|a| !a.is_empty())
        .collect();
    Some(RawEvent {
        kind: u32_at(b, 0),
        pid: u32_at(b, 4),
        uid: u32_at(b, 8),
        dirfd: u32_at(b, 12) as i32,
        flags: u32_at(b, 16),
        comm: c_string(&b[24..40]),
        path: c_string(&b[40..40 + PATH_LEN]),
        args,
    })
}

/// Make a path absolute and drop `.` and `..` without touching the file system.
pub fn resolve(path: &str, pid: u32, dirfd: i32) -> Option<PathBuf> {
    if path.is_empty() {
        return None;
    }
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        let base = if dirfd == AT_FDCWD {
            fs::read_link(format!("/proc/{pid}/cwd")).ok()?
        } else {
            fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()?
        };
        base.join(p)
    };
    let mut out = PathBuf::from("/");
    for c in full.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    Some(out)
}

/// A process that wrote a watched path.
#[derive(Debug, Clone)]
pub struct Writer {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub info: ProcInfo,
    pub exe: Option<String>,
    pub at: Instant,
}

impl Writer {
    pub fn describe(&self) -> String {
        let program = self.exe.clone().unwrap_or_else(|| self.comm.clone());
        let mut s = format!(
            "{} (PID {}, {})",
            self.comm,
            self.pid,
            crate::users::name(self.uid)
        );
        if !self.info.cmdline.is_empty() {
            let cmd: String = self.info.cmdline.chars().take(160).collect();
            s.push_str(&format!(" – {cmd}"));
        } else {
            s.push_str(&format!(" – {program}"));
        }
        if let (Some(ppid), Some(parent)) = (self.info.ppid, &self.info.parent_comm) {
            s.push_str(&format!(" ← {parent} (PID {ppid})"));
        }
        s
    }
}

/// Paths worth remembering a writer for: every persistence location of the system and of
/// every home folder.
#[derive(Default)]
struct Watched {
    files: HashSet<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl Watched {
    fn build() -> Watched {
        let mut homes: Vec<PathBuf> = fs::read_dir("/home")
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        homes.push(PathBuf::from("/root"));
        let mut targets = system_targets();
        for home in &homes {
            targets.extend(home_targets(home, false));
        }
        let mut w = Watched::default();
        for t in targets {
            match t.path {
                TargetPath::File(p) => {
                    w.files.insert(p);
                }
                TargetPath::Dir { path, .. } => w.dirs.push(path),
                TargetPath::Crontab => {}
            }
        }
        w
    }

    fn matches(&self, path: &Path) -> bool {
        self.files.contains(path) || self.dirs.iter().any(|d| path.starts_with(d))
    }
}

#[derive(Default)]
pub struct Writers {
    map: HashMap<PathBuf, Writer>,
}

pub type SharedWriters = Arc<Mutex<Writers>>;

impl Writers {
    /// The last writer of `path`, if it wrote within the last ten minutes.
    pub fn recent(&self, path: &Path) -> Option<&Writer> {
        self.map.get(path).filter(|w| w.at.elapsed() < WRITER_AGE)
    }

    fn record(&mut self, path: PathBuf, writer: Writer) {
        if self.map.len() > WRITER_LIMIT {
            self.map.retain(|_, w| w.at.elapsed() < WRITER_AGE);
        }
        self.map.insert(path, writer);
    }
}

const INTERPRETERS: [&str; 14] = [
    "sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "perl", "ruby", "node", "php", "lua",
    "tclsh", "pwsh",
];

fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name) || name.starts_with("python") || name.starts_with("perl5")
}

/// The script an interpreter was asked to run, if it lies in a temporary folder.
pub fn script_in_temp(ev: &RawEvent, program: &Path) -> Option<PathBuf> {
    let name = program.file_name()?.to_string_lossy();
    if !is_interpreter(&name) {
        return None;
    }
    let mut args = ev.args.iter().skip(1);
    // `busybox sh x.sh`: skip the applet name.
    if name == "busybox" {
        args.next();
    }
    for arg in args {
        if arg == "-c" || arg == "-e" || arg == "-m" {
            return None; // inline code or a module, no script file
        }
        if arg.starts_with('-') {
            continue;
        }
        let path = resolve(arg, ev.pid, AT_FDCWD)?;
        return (temp_root(&path).is_some() && path.is_file()).then_some(path);
    }
    None
}

/// What a start from memory runs: `/proc/<pid>/exe` points to `/memfd:<name> (deleted)`.
pub fn memfd_exe(ev: &RawEvent) -> Option<String> {
    let suspicious_name = ev.flags & AT_EMPTY_PATH != 0
        || ev.path.starts_with("/dev/fd/")
        || (ev.path.starts_with("/proc/") && ev.path.contains("/fd/"));
    if !suspicious_name {
        return None;
    }
    let exe = fs::read_link(format!("/proc/{}/exe", ev.pid)).ok()?;
    let exe = exe.to_string_lossy().into_owned();
    exe.starts_with("/memfd:").then_some(exe)
}

/// Load and attach the eBPF programs and handle their events in background threads.
pub fn start(tx: Sender<Msg>, scanner: Arc<MalwareScanner>, writers: SharedWriters) -> Result<()> {
    #[cfg(not(wachposten_bpf))]
    {
        let _ = (tx, scanner, writers);
        anyhow::bail!("this build has no eBPF part (clang was missing)");
    }
    #[cfg(wachposten_bpf)]
    {
        use aya::Ebpf;
        use aya::maps::RingBuf;
        use aya::programs::TracePoint;

        let mut bpf = Ebpf::load(OBJECT).context("cannot load the eBPF programs")?;
        let mut attached = 0;
        for (prog, tracepoint) in PROGRAMS {
            let Some(program) = bpf.program_mut(prog) else {
                continue;
            };
            let tp: &mut TracePoint = program.try_into()?;
            if let Err(e) = tp.load() {
                log::warn!("eBPF program {prog} not loaded: {e}");
                continue;
            }
            match tp.attach("syscalls", tracepoint) {
                Ok(_) => attached += 1,
                Err(e) => log::debug!("tracepoint {tracepoint} not available: {e}"),
            }
        }
        if attached == 0 {
            anyhow::bail!("no eBPF program could be attached");
        }
        let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("ring buffer missing")?)?;
        log::info!("eBPF: {attached} tracepoints attached");

        let (scan_tx, scan_rx) = mpsc::channel::<(PathBuf, ProcInfo, String, Vec<Finding>)>();
        thread::Builder::new()
            .name("ebpf-scan".into())
            .spawn(move || {
                for (path, proc, via, mut findings) in scan_rx {
                    findings.extend(wachposten_scan::findings(&path, scanner.scan_path(&path)));
                    let report = ExecReport {
                        path,
                        proc,
                        findings,
                        blocked: false,
                        via: Some(via),
                    };
                    if tx.send(Msg::Exec(report)).is_err() {
                        break;
                    }
                }
            })?;

        thread::Builder::new().name("ebpf".into()).spawn(move || {
            // The object must outlive the attached programs.
            let _bpf = bpf;
            let mut ring = ring;
            let me = std::process::id();
            let mut watched = Watched::build();
            let mut built = Instant::now();
            let mut seen: HashMap<(PathBuf, u32), Instant> = HashMap::new();
            loop {
                {
                    let mut fds = [PollFd::new(ring.as_fd(), PollFlags::POLLIN)];
                    let _ = poll(&mut fds, PollTimeout::from(1000u16));
                }
                if built.elapsed() > Duration::from_secs(300) {
                    watched = Watched::build();
                    built = Instant::now();
                    seen.retain(|_, t| t.elapsed() < Duration::from_secs(600));
                }
                while let Some(item) = ring.next() {
                    let Some(ev) = parse(&item) else { continue };
                    drop(item);
                    if ev.pid == me {
                        continue;
                    }
                    match ev.kind {
                        KIND_WRITE => {
                            let Some(path) = resolve(&ev.path, ev.pid, ev.dirfd) else {
                                continue;
                            };
                            if !watched.matches(&path) {
                                continue;
                            }
                            let info = proc::info(ev.pid as i32);
                            let exe = fs::read_link(format!("/proc/{}/exe", ev.pid))
                                .ok()
                                .map(|p| p.to_string_lossy().into_owned());
                            log::debug!("{} wrote {}", ev.comm, path.display());
                            writers.lock().unwrap_or_else(|e| e.into_inner()).record(
                                path,
                                Writer {
                                    pid: ev.pid,
                                    uid: ev.uid,
                                    comm: ev.comm.clone(),
                                    info,
                                    exe,
                                    at: Instant::now(),
                                },
                            );
                        }
                        KIND_EXEC => handle_exec(&ev, &scan_tx, &mut seen),
                        _ => {}
                    }
                }
            }
        })?;
        Ok(())
    }
}

#[cfg_attr(not(wachposten_bpf), allow(dead_code))]
fn handle_exec(
    ev: &RawEvent,
    scan_tx: &Sender<(PathBuf, ProcInfo, String, Vec<Finding>)>,
    seen: &mut HashMap<(PathBuf, u32), Instant>,
) {
    if let Some(exe) = memfd_exe(ev) {
        // Scanned through /proc, which still reaches the memory file.
        let path = PathBuf::from(format!("/proc/{}/exe", ev.pid));
        let finding = Finding {
            rule: "memfd".into(),
            line: exe.clone(),
        };
        let _ = scan_tx.send((path, proc::info(ev.pid as i32), exe, vec![finding]));
        return;
    }
    let Some(program) = resolve(&ev.path, ev.pid, ev.dirfd) else {
        return;
    };
    // Programs started directly from a temporary folder are fanotify's job.
    if temp_root(&program).is_some() {
        return;
    }
    let Some(script) = script_in_temp(ev, &program) else {
        return;
    };
    let mtime = fs::metadata(&script)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as u32);
    let key = (script.clone(), mtime);
    if seen
        .get(&key)
        .is_some_and(|t| t.elapsed() < Duration::from_secs(600))
    {
        return;
    }
    seen.insert(key, Instant::now());
    let via = program
        .file_name()
        .map_or_else(|| ev.comm.clone(), |n| n.to_string_lossy().into_owned());
    let _ = scan_tx.send((script, proc::info(ev.pid as i32), via, Vec::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(path: &str, args: &[&str]) -> RawEvent {
        RawEvent {
            kind: KIND_EXEC,
            pid: std::process::id(),
            uid: 1000,
            dirfd: AT_FDCWD,
            flags: 0,
            comm: "x".into(),
            path: path.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn parses_events() {
        let mut b = vec![0u8; EVENT_LEN];
        b[0..4].copy_from_slice(&KIND_EXEC.to_ne_bytes());
        b[4..8].copy_from_slice(&42u32.to_ne_bytes());
        b[12..16].copy_from_slice(&(-100i32).to_ne_bytes());
        b[24..30].copy_from_slice(b"python");
        b[40..53].copy_from_slice(b"/usr/bin/pyth");
        b[296..303].copy_from_slice(b"python3");
        b[424..436].copy_from_slice(b"/tmp/evil.py");
        let ev = parse(&b).unwrap();
        assert_eq!(ev.pid, 42);
        assert_eq!(ev.dirfd, -100);
        assert_eq!(ev.comm, "python");
        assert_eq!(ev.args, ["python3", "/tmp/evil.py"]);
        assert!(parse(&b[..100]).is_none());
    }

    #[test]
    fn resolves_paths() {
        assert_eq!(
            resolve("/tmp/../etc/./x", 1, AT_FDCWD).unwrap(),
            PathBuf::from("/etc/x")
        );
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve("a/b", std::process::id(), AT_FDCWD).unwrap(),
            cwd.join("a/b")
        );
    }

    #[test]
    fn finds_scripts_in_temp_folders() {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let script = dir.path().join("inst.sh");
        fs::write(&script, "echo hi").unwrap();
        let s = script.to_string_lossy();
        let bash = Path::new("/usr/bin/bash");
        assert_eq!(
            script_in_temp(&raw("/usr/bin/bash", &["bash", "-x", &s]), bash),
            Some(script.clone())
        );
        assert_eq!(
            script_in_temp(
                &raw("/usr/bin/python3", &["python3", &s]),
                Path::new("/usr/bin/python3.14")
            ),
            Some(script.clone())
        );
        assert_eq!(
            script_in_temp(&raw("/usr/bin/bash", &["bash", "-c", &s]), bash),
            None
        );
        assert_eq!(
            script_in_temp(&raw("/usr/bin/ls", &["ls", &s]), Path::new("/usr/bin/ls")),
            None
        );
        assert_eq!(
            script_in_temp(&raw("/usr/bin/bash", &["bash", "/etc/profile"]), bash),
            None
        );
    }
}
