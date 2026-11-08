//! Reports finished files in a set of folders, such as the download folder. A file counts as
//! finished once it was closed after writing or moved in, and nothing happened to it for a
//! moment. Browser partial files are ignored; their final rename is what counts.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

/// A file is reported after this long without further events.
const SETTLE: Duration = Duration::from_secs(2);
/// How often missing folders are looked for again.
const RETRY: Duration = Duration::from_secs(30);

const PARTIAL_SUFFIXES: [&str; 6] = [
    ".part",
    ".crdownload",
    ".download",
    ".tmp",
    ".partial",
    ".opdownload",
];

pub fn is_partial(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with(".goutputstream") || PARTIAL_SUFFIXES.iter().any(|s| name.ends_with(s))
}

struct State {
    inotify: Inotify,
    dirs: Vec<PathBuf>,
    watches: HashMap<WatchDescriptor, PathBuf>,
    pending: HashMap<PathBuf, Instant>,
    last_retry: Option<Instant>,
}

impl State {
    fn ensure_watches(&mut self) {
        if self.last_retry.is_some_and(|t| t.elapsed() < RETRY) {
            return;
        }
        self.last_retry = Some(Instant::now());
        for dir in &self.dirs {
            if self.watches.values().any(|d| d == dir) || !dir.is_dir() {
                continue;
            }
            let mask = WatchMask::CLOSE_WRITE
                | WatchMask::MOVED_TO
                | WatchMask::MODIFY
                | WatchMask::ONLYDIR;
            match self.inotify.watches().add(dir, mask) {
                Ok(wd) => {
                    log::info!("watching downloads in {}", dir.display());
                    self.watches.insert(wd, dir.clone());
                }
                Err(e) => log::warn!("cannot watch {}: {e}", dir.display()),
            }
        }
    }

    fn read(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        loop {
            let events = match self.inotify.read_events(buffer) {
                Ok(ev) => ev,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            };
            let mut any = false;
            for event in events {
                any = true;
                if event.mask.contains(EventMask::IGNORED) {
                    self.watches.remove(&event.wd);
                    self.last_retry = None;
                    continue;
                }
                if event.mask.contains(EventMask::ISDIR) {
                    continue;
                }
                let (Some(dir), Some(name)) = (self.watches.get(&event.wd), event.name) else {
                    continue;
                };
                if is_partial(name) {
                    continue;
                }
                self.pending.insert(dir.join(name), Instant::now());
            }
            if !any {
                return Ok(());
            }
        }
    }

    fn take_settled(&mut self) -> Vec<PathBuf> {
        let settled: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, t)| t.elapsed() >= SETTLE)
            .map(|(p, _)| p.clone())
            .collect();
        for p in &settled {
            self.pending.remove(p);
        }
        settled.into_iter().filter(|p| p.is_file()).collect()
    }
}

/// Watch `dirs` (not recursively) in a background thread and call `on_file` for every finished
/// file. Folders that do not exist yet are picked up once they appear.
pub fn spawn_files(
    dirs: Vec<PathBuf>,
    on_file: impl Fn(PathBuf) + Send + 'static,
) -> io::Result<()> {
    let mut state = State {
        inotify: Inotify::init()?,
        dirs,
        watches: HashMap::new(),
        pending: HashMap::new(),
        last_retry: None,
    };
    thread::Builder::new()
        .name("downloads".into())
        .spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                state.ensure_watches();
                let mut fds = [PollFd::new(state.inotify.as_fd(), PollFlags::POLLIN)];
                let _ = poll(&mut fds, PollTimeout::from(500u16));
                if let Err(e) = state.read(&mut buffer) {
                    log::error!("download watcher failed: {e}");
                    thread::sleep(Duration::from_secs(5));
                }
                for path in state.take_settled() {
                    on_file(path);
                }
            }
        })?;
    Ok(())
}

/// Whether `path` is directly inside one of `dirs`.
pub fn in_dirs(path: &Path, dirs: &[PathBuf]) -> bool {
    path.parent().is_some_and(|p| dirs.iter().any(|d| d == p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::mpsc;

    #[test]
    fn partial_names() {
        assert!(is_partial(OsStr::new("setup.exe.part")));
        assert!(is_partial(OsStr::new("Unconfirmed 1.crdownload")));
        assert!(!is_partial(OsStr::new("setup.exe")));
    }

    #[test]
    fn reports_finished_files_once() {
        let root = tempfile::tempdir().unwrap();
        let dl = root.path().join("Downloads");
        let (tx, rx) = mpsc::channel();
        spawn_files(vec![dl.clone()], move |p| tx.send(p).unwrap()).unwrap();
        // The folder appears after the watcher started.
        fs::create_dir(&dl).unwrap();
        thread::sleep(Duration::from_millis(100));
        // Missing folders are looked for again every RETRY, so keep writing until it is seen.
        let deadline = Instant::now() + RETRY + Duration::from_secs(5);
        let part = dl.join("tool.tar.gz.part");
        loop {
            fs::write(&part, "data").unwrap();
            fs::rename(&part, dl.join("tool.tar.gz")).unwrap();
            if let Ok(p) = rx.recv_timeout(Duration::from_secs(4)) {
                assert_eq!(p, dl.join("tool.tar.gz"));
                break;
            }
            assert!(Instant::now() < deadline, "no file reported");
        }
        assert!(rx.recv_timeout(Duration::from_secs(3)).is_err());
    }
}
