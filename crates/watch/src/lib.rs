//! A small inotify watcher that reports "something relevant changed" for a set of directories,
//! each with an optional list of names that matter. Bursts of events are folded into one report.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

/// A directory to watch and the names in it that matter. `None` means all names.
pub type Spec = (PathBuf, Option<Vec<String>>);

/// Quiet time that ends a burst of events.
const QUIET: Duration = Duration::from_millis(300);
/// A burst is reported after this long even if events keep coming.
const MAX_BURST: Duration = Duration::from_secs(2);

struct Watched {
    dir: PathBuf,
    names: Option<HashSet<OsString>>,
}

pub struct Watcher {
    inotify: Inotify,
    watches: HashMap<WatchDescriptor, Watched>,
    buffer: Vec<u8>,
}

fn mask() -> WatchMask {
    WatchMask::CREATE
        | WatchMask::CLOSE_WRITE
        | WatchMask::MODIFY
        | WatchMask::ATTRIB
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::DELETE
        | WatchMask::DELETE_SELF
        | WatchMask::MOVE_SELF
        | WatchMask::DONT_FOLLOW
        | WatchMask::ONLYDIR
}

impl Watcher {
    pub fn new() -> io::Result<Watcher> {
        Ok(Watcher {
            inotify: Inotify::init()?,
            watches: HashMap::new(),
            buffer: vec![0; 64 * 1024],
        })
    }

    /// Replace the watched directories. Directories that cannot be watched are skipped.
    pub fn set_specs(&mut self, specs: &[Spec]) {
        let wanted: HashMap<&PathBuf, &Option<Vec<String>>> =
            specs.iter().map(|(d, n)| (d, n)).collect();

        let stale: Vec<WatchDescriptor> = self
            .watches
            .iter()
            .filter(|(_, w)| !wanted.contains_key(&w.dir))
            .map(|(wd, _)| wd.clone())
            .collect();
        for wd in stale {
            self.watches.remove(&wd);
            // Fails if the directory is already gone; the kernel dropped the watch then.
            let _ = self.inotify.watches().remove(wd);
        }

        for (dir, names) in specs {
            let names = names
                .as_ref()
                .map(|n| n.iter().map(OsString::from).collect::<HashSet<_>>());
            match self.inotify.watches().add(dir, mask()) {
                Ok(wd) => {
                    self.watches.insert(
                        wd,
                        Watched {
                            dir: dir.clone(),
                            names,
                        },
                    );
                }
                Err(e) => log::debug!("cannot watch {}: {e}", dir.display()),
            }
        }
    }

    /// Number of directories currently watched.
    pub fn len(&self) -> usize {
        self.watches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.watches.is_empty()
    }

    fn readable(&self, timeout: Duration) -> io::Result<bool> {
        let mut fds = [PollFd::new(self.inotify.as_fd(), PollFlags::POLLIN)];
        let timeout = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
        match poll(&mut fds, timeout) {
            Ok(n) => Ok(n > 0),
            Err(nix::errno::Errno::EINTR) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Read pending events and return whether any of them matter.
    fn drain(&mut self) -> io::Result<bool> {
        let mut relevant = false;
        let mut gone = Vec::new();
        loop {
            let events = match self.inotify.read_events(&mut self.buffer) {
                Ok(ev) => ev,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            let mut any = false;
            for event in events {
                any = true;
                if event.mask.contains(EventMask::Q_OVERFLOW) {
                    relevant = true;
                    continue;
                }
                if event.mask.contains(EventMask::IGNORED) {
                    gone.push(event.wd.clone());
                    relevant = true;
                    continue;
                }
                let Some(watched) = self.watches.get(&event.wd) else {
                    continue;
                };
                relevant |= match (&watched.names, event.name) {
                    (_, None) => true,
                    (None, Some(_)) => true,
                    (Some(names), Some(name)) => names.contains(name),
                };
            }
            if !any {
                break;
            }
        }
        for wd in gone {
            self.watches.remove(&wd);
        }
        Ok(relevant)
    }

    /// Wait up to `timeout` for a relevant change. Returns `true` once a burst of events has
    /// settled, `false` on timeout.
    pub fn wait(&mut self, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if !self.readable(left)? {
                return Ok(false);
            }
            if self.drain()? {
                break;
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
        let start = Instant::now();
        while start.elapsed() < MAX_BURST && self.readable(QUIET)? {
            self.drain()?;
        }
        Ok(true)
    }
}

/// Handle to a watcher running in its own thread.
#[derive(Clone)]
pub struct WatchHandle {
    pending: Arc<Mutex<Option<Vec<Spec>>>>,
}

impl WatchHandle {
    /// Replace the watched directories; takes effect within half a second.
    pub fn set_specs(&self, specs: Vec<Spec>) {
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(specs);
    }
}

/// Run a watcher in a background thread and call `on_change` after each relevant burst.
pub fn spawn(on_change: impl Fn() + Send + 'static) -> io::Result<WatchHandle> {
    let mut watcher = Watcher::new()?;
    let pending: Arc<Mutex<Option<Vec<Spec>>>> = Arc::default();
    let handle = WatchHandle {
        pending: pending.clone(),
    };
    thread::Builder::new().name("watch".into()).spawn(move || {
        loop {
            let next = pending.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(specs) = next {
                watcher.set_specs(&specs);
            }
            match watcher.wait(Duration::from_millis(500)) {
                Ok(true) => on_change(),
                Ok(false) => {}
                Err(e) => {
                    log::error!("watcher failed: {e}");
                    thread::sleep(Duration::from_secs(5));
                }
            }
        }
    })?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reports_only_relevant_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watcher::new().unwrap();
        w.set_specs(&[(dir.path().to_path_buf(), Some(vec![".bashrc".into()]))]);
        assert_eq!(w.len(), 1);

        fs::write(dir.path().join(".zsh_history"), "ls").unwrap();
        assert!(!w.wait(Duration::from_millis(200)).unwrap());

        fs::write(dir.path().join(".bashrc"), "x").unwrap();
        assert!(w.wait(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn folds_bursts_and_handles_removed_dirs() {
        let root = tempfile::tempdir().unwrap();
        let sub = root.path().join("autostart");
        fs::create_dir(&sub).unwrap();
        let mut w = Watcher::new().unwrap();
        w.set_specs(&[(sub.clone(), None)]);

        for i in 0..20 {
            fs::write(sub.join(format!("{i}.desktop")), "x").unwrap();
        }
        assert!(w.wait(Duration::from_secs(2)).unwrap());
        assert!(!w.wait(Duration::from_millis(100)).unwrap());

        fs::remove_dir_all(&sub).unwrap();
        assert!(w.wait(Duration::from_secs(2)).unwrap());
        assert!(w.is_empty());
    }
}
