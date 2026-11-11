//! The Unix socket for agents and the CLI. Callers are identified by `SO_PEERCRED`.

use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use wachposten_core::ipc::{self, Reply, Request};

use crate::{Msg, users};

/// Connections handled at the same time, in all and per user. Every connection costs a thread
/// and a file descriptor of the root daemon, so one user must not be able to use them all up
/// (without free descriptors, fanotify would refuse every program start from /tmp).
const MAX_CONNECTIONS: usize = 64;
const MAX_PER_USER: usize = 8;
/// Subscribed agents per user.
pub const MAX_SUBSCRIBERS_PER_USER: usize = 4;

#[derive(Default)]
struct Slots {
    total: usize,
    per_user: HashMap<u32, usize>,
}

/// One taken connection slot, given back on drop.
struct Slot {
    slots: Arc<Mutex<Slots>>,
    uid: u32,
}

impl Slot {
    fn take(slots: &Arc<Mutex<Slots>>, uid: u32) -> Option<Slot> {
        let mut s = slots.lock().unwrap_or_else(|e| e.into_inner());
        let mine = s.per_user.get(&uid).copied().unwrap_or(0);
        if s.total >= MAX_CONNECTIONS || mine >= MAX_PER_USER {
            return None;
        }
        s.total += 1;
        s.per_user.insert(uid, mine + 1);
        Some(Slot {
            slots: slots.clone(),
            uid,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.per_user.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.per_user.remove(&self.uid);
            }
        }
    }
}

/// A subscribed agent.
pub struct Client {
    pub uid: u32,
    pub admin: bool,
    pub stream: UnixStream,
}

impl Client {
    pub fn send(&mut self, reply: &Reply) -> bool {
        ipc::write_line(&mut self.stream, reply).is_ok()
    }
}

pub fn listen(path: &Path, admin_groups: Vec<String>, tx: Sender<Msg>) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let _ = fs::remove_file(path);
    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot listen on {}", path.display()))?;
    // Everybody may connect; what a caller may do depends on who it is.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    thread::Builder::new()
        .name("socket".into())
        .spawn(move || {
            let slots = Arc::new(Mutex::new(Slots::default()));
            for stream in listener.incoming().flatten() {
                let Ok(uid) = getsockopt(&stream, PeerCredentials).map(|c| c.uid()) else {
                    continue;
                };
                let Some(slot) = Slot::take(&slots, uid) else {
                    log::warn!("too many connections, refusing one of uid {uid}");
                    continue; // dropping the stream closes it
                };
                let tx = tx.clone();
                let groups = admin_groups.clone();
                let spawned = thread::Builder::new().spawn(move || {
                    let _slot = slot;
                    if let Err(e) = handle(stream, uid, &groups, &tx) {
                        log::debug!("client: {e:#}");
                    }
                });
                if let Err(e) = spawned {
                    log::warn!("cannot start a client thread: {e}");
                }
            }
        })?;
    Ok(())
}

fn handle(stream: UnixStream, uid: u32, groups: &[String], tx: &Sender<Msg>) -> Result<()> {
    let admin = users::is_admin(uid, groups);
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request) = ipc::read_line::<Request>(&mut reader)? else {
        return Ok(());
    };
    if let Request::Subscribe = request {
        // A subscriber that does not read must not hold up the daemon for long.
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        let _ = tx.send(Msg::Subscribe(Client { uid, admin, stream }));
        return Ok(());
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(Msg::Request {
        uid,
        admin,
        request,
        reply: reply_tx,
    })?;
    let reply = reply_rx
        .recv_timeout(Duration::from_secs(120))
        .unwrap_or(Reply::Error {
            message: "the daemon did not answer in time".into(),
        });
    let mut writer = stream;
    ipc::write_line(&mut writer, &reply)?;
    Ok(())
}
