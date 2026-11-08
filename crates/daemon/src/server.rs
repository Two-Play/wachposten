//! The Unix socket for agents and the CLI. Callers are identified by `SO_PEERCRED`.

use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use wachposten_core::ipc::{self, Reply, Request};

use crate::{Msg, users};

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
            for stream in listener.incoming().flatten() {
                let tx = tx.clone();
                let groups = admin_groups.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(stream, &groups, &tx) {
                        log::debug!("client: {e:#}");
                    }
                });
            }
        })?;
    Ok(())
}

fn handle(stream: UnixStream, groups: &[String], tx: &Sender<Msg>) -> Result<()> {
    let uid = getsockopt(&stream, PeerCredentials)?.uid();
    let admin = users::is_admin(uid, groups);
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request) = ipc::read_line::<Request>(&mut reader)? else {
        return Ok(());
    };
    if let Request::Subscribe = request {
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
