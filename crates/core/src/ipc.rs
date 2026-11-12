//! Protocol between the root daemon and the agents and CLI: one JSON object per line over the
//! Unix socket [`SOCKET`]. The daemon identifies callers by `SO_PEERCRED`, never by anything
//! they send.
//!
//! A connection that sends [`Request::Subscribe`] receives [`Reply::Hello`], then a
//! [`Reply::Event`] for every open event it may see, and afterwards one for every change. All
//! other requests get exactly one reply; the CLI and the agent's decisions use short
//! connections for them.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::{Entry, Event, QuarantineItem};

pub const SOCKET: &str = "/run/wachposten/daemon.sock";

/// Largest accepted line, to keep a misbehaving peer from filling memory.
pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allow,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "kebab-case")]
pub enum Request {
    Subscribe,
    Status,
    Events {
        all: bool,
        limit: i64,
    },
    Show {
        id: i64,
    },
    Decide {
        id: i64,
        /// Hash of the state the person saw; `None` from the CLI after `show`.
        hash: Option<String>,
        decision: Decision,
    },
    Quarantine,
    Restore {
        id: i64,
        force: bool,
    },
    /// Allowed program and download hashes.
    Allowlist,
    Revoke {
        hash: String,
    },
    /// Which programs recently wrote these paths. Only paths in the caller's home folder are
    /// answered, unless the caller is an admin.
    WhoWrote {
        paths: Vec<String>,
    },
    /// Look for clamd again now (after the person installed or started it).
    RecheckClamav,
}

// Replies only live while they cross the socket; boxing the large variant would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case")]
pub enum Reply {
    Hello {
        version: String,
        /// The caller may decide on system-wide events.
        admin: bool,
    },
    Event {
        event: Event,
        /// The caller may allow or remove it.
        can_decide: bool,
    },
    Events {
        events: Vec<Event>,
    },
    Status {
        baseline: i64,
        open: i64,
        exec_watch: bool,
        blocking: bool,
        yara_rules: usize,
        known_hashes: i64,
        #[serde(default)]
        clamav: bool,
        /// `off`, `not-installed`, `not-running` or `running`.
        #[serde(default)]
        clamav_state: String,
        #[serde(default)]
        ebpf: bool,
        /// The ransomware check runs.
        #[serde(default)]
        ransomware: bool,
        /// `/home` lies on btrfs.
        #[serde(default)]
        home_btrfs: bool,
        /// The tool that takes snapshots of `/home`, if any.
        #[serde(default)]
        snapshots: Option<String>,
    },
    Quarantine {
        items: Vec<QuarantineItem>,
    },
    Allowlist {
        items: Vec<crate::store::AllowedFile>,
    },
    /// One entry per asked path, in the same order.
    Writers {
        writers: Vec<Option<String>>,
    },
    Done {
        message: String,
    },
    Error {
        message: String,
    },
}

/// Events go over the wire without file contents.
pub fn strip(mut event: Event) -> Event {
    if let Some(Entry::File { content, .. }) = &mut event.new_entry {
        *content = None;
    }
    event
}

pub fn write_line<T: Serialize>(w: &mut impl Write, value: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

/// Read one line; `Ok(None)` at end of stream.
pub fn read_line<T: for<'de> Deserialize<'de>>(r: &mut impl BufRead) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    let n = io::Read::take(&mut *r, MAX_LINE as u64 + 1).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE {
        return Err(io::Error::other("line too long"));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(io::Error::other)
}

/// Send one request and wait for its reply.
pub fn call(socket: &Path, request: &Request) -> io::Result<Reply> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut writer = stream.try_clone()?;
    write_line(&mut writer, request)?;
    read_line(&mut BufReader::new(stream))?
        .ok_or_else(|| io::Error::other("daemon closed the connection"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_line(
            &mut buf,
            &Request::Decide {
                id: 3,
                hash: Some("abc".into()),
                decision: Decision::Remove,
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf),
            "{\"request\":\"decide\",\"id\":3,\"hash\":\"abc\",\"decision\":\"remove\"}\n"
        );
        let back: Request = read_line(&mut buf.as_slice()).unwrap().unwrap();
        assert!(matches!(back, Request::Decide { id: 3, .. }));
        assert!(read_line::<Request>(&mut &b""[..]).unwrap().is_none());
    }
}
