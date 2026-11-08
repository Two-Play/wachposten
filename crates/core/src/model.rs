//! Data types shared by the agent, the CLI and the store.

use std::fmt;
use std::str::FromStr;

/// What kind of persistence location an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// XDG autostart entries and KDE autostart scripts.
    Autostart,
    /// systemd user units, timers and their enablement symlinks.
    SystemdUser,
    /// Shell startup files such as `.bashrc` or `.profile`.
    ShellRc,
    /// Files read when a graphical session starts (`.xprofile`, Plasma env scripts).
    Session,
    /// Environment files (`environment.d`, `.pam_environment`).
    Environment,
    /// SSH login configuration (`authorized_keys`, `~/.ssh/rc`).
    Ssh,
    /// The user's crontab.
    Crontab,
    /// A file in a download folder that matched a malware signature or hash.
    Download,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::Autostart,
        Kind::SystemdUser,
        Kind::ShellRc,
        Kind::Session,
        Kind::Environment,
        Kind::Ssh,
        Kind::Crontab,
        Kind::Download,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Autostart => "autostart",
            Kind::SystemdUser => "systemd-user",
            Kind::ShellRc => "shell-rc",
            Kind::Session => "session",
            Kind::Environment => "environment",
            Kind::Ssh => "ssh",
            Kind::Crontab => "crontab",
            Kind::Download => "download",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Kind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| format!("unknown kind {s:?}"))
    }
}

/// The observed state of one watched path. A missing path has no `Entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    File {
        hash: String,
        mode: u32,
        size: u64,
        /// The content, unless the file is larger than [`crate::MAX_CONTENT`].
        content: Option<Vec<u8>>,
    },
    Symlink {
        hash: String,
        target: String,
    },
}

impl Entry {
    pub fn hash(&self) -> &str {
        match self {
            Entry::File { hash, .. } | Entry::Symlink { hash, .. } => hash,
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Entry::File { .. } => "file",
            Entry::Symlink { .. } => "symlink",
        }
    }

    /// The content as text, if it is a file with stored, valid UTF-8 content.
    pub fn text(&self) -> Option<&str> {
        match self {
            Entry::File {
                content: Some(c), ..
            } => std::str::from_utf8(c).ok(),
            _ => None,
        }
    }
}

/// Hash of an absent entry, used to compare states uniformly.
pub const ABSENT: &str = "absent";

pub fn hash_of(entry: Option<&Entry>) -> &str {
    entry.map_or(ABSENT, Entry::hash)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Modified,
    Deleted,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Created => "created",
            Change::Modified => "modified",
            Change::Deleted => "deleted",
        }
    }
}

impl FromStr for Change {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(Change::Created),
            "modified" => Ok(Change::Modified),
            "deleted" => Ok(Change::Deleted),
            _ => Err(format!("unknown change {s:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Recorded only, no question asked (for example a deleted entry).
    Info,
    /// A new or changed entry without suspicious content.
    Notice,
    /// At least one rule matched.
    Suspicious,
    /// A malware signature or hash matched.
    Malicious,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Suspicious => "suspicious",
            Severity::Malicious => "malicious",
        }
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Severity::Info),
            "notice" => Ok(Severity::Notice),
            "suspicious" => Ok(Severity::Suspicious),
            "malicious" => Ok(Severity::Malicious),
            _ => Err(format!("unknown severity {s:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Waiting for a decision.
    Open,
    /// The person allowed the change; it is now part of the baseline.
    Allowed,
    /// The person removed the change; the old state was restored.
    Removed,
    /// The change was undone by someone else before a decision.
    Reverted,
    /// Recorded without a question (deletions).
    Accepted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Allowed => "allowed",
            Status::Removed => "removed",
            Status::Reverted => "reverted",
            Status::Accepted => "accepted",
        }
    }
}

impl FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Status::Open),
            "allowed" => Ok(Status::Allowed),
            "removed" => Ok(Status::Removed),
            "reverted" => Ok(Status::Reverted),
            "accepted" => Ok(Status::Accepted),
            _ => Err(format!("unknown status {s:?}")),
        }
    }
}

/// One rule that matched in new or changed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule identifier, see [`crate::analyze`].
    pub rule: String,
    /// The line that matched, trimmed.
    pub line: String,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub id: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub path: String,
    pub kind: Kind,
    pub change: Change,
    pub severity: Severity,
    pub status: Status,
    pub old_hash: String,
    /// The state the event describes. `None` for deletions.
    pub new_entry: Option<Entry>,
    pub findings: Vec<Finding>,
    /// Lines added compared to the baseline (all lines for new text files).
    pub added_lines: Vec<String>,
    pub resolved_at: Option<i64>,
    pub quarantine_id: Option<i64>,
}

impl Event {
    pub fn new_hash(&self) -> &str {
        hash_of(self.new_entry.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct QuarantineItem {
    pub id: i64,
    pub created_at: i64,
    pub original_path: String,
    pub kind: Kind,
    pub entry_type: String,
    pub mode: u32,
    pub link_target: Option<String>,
    pub hash: String,
    pub event_id: Option<i64>,
    pub restored_at: Option<i64>,
}
