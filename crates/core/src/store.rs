//! SQLite storage for the baseline, events and quarantine records.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::model::{Change, Entry, Event, Finding, Kind, QuarantineItem, Severity, Status};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS baseline (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    hash TEXT NOT NULL,
    mode INTEGER NOT NULL,
    size INTEGER NOT NULL,
    content BLOB,
    link_target TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    change TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    old_hash TEXT NOT NULL,
    new_type TEXT,
    new_hash TEXT,
    new_mode INTEGER,
    new_size INTEGER,
    new_content BLOB,
    new_link_target TEXT,
    findings TEXT NOT NULL,
    added_lines TEXT NOT NULL,
    resolved_at INTEGER,
    quarantine_id INTEGER
);
CREATE INDEX IF NOT EXISTS events_open ON events (status, path);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    original_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    mode INTEGER NOT NULL,
    link_target TEXT,
    hash TEXT NOT NULL,
    event_id INTEGER,
    restored_at INTEGER
);
";

pub struct Store {
    conn: Connection,
}

/// Columns of an entry in the order `entry_type, hash, mode, size, content, link_target`.
type EntryCols = (
    Option<String>,
    Option<String>,
    Option<u32>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<String>,
);

fn entry_cols(entry: Option<&Entry>) -> EntryCols {
    match entry {
        None => (None, None, None, None, None, None),
        Some(Entry::File {
            hash,
            mode,
            size,
            content,
        }) => (
            Some("file".into()),
            Some(hash.clone()),
            Some(*mode),
            Some(*size as i64),
            content.clone(),
            None,
        ),
        Some(Entry::Symlink { hash, target }) => (
            Some("symlink".into()),
            Some(hash.clone()),
            Some(0o777),
            Some(0),
            None,
            Some(target.clone()),
        ),
    }
}

fn entry_from_cols(cols: EntryCols) -> Option<Entry> {
    let (ty, hash, mode, size, content, link) = cols;
    match ty.as_deref()? {
        "symlink" => Some(Entry::Symlink {
            hash: hash?,
            target: link?,
        }),
        _ => Some(Entry::File {
            hash: hash?,
            mode: mode.unwrap_or(0o644),
            size: size.unwrap_or(0).max(0) as u64,
            content,
        }),
    }
}

fn parse<T: std::str::FromStr<Err = String>>(s: String) -> rusqlite::Result<T> {
    s.parse().map_err(|e: String| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, e.into())
    })
}

fn encode_findings(f: &[Finding]) -> String {
    f.iter()
        .map(|f| format!("{}\t{}", f.rule, f.line.replace(['\n', '\t'], " ")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn decode_findings(s: &str) -> Vec<Finding> {
    s.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (rule, line) = l.split_once('\t').unwrap_or((l, ""));
            Finding {
                rule: rule.into(),
                line: line.into(),
            }
        })
        .collect()
}

const EVENT_COLS: &str = "id, created_at, updated_at, path, kind, change, severity, status, old_hash, \
     new_type, new_hash, new_mode, new_size, new_content, new_link_target, findings, added_lines, \
     resolved_at, quarantine_id";

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        created_at: row.get(1)?,
        updated_at: row.get(2)?,
        path: row.get(3)?,
        kind: parse(row.get(4)?)?,
        change: parse(row.get(5)?)?,
        severity: parse(row.get(6)?)?,
        status: parse(row.get(7)?)?,
        old_hash: row.get(8)?,
        new_entry: entry_from_cols((
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
            row.get(14)?,
        )),
        findings: decode_findings(&row.get::<_, String>(15)?),
        added_lines: row
            .get::<_, String>(16)?
            .lines()
            .map(str::to_string)
            .collect(),
        resolved_at: row.get(17)?,
        quarantine_id: row.get(18)?,
    })
}

/// A new event, before it is stored.
pub struct NewEvent<'a> {
    pub path: &'a str,
    pub kind: Kind,
    pub change: Change,
    pub severity: Severity,
    pub status: Status,
    pub old_hash: &'a str,
    pub new_entry: Option<&'a Entry>,
    pub findings: &'a [Finding],
    pub added_lines: &'a [String],
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> rusqlite::Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Store> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&Store) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match f(self) {
            Ok(v) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn meta(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    pub fn baseline(&self) -> rusqlite::Result<BTreeMap<String, (Kind, Entry)>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, kind, entry_type, hash, mode, size, content, link_target FROM baseline",
        )?;
        let rows = stmt.query_map([], |r| {
            let kind: Kind = parse(r.get(1)?)?;
            let entry = entry_from_cols((
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ));
            Ok((r.get::<_, String>(0)?, kind, entry))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (path, kind, entry) = row?;
            if let Some(entry) = entry {
                out.insert(path, (kind, entry));
            }
        }
        Ok(out)
    }

    pub fn baseline_entry(&self, path: &str) -> rusqlite::Result<Option<Entry>> {
        self.conn
            .query_row(
                "SELECT entry_type, hash, mode, size, content, link_target FROM baseline WHERE path = ?1",
                [path],
                |r| Ok(entry_from_cols((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))),
            )
            .optional()
            .map(Option::flatten)
    }

    pub fn set_baseline(
        &self,
        path: &str,
        kind: Kind,
        entry: Option<&Entry>,
    ) -> rusqlite::Result<()> {
        let Some(entry) = entry else {
            self.conn
                .execute("DELETE FROM baseline WHERE path = ?1", [path])?;
            return Ok(());
        };
        let (ty, hash, mode, size, content, link) = entry_cols(Some(entry));
        self.conn.execute(
            "INSERT INTO baseline (path, kind, entry_type, hash, mode, size, content, link_target, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(path) DO UPDATE SET kind = excluded.kind, entry_type = excluded.entry_type,
               hash = excluded.hash, mode = excluded.mode, size = excluded.size,
               content = excluded.content, link_target = excluded.link_target,
               updated_at = excluded.updated_at",
            params![path, kind.as_str(), ty, hash, mode, size, content, link, now()],
        )?;
        Ok(())
    }

    pub fn baseline_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM baseline", [], |r| r.get(0))
    }

    pub fn insert_event(&self, e: &NewEvent<'_>) -> rusqlite::Result<i64> {
        let (ty, hash, mode, size, content, link) = entry_cols(e.new_entry);
        let t = now();
        let resolved = (e.status != Status::Open).then_some(t);
        self.conn.execute(
            "INSERT INTO events (created_at, updated_at, path, kind, change, severity, status, old_hash,
               new_type, new_hash, new_mode, new_size, new_content, new_link_target, findings, added_lines,
               resolved_at)
             VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                t,
                e.path,
                e.kind.as_str(),
                e.change.as_str(),
                e.severity.as_str(),
                e.status.as_str(),
                e.old_hash,
                ty,
                hash,
                mode,
                size,
                content,
                link,
                encode_findings(e.findings),
                e.added_lines.join("\n"),
                resolved
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Replace the described state of an open event, keeping its id.
    pub fn update_event(&self, id: i64, e: &NewEvent<'_>) -> rusqlite::Result<()> {
        let (ty, hash, mode, size, content, link) = entry_cols(e.new_entry);
        self.conn.execute(
            "UPDATE events SET updated_at = ?2, change = ?3, severity = ?4, new_type = ?5, new_hash = ?6,
               new_mode = ?7, new_size = ?8, new_content = ?9, new_link_target = ?10, findings = ?11,
               added_lines = ?12
             WHERE id = ?1",
            params![
                id,
                now(),
                e.change.as_str(),
                e.severity.as_str(),
                ty,
                hash,
                mode,
                size,
                content,
                link,
                encode_findings(e.findings),
                e.added_lines.join("\n")
            ],
        )?;
        Ok(())
    }

    pub fn resolve_event(
        &self,
        id: i64,
        status: Status,
        quarantine_id: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE events SET status = ?2, resolved_at = ?3, quarantine_id = COALESCE(?4, quarantine_id)
             WHERE id = ?1",
            params![id, status.as_str(), now(), quarantine_id],
        )?;
        Ok(())
    }

    pub fn event(&self, id: i64) -> rusqlite::Result<Option<Event>> {
        self.conn
            .query_row(
                &format!("SELECT {EVENT_COLS} FROM events WHERE id = ?1"),
                [id],
                event_from_row,
            )
            .optional()
    }

    pub fn open_event_for(&self, path: &str) -> rusqlite::Result<Option<Event>> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {EVENT_COLS} FROM events WHERE status = 'open' AND path = ?1 ORDER BY id DESC LIMIT 1"
                ),
                [path],
                event_from_row,
            )
            .optional()
    }

    pub fn open_events(&self) -> rusqlite::Result<Vec<Event>> {
        self.query_events("WHERE status = 'open' ORDER BY id", [])
    }

    pub fn recent_events(&self, limit: i64) -> rusqlite::Result<Vec<Event>> {
        self.query_events("ORDER BY id DESC LIMIT ?1", [limit])
    }

    fn query_events(&self, tail: &str, p: impl rusqlite::Params) -> rusqlite::Result<Vec<Event>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {EVENT_COLS} FROM events {tail}"))?;
        stmt.query_map(p, event_from_row)?.collect()
    }

    pub fn insert_quarantine(&self, q: &QuarantineItem) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO quarantine (created_at, original_path, kind, entry_type, mode, link_target, hash, event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now(),
                q.original_path,
                q.kind.as_str(),
                q.entry_type,
                q.mode,
                q.link_target,
                q.hash,
                q.event_id
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn mark_restored(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE quarantine SET restored_at = ?2 WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    fn quarantine_from_row(r: &Row<'_>) -> rusqlite::Result<QuarantineItem> {
        Ok(QuarantineItem {
            id: r.get(0)?,
            created_at: r.get(1)?,
            original_path: r.get(2)?,
            kind: parse(r.get(3)?)?,
            entry_type: r.get(4)?,
            mode: r.get(5)?,
            link_target: r.get(6)?,
            hash: r.get(7)?,
            event_id: r.get(8)?,
            restored_at: r.get(9)?,
        })
    }

    pub fn quarantine_item(&self, id: i64) -> rusqlite::Result<Option<QuarantineItem>> {
        self.conn
            .query_row(
                "SELECT id, created_at, original_path, kind, entry_type, mode, link_target, hash, event_id, restored_at
                 FROM quarantine WHERE id = ?1",
                [id],
                Self::quarantine_from_row,
            )
            .optional()
    }

    pub fn quarantine_items(&self) -> rusqlite::Result<Vec<QuarantineItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at, original_path, kind, entry_type, mode, link_target, hash, event_id, restored_at
             FROM quarantine ORDER BY id DESC",
        )?;
        stmt.query_map([], Self::quarantine_from_row)?.collect()
    }
}
