//! Local list of known malware hashes, filled from MalwareBazaar exports.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

/// A known sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHash {
    pub sha256: String,
    pub signature: Option<String>,
    pub first_seen: Option<String>,
}

pub struct HashDb {
    conn: Mutex<Connection>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Split one CSV line, honouring double quotes.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields.into_iter().map(|f| f.trim().to_string()).collect()
}

/// Parse a MalwareBazaar CSV export or a plain list with one SHA-256 per line.
/// The CSV header is a comment line naming the columns, e.g. `# "first_seen_utc","sha256_hash",…`.
pub fn parse_list(reader: impl Read) -> Result<Vec<KnownHash>> {
    let mut columns: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();
    for line in BufReader::new(reader).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            if comment.contains("sha256_hash") {
                columns = split_csv(comment.trim())
                    .into_iter()
                    .enumerate()
                    .map(|(i, name)| (name, i))
                    .collect();
            }
            continue;
        }
        let fields = split_csv(line);
        let get = |name: &str| {
            columns
                .get(name)
                .and_then(|&i| fields.get(i))
                .map(|s| s.as_str())
                .filter(|s| !s.is_empty() && *s != "n/a")
        };
        let sha = get("sha256_hash")
            .map(str::to_string)
            .or_else(|| fields.iter().find(|f| is_sha256(f)).cloned());
        let Some(sha) = sha.filter(|s| is_sha256(s)) else {
            continue;
        };
        out.push(KnownHash {
            sha256: sha.to_ascii_lowercase(),
            signature: get("signature").map(str::to_string),
            first_seen: get("first_seen_utc").map(str::to_string),
        });
    }
    Ok(out)
}

impl HashDb {
    pub fn open(path: &Path) -> Result<HashDb> {
        let conn =
            Connection::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hashes (
                 sha256 TEXT PRIMARY KEY,
                 signature TEXT,
                 first_seen TEXT,
                 source TEXT NOT NULL,
                 added_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS lookups (
                 sha256 TEXT PRIMARY KEY,
                 found INTEGER NOT NULL,
                 checked_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        Ok(HashDb {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn lookup(&self, sha256: &str) -> Result<Option<KnownHash>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT sha256, signature, first_seen FROM hashes WHERE sha256 = ?1",
                [sha256],
                |r| {
                    Ok(KnownHash {
                        sha256: r.get(0)?,
                        signature: r.get(1)?,
                        first_seen: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Add hashes; returns how many were new.
    pub fn insert(&self, hashes: &[KnownHash], source: &str) -> Result<usize> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut added = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO hashes (sha256, signature, first_seen, source, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            let t = now();
            for h in hashes {
                added += stmt.execute(params![h.sha256, h.signature, h.first_seen, source, t])?;
            }
        }
        tx.commit()?;
        Ok(added)
    }

    pub fn count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM hashes", [], |r| r.get(0))?)
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            [key, value],
        )?;
        Ok(())
    }

    /// Cached result of an online lookup younger than `max_age`.
    pub fn cached_lookup(&self, sha256: &str, max_age: Duration) -> Result<Option<bool>> {
        let min = now() - max_age.as_secs() as i64;
        Ok(self
            .conn()
            .query_row(
                "SELECT found FROM lookups WHERE sha256 = ?1 AND checked_at >= ?2",
                params![sha256, min],
                |r| r.get::<_, bool>(0),
            )
            .optional()?)
    }

    pub fn cache_lookup(&self, sha256: &str, found: bool) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO lookups (sha256, found, checked_at) VALUES (?1, ?2, ?3)",
            params![sha256, found, now()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn parses_bazaar_csv() {
        let csv = format!(
            "################\n# MalwareBazaar recent\n\
             # \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\"\n\
             \"2026-11-08 10:00:00\",\"{A}\",\"x\",\"y\",\"r\",\"a, b.exe\",\"exe\",\"app\",\"AgentTesla\"\n\
             \"2026-11-08 11:00:00\",\"{B}\",\"x\",\"y\",\"r\",\"c.sh\",\"sh\",\"text\",\"n/a\"\n"
        );
        let list = parse_list(csv.as_bytes()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].signature.as_deref(), Some("AgentTesla"));
        assert_eq!(list[0].first_seen.as_deref(), Some("2026-11-08 10:00:00"));
        assert_eq!(list[1].sha256, B.to_ascii_lowercase());
        assert_eq!(list[1].signature, None);
    }

    #[test]
    fn parses_plain_list_and_stores() {
        let list = parse_list(format!("# comment\n{A}\nnot-a-hash\n").as_bytes()).unwrap();
        assert_eq!(list.len(), 1);
        let dir = tempfile::tempdir().unwrap();
        let db = HashDb::open(&dir.path().join("h.db")).unwrap();
        assert_eq!(db.insert(&list, "test").unwrap(), 1);
        assert_eq!(db.insert(&list, "test").unwrap(), 0);
        assert!(db.lookup(A).unwrap().is_some());
        assert_eq!(db.count().unwrap(), 1);
        db.cache_lookup(B, false).unwrap();
        assert_eq!(
            db.cached_lookup(B, Duration::from_secs(60)).unwrap(),
            Some(false)
        );
    }
}
