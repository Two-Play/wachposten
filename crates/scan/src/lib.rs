//! Known-malware detection: YARA-X rules and hash lists, behind the core's
//! [`FileScanner`](wachposten_core::FileScanner) trait.

pub mod bazaar;
pub mod hashdb;
pub mod yara;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use wachposten_core::scanner::MALWARE_RULE;
use wachposten_core::{FileScanner, Finding, Settings};

pub use hashdb::HashDb;
pub use yara::YaraEngine;

/// Online lookups are repeated at most this often per hash.
const LOOKUP_CACHE: Duration = Duration::from_secs(24 * 3600);

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Why a file was flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// `yara`, `hashlist` or `online`.
    pub source: &'static str,
    pub name: String,
    pub description: Option<String>,
}

impl Detection {
    pub fn label(&self) -> String {
        let source = match self.source {
            "yara" => "YARA",
            "hashlist" => "MalwareBazaar",
            _ => "MalwareBazaar online",
        };
        match &self.description {
            Some(d) => format!("{source}: {} ({d})", self.name),
            None => format!("{source}: {}", self.name),
        }
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn hash_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("hashes.db")
}

pub struct MalwareScanner {
    pub yara: Option<YaraEngine>,
    pub hashes: Option<HashDb>,
    online_key: Option<String>,
    max_scan_bytes: u64,
}

impl MalwareScanner {
    pub fn new(
        yara: Option<YaraEngine>,
        hashes: Option<HashDb>,
        online_key: Option<String>,
        max_scan_mb: u64,
    ) -> MalwareScanner {
        MalwareScanner {
            yara,
            hashes,
            online_key,
            max_scan_bytes: max_scan_mb.saturating_mul(1024 * 1024),
        }
    }

    pub fn from_settings(settings: &Settings, data_dir: &Path) -> MalwareScanner {
        let yara = settings
            .yara
            .enabled
            .then(|| YaraEngine::new(&settings.yara.extra_rule_dirs));
        let hashes = match HashDb::open(&hash_db_path(data_dir)) {
            Ok(db) => Some(db),
            Err(e) => {
                log::error!("hash list unavailable: {e:#}");
                None
            }
        };
        let online_key = settings
            .hashes
            .online_lookup
            .then(|| settings.hashes.malwarebazaar_auth_key.clone())
            .flatten();
        MalwareScanner::new(yara, hashes, online_key, settings.downloads.max_scan_mb)
    }

    /// Check one regular file. Errors are logged; an unreadable file gives no detections.
    pub fn scan_path(&self, path: &Path) -> Vec<Detection> {
        let Ok(meta) = std::fs::metadata(path) else {
            return Vec::new();
        };
        if !meta.is_file() || meta.len() == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();

        let sha = match sha256_file(path) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!("cannot hash {}: {e}", path.display());
                None
            }
        };
        if let (Some(db), Some(sha)) = (&self.hashes, &sha) {
            match db.lookup(sha) {
                Ok(Some(known)) => out.push(Detection {
                    source: "hashlist",
                    name: known.signature.unwrap_or_else(|| "known sample".into()),
                    description: None,
                }),
                Ok(None) => {
                    if let Some(key) = &self.online_key
                        && let Some(name) = self.online(db, key, sha)
                    {
                        out.push(Detection {
                            source: "online",
                            name,
                            description: None,
                        });
                    }
                }
                Err(e) => log::warn!("hash lookup failed: {e:#}"),
            }
        }

        if let Some(yara) = &self.yara
            && meta.len() <= self.max_scan_bytes
        {
            match yara.scan_file(path) {
                Ok(matches) => out.extend(matches.into_iter().map(|m| Detection {
                    source: "yara",
                    name: m.rule,
                    description: m.description,
                })),
                Err(e) => log::warn!("YARA scan of {} failed: {e:#}", path.display()),
            }
        }
        out
    }

    fn online(&self, db: &HashDb, key: &str, sha: &str) -> Option<String> {
        if let Ok(Some(false)) = db.cached_lookup(sha, LOOKUP_CACHE) {
            return None;
        }
        match bazaar::lookup(key, sha) {
            Ok(found) => {
                let _ = db.cache_lookup(sha, found.is_some());
                if let Some(name) = &found {
                    let _ = db.insert(
                        &[hashdb::KnownHash {
                            sha256: sha.to_string(),
                            signature: Some(name.clone()),
                            first_seen: None,
                        }],
                        "online",
                    );
                }
                found
            }
            Err(e) => {
                log::warn!("{e:#}");
                None
            }
        }
    }
}

impl FileScanner for MalwareScanner {
    fn scan(&self, path: &Path) -> Vec<Finding> {
        self.scan_path(path)
            .into_iter()
            .map(|d| Finding {
                rule: MALWARE_RULE.to_string(),
                line: format!("{} – {}", d.label(), path.display()),
            })
            .collect()
    }
}
