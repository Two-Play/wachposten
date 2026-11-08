//! MalwareBazaar (abuse.ch) exports and lookups. Every request needs the person's own Auth-Key
//! from https://auth.abuse.ch/. abuse.ch allows free use for non-commercial purposes only.

use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::hashdb::{HashDb, KnownHash, parse_list};

const EXPORT_BASE: &str = "https://mb-api.abuse.ch/v2/files/exports";
const API: &str = "https://mb-api.abuse.ch/api/v1/";
const USER_AGENT: &str = concat!("wachposten/", env!("CARGO_PKG_VERSION"));

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .user_agent(USER_AGENT)
        .build()
        .into()
}

fn check_key(key: &str) -> Result<()> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("the Auth-Key may only contain letters and digits");
    }
    Ok(())
}

/// Download the hashes of the last 48 hours and add them. Returns (received, new).
pub fn update_recent(db: &HashDb, key: &str) -> Result<(usize, usize)> {
    check_key(key)?;
    let url = format!("{EXPORT_BASE}/{key}/recent.csv");
    let body = agent()
        .get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("MalwareBazaar export failed: {e}"))?
        .into_body()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()?;
    let list = parse_list(body.as_slice())?;
    if list.is_empty() {
        bail!("MalwareBazaar returned no hashes; check the Auth-Key");
    }
    let added = db.insert(&list, "malwarebazaar-recent")?;
    db.set_meta("updated_at", &crate::now().to_string())?;
    Ok((list.len(), added))
}

/// Import a list downloaded by hand: CSV or plain text, optionally inside a ZIP file.
pub fn import_file(db: &HashDb, path: &Path) -> Result<(usize, usize)> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic)?;
    file.rewind()?;
    let list: Vec<KnownHash> = if n == 4 && magic == *b"PK\x03\x04" {
        let mut archive = zip::ZipArchive::new(file)?;
        let mut all = Vec::new();
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            if entry.is_file() {
                all.extend(parse_list(entry)?);
            }
        }
        all
    } else {
        parse_list(file)?
    };
    let added = db.insert(&list, "import")?;
    db.set_meta("imported_at", &crate::now().to_string())?;
    Ok((list.len(), added))
}

/// Ask MalwareBazaar about one hash. Returns the signature name (or "unknown family") if known.
pub fn lookup(key: &str, sha256: &str) -> Result<Option<String>> {
    check_key(key)?;
    let text = agent()
        .post(API)
        .header("Auth-Key", key)
        .send_form([("query", "get_info"), ("hash", sha256)])
        .map_err(|e| anyhow::anyhow!("MalwareBazaar lookup failed: {e}"))?
        .into_body()
        .read_to_string()?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    match json["query_status"].as_str() {
        Some("ok") => Ok(Some(
            json["data"][0]["signature"]
                .as_str()
                .unwrap_or("unknown family")
                .to_string(),
        )),
        Some("hash_not_found") => Ok(None),
        other => bail!("MalwareBazaar answered {other:?}"),
    }
}
