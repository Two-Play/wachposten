//! User settings in `$XDG_CONFIG_HOME/wachposten/config.toml`.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub downloads: Downloads,
    pub yara: Yara,
    pub hashes: Hashes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Downloads {
    /// Scan new files in the download folders.
    pub enabled: bool,
    /// Folders to watch. Empty means the XDG download folder.
    pub dirs: Vec<PathBuf>,
    /// Larger files are only checked against the hash list.
    pub max_scan_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Yara {
    pub enabled: bool,
    /// Extra folders with `.yar` / `.yara` files, added to the built-in rules.
    pub extra_rule_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Hashes {
    /// Personal MalwareBazaar Auth-Key. Without it no hash list is downloaded.
    pub malwarebazaar_auth_key: Option<String>,
    /// How often the list of recent hashes is fetched.
    pub update_hours: u64,
    /// Also ask MalwareBazaar about single downloads. This sends their SHA-256 hash.
    pub online_lookup: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            downloads: Downloads {
                enabled: true,
                dirs: Vec::new(),
                max_scan_mb: 256,
            },
            yara: Yara {
                enabled: true,
                extra_rule_dirs: Vec::new(),
            },
            hashes: Hashes {
                malwarebazaar_auth_key: None,
                update_hours: 6,
                online_lookup: false,
            },
        }
    }
}

impl Default for Downloads {
    fn default() -> Self {
        Settings::default().downloads
    }
}

impl Default for Yara {
    fn default() -> Self {
        Settings::default().yara
    }
}

impl Default for Hashes {
    fn default() -> Self {
        Settings::default().hashes
    }
}

pub fn config_dir(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
        .join("wachposten")
}

pub fn settings_path(home: &Path) -> PathBuf {
    config_dir(home).join("config.toml")
}

impl Settings {
    /// Load the settings; a missing file gives the defaults.
    pub fn load(home: &Path) -> Result<Settings> {
        let path = settings_path(home);
        match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Save with mode 0600, since the file may hold an Auth-Key.
    pub fn save(&self, home: &Path) -> Result<()> {
        let path = settings_path(home);
        let dir = config_dir(home);
        fs::create_dir_all(&dir)?;
        let tmp = dir.join(".config.toml.tmp");
        fs::write(&tmp, toml::to_string_pretty(self)?)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// The folders to watch for downloads.
    pub fn download_dirs(&self, home: &Path) -> Vec<PathBuf> {
        if !self.downloads.dirs.is_empty() {
            return self.downloads.dirs.clone();
        }
        vec![xdg_download_dir(home)]
    }
}

/// `XDG_DOWNLOAD_DIR` from `user-dirs.dirs`, or `~/Downloads`.
pub fn xdg_download_dir(home: &Path) -> PathBuf {
    let file = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("user-dirs.dirs");
    if let Ok(text) = fs::read_to_string(file) {
        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") {
                let value = value.trim().trim_matches('"');
                let path = match value.strip_prefix("$HOME") {
                    Some(rest) => home.join(rest.trim_start_matches('/')),
                    None => PathBuf::from(value),
                };
                if path.is_absolute() && path != home {
                    return path;
                }
            }
        }
    }
    home.join("Downloads")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_file_keeps_defaults() {
        let s: Settings = toml::from_str("[hashes]\nmalwarebazaar_auth_key = \"k\"\n").unwrap();
        assert_eq!(s.hashes.malwarebazaar_auth_key.as_deref(), Some("k"));
        assert_eq!(s.hashes.update_hours, 6);
        assert!(s.downloads.enabled);
        assert!(toml::from_str::<Settings>("[hashes]\ntypo = 1\n").is_err());
    }

    #[test]
    fn reads_user_dirs() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".config")).unwrap();
        fs::write(
            home.path().join(".config/user-dirs.dirs"),
            "XDG_DOWNLOAD_DIR=\"$HOME/Herunterladen\"\n",
        )
        .unwrap();
        // Only valid when XDG_CONFIG_HOME is not set in the test environment.
        if std::env::var_os("XDG_CONFIG_HOME").is_none() {
            assert_eq!(
                xdg_download_dir(home.path()),
                home.path().join("Herunterladen")
            );
        }
    }
}
