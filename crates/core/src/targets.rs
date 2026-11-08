//! The persistence locations in a home directory and how to read their state.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::model::{Entry, Kind};

/// Files larger than this are hashed but their content is not stored, so they cannot be restored.
pub const MAX_CONTENT: u64 = 1024 * 1024;

/// Virtual path used for the user's crontab.
pub const CRONTAB_PATH: &str = "crontab:user";

/// Which directory entries a directory target includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// `*.desktop`
    Desktop,
    /// Anything that is not a directory and not an editor temp file.
    Any,
    /// `*.sh`
    Shell,
    /// `*.conf`
    Conf,
    /// `*.fish`
    Fish,
    /// systemd unit files, drop-ins and enablement symlinks.
    SystemdUnits,
}

#[derive(Debug, Clone)]
pub enum TargetPath {
    File(PathBuf),
    Dir {
        path: PathBuf,
        recursive: bool,
        filter: Filter,
    },
    Crontab,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub kind: Kind,
    pub path: TargetPath,
}

const SYSTEMD_SUFFIXES: [&str; 11] = [
    "service",
    "socket",
    "timer",
    "path",
    "target",
    "mount",
    "automount",
    "slice",
    "scope",
    "swap",
    "conf",
];

/// All persistence locations for one home directory.
pub fn home_targets(home: &Path, crontab: bool) -> Vec<Target> {
    use Kind::*;
    let file = |kind, rel: &str| Target {
        kind,
        path: TargetPath::File(home.join(rel)),
    };
    let dir = |kind, rel: &str, recursive, filter| Target {
        kind,
        path: TargetPath::Dir {
            path: home.join(rel),
            recursive,
            filter,
        },
    };

    let mut targets = vec![
        dir(Autostart, ".config/autostart", false, Filter::Desktop),
        dir(Autostart, ".config/autostart-scripts", false, Filter::Any),
        dir(
            Session,
            ".config/plasma-workspace/env",
            false,
            Filter::Shell,
        ),
        dir(
            Session,
            ".config/plasma-workspace/shutdown",
            false,
            Filter::Shell,
        ),
        dir(
            SystemdUser,
            ".config/systemd/user",
            true,
            Filter::SystemdUnits,
        ),
        dir(
            SystemdUser,
            ".local/share/systemd/user",
            true,
            Filter::SystemdUnits,
        ),
        dir(Environment, ".config/environment.d", false, Filter::Conf),
        file(Environment, ".pam_environment"),
        file(Session, ".xprofile"),
        file(Session, ".xsessionrc"),
        file(Session, ".xinitrc"),
        file(Ssh, ".ssh/authorized_keys"),
        file(Ssh, ".ssh/authorized_keys2"),
        file(Ssh, ".ssh/rc"),
        dir(ShellRc, ".config/fish/conf.d", false, Filter::Fish),
        file(ShellRc, ".config/fish/config.fish"),
    ];
    for rc in [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
    ] {
        targets.push(file(ShellRc, rc));
    }
    if crontab {
        targets.push(Target {
            kind: Crontab,
            path: TargetPath::Crontab,
        });
    }
    targets
}

/// System-wide persistence locations, watched by the root daemon.
pub fn system_targets() -> Vec<Target> {
    use Kind::*;
    let file = |kind, path: &str| Target {
        kind,
        path: TargetPath::File(PathBuf::from(path)),
    };
    let dir = |kind, path: &str, recursive, filter| Target {
        kind,
        path: TargetPath::Dir {
            path: PathBuf::from(path),
            recursive,
            filter,
        },
    };
    let mut t = vec![
        dir(
            SystemdSystem,
            "/etc/systemd/system",
            true,
            Filter::SystemdUnits,
        ),
        dir(
            SystemdSystem,
            "/etc/systemd/user",
            true,
            Filter::SystemdUnits,
        ),
        dir(SystemdSystem, "/etc/udev/rules.d", false, Filter::Any),
        file(SystemdSystem, "/etc/rc.local"),
        file(SystemdSystem, "/etc/rc.d/rc.local"),
        file(Preload, "/etc/ld.so.preload"),
        file(Preload, "/etc/ld.so.conf"),
        dir(Preload, "/etc/ld.so.conf.d", false, Filter::Conf),
        file(Crontab, "/etc/crontab"),
        file(Crontab, "/etc/anacrontab"),
        dir(Crontab, "/etc/cron.d", false, Filter::Any),
        dir(Crontab, "/etc/cron.hourly", false, Filter::Any),
        dir(Crontab, "/etc/cron.daily", false, Filter::Any),
        dir(Crontab, "/etc/cron.weekly", false, Filter::Any),
        dir(Crontab, "/etc/cron.monthly", false, Filter::Any),
        dir(Crontab, "/var/spool/cron", true, Filter::Any),
        dir(ShellRc, "/etc/profile.d", false, Filter::Any),
        dir(Environment, "/etc/environment.d", false, Filter::Conf),
        file(Environment, "/etc/environment"),
        file(Environment, "/etc/security/pam_env.conf"),
        dir(Autostart, "/etc/xdg/autostart", false, Filter::Desktop),
        dir(Session, "/etc/X11/xinit/xinitrc.d", false, Filter::Any),
        file(Ssh, "/root/.ssh/authorized_keys"),
        file(Ssh, "/root/.ssh/authorized_keys2"),
        file(Ssh, "/etc/ssh/sshd_config"),
        dir(Ssh, "/etc/ssh/sshd_config.d", false, Filter::Conf),
        file(Privileges, "/etc/sudoers"),
        dir(Privileges, "/etc/sudoers.d", false, Filter::Any),
        dir(Privileges, "/etc/polkit-1/rules.d", false, Filter::Any),
        dir(Privileges, "/etc/pam.d", false, Filter::Any),
    ];
    for rc in [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/zshrc",
        "/etc/zprofile",
        "/etc/zshenv",
        "/etc/zlogin",
        "/root/.bashrc",
        "/root/.bash_profile",
        "/root/.profile",
        "/root/.zshrc",
    ] {
        t.push(file(ShellRc, rc));
    }
    t
}

fn is_editor_temp(name: &str) -> bool {
    name.ends_with('~')
        || name.ends_with(".swp")
        || name.ends_with(".swx")
        || name.starts_with(".#")
        || (name.starts_with('#') && name.ends_with('#'))
}

fn matches(filter: Filter, name: &str) -> bool {
    if is_editor_temp(name) {
        return false;
    }
    let ext = Path::new(name).extension().and_then(OsStr::to_str);
    match filter {
        Filter::Any => true,
        Filter::Desktop => ext == Some("desktop"),
        Filter::Shell => ext == Some("sh"),
        Filter::Conf => ext == Some("conf"),
        Filter::Fish => ext == Some("fish"),
        Filter::SystemdUnits => ext.is_some_and(|e| SYSTEMD_SUFFIXES.contains(&e)),
    }
}

/// Read one path. `Ok(None)` means it does not exist.
pub fn read_entry(path: &Path) -> io::Result<Option<Entry>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        // A link that vanished in between counts as missing (also /proc/<pid>/exe of a
        // process that just ended).
        let target = match fs::read_link(path) {
            Ok(t) => t.to_string_lossy().into_owned(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let hash = format!("link:{}", hex::encode(Sha256::digest(target.as_bytes())));
        return Ok(Some(Entry::Symlink { hash, target }));
    }
    if !meta.is_file() {
        return Ok(None);
    }
    let mode = meta.permissions().mode() & 0o7777;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut content = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
        if size <= MAX_CONTENT {
            content.extend_from_slice(&buf[..n]);
        }
    }
    let content = (size <= MAX_CONTENT).then_some(content);
    Ok(Some(Entry::File {
        hash: hex::encode(hasher.finalize()),
        mode,
        size,
        content,
    }))
}

/// Build an entry from in-memory content (used for the crontab).
pub fn entry_from_bytes(content: Vec<u8>, mode: u32) -> Entry {
    Entry::File {
        hash: hex::encode(Sha256::digest(&content)),
        mode,
        size: content.len() as u64,
        content: Some(content),
    }
}

fn collect_dir(
    dir: &Path,
    recursive: bool,
    filter: Filter,
    kind: Kind,
    out: &mut BTreeMap<String, (Kind, Entry)>,
) {
    let Ok(read) = fs::read_dir(dir) else { return };
    for item in read.flatten() {
        let path = item.path();
        let name = item.file_name().to_string_lossy().into_owned();
        let Ok(ft) = item.file_type() else { continue };
        if ft.is_dir() {
            if recursive {
                collect_dir(&path, recursive, filter, kind, out);
            }
            continue;
        }
        // Enablement symlinks in *.wants and *.requires carry unit names, so the filter applies too.
        if !matches(filter, &name) {
            continue;
        }
        match read_entry(&path) {
            Ok(Some(entry)) => {
                out.insert(path.to_string_lossy().into_owned(), (kind, entry));
            }
            Ok(None) => {}
            Err(e) => log::warn!("cannot read {}: {e}", path.display()),
        }
    }
}

/// Directories a watcher has to observe for the given targets, each with an optional list of
/// names that matter. `None` means every name in that directory matters. Missing directories
/// are covered by watching their nearest existing ancestor below `home` (or `/`).
pub fn watch_specs(home: &Path, targets: &[Target]) -> Vec<(PathBuf, Option<Vec<String>>)> {
    let mut specs: BTreeMap<PathBuf, Option<Vec<String>>> = BTreeMap::new();
    let mut add_name = |dir: PathBuf, name: Option<String>| {
        let slot = specs.entry(dir).or_insert_with(|| Some(Vec::new()));
        match (slot.as_mut(), name) {
            (Some(names), Some(n)) => {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
            (Some(_), None) => *slot = None,
            (None, _) => {}
        }
    };

    for target in targets {
        let (want, is_dir, recursive) = match &target.path {
            TargetPath::File(p) => (p.clone(), false, false),
            TargetPath::Dir {
                path, recursive, ..
            } => (path.clone(), true, *recursive),
            TargetPath::Crontab => continue,
        };
        if is_dir && want.is_dir() {
            add_name(want.clone(), None);
            if recursive {
                for sub in subdirs(&want) {
                    add_name(sub, None);
                }
            }
        }
        // Watch the nearest existing ancestor for the next missing path component, so that
        // creating `.ssh` or `.config/autostart` is noticed.
        let mut child = want;
        while let Some(parent) = child.parent() {
            if !parent.starts_with(home) {
                break;
            }
            if parent.is_dir() {
                let name = child.file_name().map(|n| n.to_string_lossy().into_owned());
                add_name(parent.to_path_buf(), name);
                break;
            }
            child = parent.to_path_buf();
        }
    }
    specs.into_iter().collect()
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(read) = fs::read_dir(dir) else {
        return out;
    };
    for item in read.flatten() {
        if item.file_type().is_ok_and(|t| t.is_dir()) {
            let p = item.path();
            out.extend(subdirs(&p));
            out.push(p);
        }
    }
    out
}

/// Read the current state of every target. Paths that do not exist are left out.
pub fn snapshot(
    targets: &[Target],
    crontab: &dyn crate::crontab::CrontabBackend,
) -> BTreeMap<String, (Kind, Entry)> {
    let mut out = BTreeMap::new();
    for target in targets {
        match &target.path {
            TargetPath::File(p) => match read_entry(p) {
                Ok(Some(entry)) => {
                    out.insert(p.to_string_lossy().into_owned(), (target.kind, entry));
                }
                Ok(None) => {}
                Err(e) => log::warn!("cannot read {}: {e}", p.display()),
            },
            TargetPath::Dir {
                path,
                recursive,
                filter,
            } => collect_dir(path, *recursive, *filter, target.kind, &mut out),
            TargetPath::Crontab => match crontab.read() {
                Ok(Some(content)) => {
                    out.insert(
                        CRONTAB_PATH.to_string(),
                        (target.kind, entry_from_bytes(content, 0o600)),
                    );
                }
                Ok(None) => {}
                Err(e) => log::warn!("cannot read crontab: {e}"),
            },
        }
    }
    out
}

/// Find which target kind a path belongs to, for paths outside the snapshot.
pub fn kind_for(targets: &[Target], path: &str) -> Option<Kind> {
    if path == CRONTAB_PATH {
        return Some(Kind::Crontab);
    }
    let p = Path::new(path);
    targets.iter().find_map(|t| match &t.path {
        TargetPath::File(f) if f == p => Some(t.kind),
        TargetPath::Dir { path, .. } if p.starts_with(path) => Some(t.kind),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert!(matches(Filter::Desktop, "x.desktop"));
        assert!(!matches(Filter::Desktop, "x.desktop~"));
        assert!(!matches(Filter::Desktop, "x.txt"));
        assert!(matches(Filter::SystemdUnits, "evil.service"));
        assert!(matches(Filter::SystemdUnits, "override.conf"));
        assert!(!matches(Filter::SystemdUnits, ".evil.service.swp"));
        assert!(matches(Filter::Any, "script"));
        assert!(!matches(Filter::Any, ".#script"));
    }

    #[test]
    fn watch_specs_cover_missing_dirs() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        fs::create_dir_all(h.join(".config/systemd/user/default.target.wants")).unwrap();
        let targets = home_targets(h, false);
        let specs = watch_specs(h, &targets);
        let get = |p: PathBuf| specs.iter().find(|(d, _)| *d == p).map(|(_, n)| n.clone());

        // Existing recursive dir and its subdirs are watched fully.
        assert_eq!(get(h.join(".config/systemd/user")), Some(None));
        assert_eq!(
            get(h.join(".config/systemd/user/default.target.wants")),
            Some(None)
        );
        // Home is watched for rc files and the missing `.ssh` directory only.
        let home_names = get(h.to_path_buf()).unwrap().unwrap();
        assert!(home_names.contains(&".bashrc".to_string()));
        assert!(home_names.contains(&".ssh".to_string()));
        assert!(!home_names.contains(&".zsh_history".to_string()));
        // `.config` is watched for the missing `autostart` directory.
        let config_names = get(h.join(".config")).unwrap().unwrap();
        assert!(config_names.contains(&"autostart".to_string()));
    }
}
