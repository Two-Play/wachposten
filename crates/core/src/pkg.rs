//! Package manager checks, so files that rpm or dpkg installed unchanged are not questioned.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn has_dpkg() -> bool {
    Path::new("/var/lib/dpkg/status").exists()
}

fn output(cmd: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

/// Whether `path` belongs to an installed package and has the content the package shipped.
pub fn installed_unchanged(path: &Path) -> bool {
    let p = path.to_string_lossy();
    if has_dpkg() {
        let Some((true, owners)) = output("dpkg", &["-S", &p]) else {
            return false;
        };
        let pkgs: Vec<&str> = owners
            .lines()
            .filter_map(|l| l.split_once(": ").map(|(pkg, _)| pkg))
            .flat_map(|pkgs| pkgs.split(", "))
            .collect();
        return !pkgs.is_empty()
            && pkgs.iter().all(|pkg| {
                output("dpkg", &["--verify", pkg])
                    .is_some_and(|(_, out)| !out.lines().any(|l| l.ends_with(&format!(" {p}"))))
            });
    }
    let Some((true, owners)) = output("rpm", &["-qf", "--qf", "%{NAME}\n", "--", &p]) else {
        return false;
    };
    let pkgs: Vec<&str> = owners.lines().filter(|l| !l.is_empty()).collect();
    !pkgs.is_empty()
        && pkgs.iter().all(|pkg| {
            // `rpm -V` exits non-zero when anything in the package differs; only this file counts.
            output("rpm", &["-V", "--nomtime", "--", pkg])
                .is_some_and(|(_, out)| !out.lines().any(|l| l.ends_with(&format!(" {p}"))))
        })
}

const LOCK_FILES: [&str; 4] = [
    "/usr/lib/sysimage/rpm/.rpm.lock",
    "/var/lib/rpm/.rpm.lock",
    "/var/lib/dpkg/lock",
    "/var/lib/dpkg/lock-frontend",
];

const MANAGERS: [&str; 8] = [
    "rpm",
    "dnf",
    "dnf5",
    "yum",
    "rpm-ostree",
    "apt",
    "apt-get",
    "dpkg",
];

/// Whether a package transaction runs right now: one of the package database locks is held,
/// or a package manager process runs. Files change one by one during a transaction and the
/// database only knows them at the end, so checks wait until it is over.
pub fn manager_busy() -> bool {
    let locks = fs::read_to_string("/proc/locks").unwrap_or_default();
    for lock in LOCK_FILES {
        let Ok(meta) = fs::metadata(lock) else {
            continue;
        };
        let ino = format!(":{} ", meta.ino());
        if locks.lines().any(|l| l.contains(&ino)) {
            return true;
        }
    }
    let Ok(procs) = fs::read_dir("/proc") else {
        return false;
    };
    procs.flatten().any(|p| {
        p.file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
            && fs::read_to_string(p.path().join("comm")).is_ok_and(|c| MANAGERS.contains(&c.trim()))
    })
}
