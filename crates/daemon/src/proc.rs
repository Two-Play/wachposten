//! Process details from `/proc`.

use std::fs;
use std::path::Path;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: i32,
    pub uid: Option<u32>,
    pub comm: String,
    pub cmdline: String,
    pub ppid: Option<i32>,
    pub parent_comm: Option<String>,
}

fn status_field(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
}

fn comm(pid: i32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

/// Read what is known about a process; empty fields if it already ended.
pub fn info(pid: i32) -> ProcInfo {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let uid = status_field(&status, "Uid:")
        .and_then(|v| v.split_whitespace().next().and_then(|u| u.parse().ok()));
    let ppid: Option<i32> = status_field(&status, "PPid:").and_then(|v| v.parse().ok());
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    ProcInfo {
        pid,
        uid,
        comm: comm(pid).unwrap_or_default(),
        cmdline,
        ppid,
        parent_comm: ppid.and_then(comm),
    }
}

/// Processes whose program is `path` (also after the file was deleted).
pub fn running(path: &Path) -> Vec<i32> {
    let want = path.to_string_lossy().into_owned();
    let deleted = format!("{want} (deleted)");
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| {
                let exe = exe.to_string_lossy();
                exe == want || exe == deleted
            })
        })
        .collect()
}

/// End all processes of a program. Returns how many were signalled. `/proc/<pid>/exe` (a
/// program started from memory) ends that one process.
pub fn kill_program(path: &Path) -> usize {
    let s = path.to_string_lossy();
    if let Some(pid) = s
        .strip_prefix("/proc/")
        .and_then(|r| r.strip_suffix("/exe"))
        .and_then(|p| p.parse::<i32>().ok())
    {
        let ok = kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok();
        if ok {
            log::warn!("killed process {pid} (started from memory)");
        }
        return usize::from(ok);
    }
    running(path)
        .into_iter()
        .filter(|pid| {
            let ok = kill(Pid::from_raw(*pid), Signal::SIGKILL).is_ok();
            if ok {
                log::warn!("killed process {pid} ({})", path.display());
            }
            ok
        })
        .count()
}
