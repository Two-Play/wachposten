//! Checking files and folders on request (`wachposten scan-file`), also from the context menu
//! of the file manager, and adding that menu entry for one user.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use notify_rust::{Notification, Timeout, Urgency};
use wachposten_core::i18n::tr;
use wachposten_core::{Event, Guard};
use wachposten_scan::{Detection, MalwareScanner};

/// Folders are walked to this depth; deeper levels are left out.
const MAX_DEPTH: usize = 32;

#[derive(Default)]
pub struct Report {
    pub files: usize,
    pub skipped: usize,
    /// File and what was found.
    pub hits: Vec<(PathBuf, String)>,
}

/// Check every file in `paths`, folders with all files in them (symbolic links are not
/// followed). `each` sees every checked file with its detections.
#[cfg_attr(not(test), allow(dead_code))]
pub fn scan_paths(
    scanner: &MalwareScanner,
    paths: &[PathBuf],
    each: impl FnMut(&Path, &[Detection]),
) -> Report {
    scan_paths_skipping(scanner, paths, &[], each)
}

/// Large caches of tools in a home folder, left out of a check of the whole home folder.
pub fn home_skips(home: &Path) -> Vec<PathBuf> {
    [
        ".cache",
        ".local/share/flatpak",
        ".local/share/containers",
        ".local/share/Steam",
        ".local/share/Trash",
        ".var/app",
        ".cargo/registry",
        ".cargo/git",
        ".rustup",
        ".npm",
        ".m2",
        ".gradle",
        ".local/share/wachposten",
    ]
    .iter()
    .map(|p| home.join(p))
    .collect()
}

/// Like [`scan_paths`], leaving out the folders in `skip`.
pub fn scan_paths_skipping(
    scanner: &MalwareScanner,
    paths: &[PathBuf],
    skip: &[PathBuf],
    mut each: impl FnMut(&Path, &[Detection]),
) -> Report {
    let mut report = Report::default();
    let mut stack: Vec<(PathBuf, usize)> = paths.iter().map(|p| (p.clone(), 0)).collect();
    while let Some((path, depth)) = stack.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            report.skipped += 1;
            continue;
        };
        if meta.is_dir() {
            if depth >= MAX_DEPTH || skip.iter().any(|s| s == &path) {
                continue;
            }
            match fs::read_dir(&path) {
                Ok(entries) => {
                    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                    children.sort();
                    stack.extend(children.into_iter().rev().map(|c| (c, depth + 1)));
                }
                Err(_) => report.skipped += 1,
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        if fs::File::open(&path).is_err() {
            report.skipped += 1;
            continue;
        }
        report.files += 1;
        let detections = scanner.scan_path(&path);
        each(&path, &detections);
        for d in detections {
            report.hits.push((path.clone(), d.label()));
        }
    }
    report
}

/// Show the result as a desktop notification. With hits it offers to move the recorded
/// `events` to quarantine or to show them in the window, and waits for the answer.
pub fn notify(report: &Report, guard: &mut Guard, events: &[Event]) {
    let mut n = Notification::new();
    n.appname("Wachposten");
    if report.hits.is_empty() {
        n.summary(tr("Nichts gefunden", "Nothing found"))
            .body(&format!(
                "{} {}{}",
                report.files,
                tr("Dateien geprüft.", "files checked."),
                if report.skipped > 0 {
                    format!(
                        " {} {}",
                        report.skipped,
                        tr("konnten nicht gelesen werden.", "could not be read.")
                    )
                } else {
                    String::new()
                }
            ))
            .icon("security-high")
            .timeout(Timeout::Milliseconds(6000));
        if let Err(e) = n.show() {
            eprintln!("wachposten: cannot show the notification: {e}");
        }
        return;
    }

    n.summary(tr("Schadsoftware gefunden", "Malware found"))
        .body(&hits_body(report, !events.is_empty()))
        .icon("security-low")
        .urgency(Urgency::Critical)
        .timeout(Timeout::Never)
        .action("default", tr("Anzeigen", "Show"))
        .action("show", tr("Anzeigen", "Show"));
    if !events.is_empty() {
        n.action("quarantine", tr("In Quarantäne", "Quarantine"));
    }
    let handle = match n.show() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("wachposten: cannot show the notification: {e}");
            return;
        }
    };
    let mut chosen = String::new();
    handle.wait_for_action(|action| chosen = action.to_string());
    match chosen.as_str() {
        "quarantine" => quarantine(guard, events),
        "show" | "default" => open_alerts(),
        _ => {}
    }
}

fn hits_body(report: &Report, recorded: bool) -> String {
    let mut body: Vec<String> = report
        .hits
        .iter()
        .take(5)
        .map(|(p, what)| format!("{}\n   {}", escape(&p.display().to_string()), escape(what)))
        .collect();
    if report.hits.len() > 5 {
        body.push(format!(
            "{} {}",
            report.hits.len() - 5,
            tr("weitere", "more")
        ));
    }
    body.push(String::new());
    body.push(
        if recorded {
            tr(
                "Öffne die Dateien nicht. Sie stehen im Wachposten-Fenster unter Meldungen.",
                "Do not open them. They are listed in the Wachposten window under Alerts.",
            )
        } else {
            tr("Öffne die Dateien nicht.", "Do not open them.")
        }
        .into(),
    );
    body.join("\n")
}

/// Move the files to quarantine and say how it went.
fn quarantine(guard: &mut Guard, events: &[Event]) {
    let mut moved = 0;
    let mut failed = Vec::new();
    for ev in events {
        match guard.remove(ev.id, Some(ev.new_hash())) {
            Ok(_) => moved += 1,
            Err(e) => failed.push(format!("{}: {e:#}", ev.path)),
        }
    }
    let mut n = Notification::new();
    n.appname("Wachposten").timeout(Timeout::Milliseconds(8000));
    if failed.is_empty() {
        n.summary(tr("In Quarantäne verschoben", "Moved to quarantine"))
            .body(&format!(
                "{moved} {}",
                tr(
                    "Datei(en). Im Fenster unter Quarantäne kannst du sie wiederherstellen.",
                    "file(s). You can restore them in the window under Quarantine.",
                )
            ))
            .icon("security-high");
    } else {
        n.summary(tr("Nicht alles verschoben", "Not everything was moved"))
            .body(&escape(&failed.join("\n")))
            .icon("security-low");
    }
    let _ = n.show();
}

fn open_alerts() {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wachposten"));
    if let Err(e) = std::process::Command::new(exe)
        .args(["window", "--tab", "alerts"])
        .spawn()
    {
        eprintln!("wachposten: cannot open the window: {e}");
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

const SERVICE_MENU: &str = include_str!("../../../packaging/integration/wachposten-scan.desktop");

const NAUTILUS_SCRIPT: &str = "#!/bin/sh\n\
# Added by \"wachposten integrate\".\n\
printf '%s' \"$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\" | tr '\\n' '\\0' | xargs -0 -r wachposten scan-file --notify --\n";

fn data_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
}

fn write_executable(path: &Path, content: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, content).with_context(|| format!("cannot write {}", path.display()))?;
    // Plasma only runs service menus from the home folder when they are executable.
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Add or remove the context menu entries for this user.
pub fn integrate(home: &Path, remove: bool) -> Result<()> {
    integrate_in(&data_home(home), remove)
}

fn integrate_in(data: &Path, remove: bool) -> Result<()> {
    let dolphin = data.join("kio/servicemenus/wachposten-scan.desktop");
    let nautilus = data
        .join("nautilus/scripts")
        .join(tr("Mit Wachposten prüfen", "Check with Wachposten"));
    if remove {
        for p in [&dolphin, &nautilus] {
            match fs::remove_file(p) {
                Ok(()) => println!("removed {}", p.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("cannot remove {}", p.display())),
            }
        }
        return Ok(());
    }
    write_executable(&dolphin, SERVICE_MENU)?;
    println!("Dolphin:      {}", dolphin.display());
    write_executable(&nautilus, NAUTILUS_SCRIPT)?;
    println!("GNOME Files:  {} (menu Scripts)", nautilus.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_folders_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::create_dir_all(d.join("a/b")).unwrap();
        fs::write(d.join("a/one.txt"), "x").unwrap();
        fs::write(d.join("a/b/two.txt"), "y").unwrap();
        std::os::unix::fs::symlink(d, d.join("a/loop")).unwrap();
        let scanner = MalwareScanner::new(None, None, None, 10);
        let mut seen = Vec::new();
        let report = scan_paths(&scanner, &[d.join("a")], |p, _| seen.push(p.to_path_buf()));
        assert_eq!(report.files, 2);
        assert!(report.hits.is_empty());
        assert_eq!(seen, [d.join("a/b/two.txt"), d.join("a/one.txt")]);
    }

    #[test]
    fn integrate_writes_and_removes_entries() {
        let data = tempfile::tempdir().unwrap();
        integrate_in(data.path(), false).unwrap();
        let menu = data.path().join("kio/servicemenus/wachposten-scan.desktop");
        assert!(
            fs::read_to_string(&menu)
                .unwrap()
                .contains("scan-file --notify")
        );
        assert_eq!(
            fs::metadata(&menu).unwrap().permissions().mode() & 0o111,
            0o111
        );
        integrate_in(data.path(), true).unwrap();
        assert!(!menu.exists());
    }
}
