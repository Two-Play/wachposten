//! German and English texts for notifications and the tray. The language follows
//! `LC_ALL`, `LC_MESSAGES` or `LANG`; anything starting with `de` gives German.

use std::sync::LazyLock;

use crate::model::{Change, Event, Kind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    De,
    En,
}

static LANG: LazyLock<Lang> = LazyLock::new(|| {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return if v.starts_with("de") {
                Lang::De
            } else {
                Lang::En
            };
        }
    }
    Lang::En
});

pub fn lang() -> Lang {
    *LANG
}

/// Pick the German or English text.
pub fn tr(de: &'static str, en: &'static str) -> &'static str {
    match lang() {
        Lang::De => de,
        Lang::En => en,
    }
}

pub fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Autostart => tr("Autostart", "autostart"),
        Kind::SystemdUser => tr("systemd-Benutzerdienst", "systemd user service"),
        Kind::ShellRc => tr("Shell-Startdatei", "shell startup file"),
        Kind::Session => tr("Sitzungsstart", "session startup"),
        Kind::Environment => tr("Umgebungsvariablen", "environment variables"),
        Kind::Ssh => tr("SSH-Zugang", "SSH access"),
        Kind::Crontab => tr("Zeitgesteuerte Aufgabe (cron)", "scheduled task (cron)"),
        Kind::Download => tr("Download", "download"),
        Kind::Checked => tr("Geprüfte Datei", "checked file"),
        Kind::SystemdSystem => tr("Systemdienst / Systemstart", "system service / boot"),
        Kind::Preload => tr("Bibliotheken laden", "library loading"),
        Kind::Privileges => tr(
            "Rechte (sudo, polkit, PAM)",
            "privileges (sudo, polkit, PAM)",
        ),
        Kind::TempExec => tr(
            "Programmstart aus temporärem Ordner",
            "program start from a temporary folder",
        ),
        Kind::Ransomware => tr("Erpressungs-Software", "ransomware"),
        Kind::Applications => tr(
            "Programmstarter und Dateizuordnungen",
            "launchers and file handlers",
        ),
        Kind::Browser => tr("Browser-Erweiterung", "browser extension"),
        Kind::DevTools => tr("Entwickler-Werkzeuge", "developer tools"),
        Kind::Hooks => tr("Paketmanager-Hook", "package manager hook"),
    }
}

pub fn rule_label(rule: &str) -> &'static str {
    match rule {
        "preload" => tr(
            "lädt eine Bibliothek in jedes Programm (LD_PRELOAD)",
            "loads a library into every program (LD_PRELOAD)",
        ),
        "pipe-to-shell" => tr(
            "lädt etwas aus dem Netz und führt es sofort aus",
            "downloads something and runs it right away",
        ),
        "inline-interpreter" => tr(
            "führt eingebetteten Programmcode aus",
            "runs embedded program code",
        ),
        "base64" => tr(
            "enthält verschleierten (Base64-)Inhalt",
            "contains obfuscated (base64) content",
        ),
        "temp-path" => tr(
            "startet etwas aus einem temporären Ordner",
            "starts something from a temporary folder",
        ),
        "reverse-shell" => tr(
            "öffnet eine Fernsteuerung über das Netz",
            "opens a remote shell over the network",
        ),
        "background" => tr(
            "startet unbemerkt einen Hintergrundprozess",
            "quietly starts a background process",
        ),
        "make-executable" => tr("macht eine Datei ausführbar", "makes a file executable"),
        "forced-command" => tr(
            "SSH-Schlüssel mit erzwungenem Befehl",
            "SSH key with a forced command",
        ),
        "hidden-dir" => tr(
            "startet ein Programm aus einem versteckten Ordner",
            "starts a program from a hidden folder",
        ),
        "binary" => tr("ist eine Programmdatei, kein Text", "is a binary, not text"),
        "malware" => tr("bekannte Schadsoftware", "known malware"),
        "shm" => tr(
            "läuft aus dem Arbeitsspeicher-Ordner /dev/shm",
            "runs from the memory folder /dev/shm",
        ),
        "memfd" => tr(
            "läuft direkt aus dem Arbeitsspeicher (memfd), ohne Datei",
            "runs straight from memory (memfd), without a file",
        ),
        "masquerade" => tr(
            "tarnt sich mit dem Namen eines Systemprozesses",
            "poses as a system process by name",
        ),
        "pth-code" => tr(
            "führt bei jedem Python-Start Code aus",
            "runs code at every Python start",
        ),
        "git-command" => tr(
            "lässt git einen Befehl oder Hook ausführen",
            "makes git run a command or hook",
        ),
        "ransomware" => tr(
            "verschlüsselt anscheinend deine Dateien",
            "seems to encrypt your files",
        ),
        "decoy" => tr("hat eine Köderdatei verändert", "changed a decoy file"),
        _ => tr("auffälliger Inhalt", "suspicious content"),
    }
}

/// Short title for a notification.
pub fn event_title(ev: &Event) -> String {
    let name = display_name(&ev.path);
    match (ev.kind, ev.change) {
        (Kind::Ransomware, _) => format!(
            "{}: {name}",
            tr("Verschlüsselt deine Dateien", "Encrypting your files")
        ),
        (Kind::TempExec, _) if ev.severity == crate::model::Severity::Malicious => {
            format!(
                "{}: {name}",
                tr("Schadsoftware gestartet", "Malware started")
            )
        }
        (Kind::TempExec, _) => format!(
            "{}: {name}",
            tr(
                "Programm aus temporärem Ordner",
                "Program from a temporary folder"
            )
        ),
        (Kind::SystemdSystem, Change::Created) => {
            format!("{}: {name}", tr("Neuer Systemdienst", "New system service"))
        }
        (Kind::Preload, _) => format!(
            "{}: {name}",
            tr("Bibliotheken-Laden geändert", "Library loading changed")
        ),
        (Kind::Privileges, _) => format!("{}: {name}", tr("Rechte geändert", "Privileges changed")),
        (Kind::Download, _) => format!(
            "{}: {name}",
            tr("Schadsoftware erkannt", "Malware detected")
        ),
        (Kind::Checked, _) => format!("{}: {name}", tr("Schadsoftware gefunden", "Malware found")),
        (Kind::Autostart, Change::Created) => {
            tr("Neuer Autostart-Eintrag", "New autostart entry").into()
        }
        (Kind::SystemdUser, Change::Created) => {
            format!("{}: {name}", tr("Neuer Benutzerdienst", "New user service"))
        }
        (Kind::Ssh, _) => format!(
            "{}: {name}",
            tr("SSH-Zugang geändert", "SSH access changed")
        ),
        (Kind::Browser, Change::Created) => format!(
            "{}: {name}",
            tr("Neue Browser-Erweiterung", "New browser extension")
        ),
        (Kind::Browser, _) => format!(
            "{}: {name}",
            tr("Browser-Einstellung geändert", "Browser setting changed")
        ),
        (Kind::Hooks, _) => format!(
            "{}: {name}",
            tr("Paketmanager-Hook", "Package manager hook")
        ),
        (Kind::Crontab, _) => {
            tr("Zeitgesteuerte Aufgabe geändert", "Scheduled task changed").into()
        }
        (_, Change::Created) => format!("{}: {name}", tr("Neu", "New")),
        _ => format!("{}: {name}", tr("Geändert", "Changed")),
    }
}

/// One-sentence explanation of what happened.
pub fn event_sentence(ev: &Event) -> &'static str {
    match (ev.kind, ev.change) {
        (Kind::Applications, _) => tr(
            "Ein Programmstarter, eine Dateizuordnung oder ein Rechtsklick-Eintrag wurde angelegt oder geändert. Er startet ein Programm, sobald du eine Datei öffnest oder den Eintrag wählst.",
            "A launcher, file handler or right-click action was added or changed. It starts a program when you open a file or pick the entry.",
        ),
        (Kind::Browser, _) => tr(
            "Eine Browser-Erweiterung oder eine Browser-Richtlinie wurde hinzugefügt oder geändert. Erweiterungen können alles mitlesen, was du im Browser tust.",
            "A browser extension or browser policy was added or changed. Extensions can read everything you do in the browser.",
        ),
        (Kind::DevTools, _) => tr(
            "Eine Einstellung von git oder Python wurde geändert, die Befehle ausführen kann (Hooks, Aliase, .pth-Dateien).",
            "A git or Python setting that can run commands was changed (hooks, aliases, .pth files).",
        ),
        (Kind::Hooks, _) => tr(
            "Ein Hook des Paketmanagers wurde angelegt oder geändert. Er läuft bei jeder Installation mit Root-Rechten.",
            "A package manager hook was added or changed. It runs with root rights on every install.",
        ),
        (Kind::Autostart, _) => tr(
            "Ein Programm hat sich in deinen Autostart eingetragen.",
            "A program added itself to your autostart.",
        ),
        (Kind::SystemdUser, _) => tr(
            "Ein Dienst soll mit deiner Anmeldung starten.",
            "A service is set to start when you log in.",
        ),
        (Kind::ShellRc, _) => tr(
            "Eine Datei, die jede neue Shell ausführt, wurde geändert.",
            "A file that every new shell runs was changed.",
        ),
        (Kind::Session, _) => tr(
            "Eine Datei, die beim Anmelden ausgeführt wird, wurde geändert.",
            "A file that runs when you log in was changed.",
        ),
        (Kind::Environment, _) => tr(
            "Umgebungsvariablen für deine Sitzung wurden geändert.",
            "Environment variables for your session were changed.",
        ),
        (Kind::Ssh, _) => tr(
            "Jemand kann sich damit eventuell per SSH anmelden.",
            "This may let someone log in over SSH.",
        ),
        (Kind::Crontab, _) => tr(
            "Eine Aufgabe soll regelmäßig automatisch laufen.",
            "A task is set to run automatically on a schedule.",
        ),
        (Kind::Download, _) => tr(
            "Eine heruntergeladene Datei ist als Schadsoftware bekannt. Öffne sie nicht.",
            "A downloaded file is known malware. Do not open it.",
        ),
        (Kind::Checked, _) => tr(
            "Beim Prüfen wurde diese Datei als Schadsoftware erkannt. Öffne sie nicht. Entfernen verschiebt sie in die Quarantäne.",
            "The check found this file to be malware. Do not open it. Remove moves it to quarantine.",
        ),
        (Kind::SystemdSystem, _) => tr(
            "Etwas soll beim Systemstart oder als Systemdienst mit Root-Rechten laufen.",
            "Something is set to run at boot or as a system service with root rights.",
        ),
        (Kind::Preload, _) => tr(
            "Das Laden von Bibliotheken wurde geändert. Das betrifft jedes Programm.",
            "How libraries are loaded was changed. This affects every program.",
        ),
        (Kind::Privileges, _) => tr(
            "Rechte für sudo, polkit oder die Anmeldung (PAM) wurden geändert.",
            "Rights for sudo, polkit or login (PAM) were changed.",
        ),
        (Kind::Ransomware, _) => tr(
            "Ein Programm verschlüsselt anscheinend deine Dateien. Es wurde angehalten und wartet auf deine Entscheidung. „Entfernen“ beendet es.",
            "A program seems to be encrypting your files. It was stopped and waits for your decision. \"Remove\" ends it.",
        ),
        (Kind::TempExec, _) => tr(
            "Ein Programm wurde aus einem temporären Ordner gestartet. Schadsoftware nutzt solche Orte gern.",
            "A program was started from a temporary folder. Malware likes to use such places.",
        ),
    }
}

/// File name, or a friendly name for the crontab.
pub fn display_name(path: &str) -> String {
    if path == crate::targets::CRONTAB_PATH {
        return "crontab".into();
    }
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

pub fn action_allow() -> &'static str {
    tr("Erlauben", "Allow")
}

pub fn action_remove() -> &'static str {
    tr("Entfernen", "Remove")
}

pub fn action_later() -> &'static str {
    tr("Später", "Later")
}
