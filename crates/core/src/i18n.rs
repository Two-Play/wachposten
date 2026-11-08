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
        _ => tr("auffälliger Inhalt", "suspicious content"),
    }
}

/// Short title for a notification.
pub fn event_title(ev: &Event) -> String {
    let name = display_name(&ev.path);
    match (ev.kind, ev.change) {
        (Kind::Download, _) => format!(
            "{}: {name}",
            tr("Schadsoftware erkannt", "Malware detected")
        ),
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
