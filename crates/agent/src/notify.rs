//! Desktop notifications in three levels: a question with "Allow / Remove / Later" buttons
//! for dangerous changes, a warning for suspicious ones that wait in the tray, and a short
//! hint for harmless changes that were accepted right away.

use std::path::Path;
use std::sync::mpsc::Sender;
use std::thread;

use notify_rust::{Notification, Timeout, Urgency};
use wachposten_core::i18n::{self, tr};
use wachposten_core::scanner::MALWARE_RULE;
use wachposten_core::{Entry, Event, Severity};

use crate::{Decision, Msg};

const APP: &str = "Wachposten";
const MAX_LINES: usize = 3;
const MAX_LINE_LEN: usize = 110;

/// Notification servers may interpret a small HTML subset, so text is escaped.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn shorten(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() > MAX_LINE_LEN {
        let cut: String = s.chars().take(MAX_LINE_LEN).collect();
        format!("{cut}…")
    } else {
        s.to_string()
    }
}

pub fn pretty_path(home: &Path, path: &str) -> String {
    match Path::new(path).strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) if path == wachposten_core::CRONTAB_PATH => i18n::display_name(path),
        Err(_) => path.to_string(),
    }
}

pub fn body(home: &Path, ev: &Event) -> String {
    let mut out = vec![
        escape(i18n::event_sentence(ev)),
        escape(&pretty_path(home, &ev.path)),
    ];
    if let Some(actor) = &ev.actor {
        out.push(format!(
            "✎ {}: {}",
            tr("Geändert von", "Changed by"),
            escape(&shorten(actor))
        ));
    }
    if let Some(Entry::Symlink { target, .. }) = &ev.new_entry {
        out.push(format!("→ {}", escape(target)));
    }
    for finding in &ev.findings {
        if finding.rule == MALWARE_RULE {
            // The line names the signature; the path is already shown above.
            let name = finding.line.split(" – ").next().unwrap_or(&finding.line);
            out.push(format!("⛔ {}", escape(&shorten(name))));
        } else {
            out.push(format!("⚠ {}", escape(i18n::rule_label(&finding.rule))));
        }
    }
    if ev.kind.is_file_report() {
        // Details about the process, not file lines.
        let n = if ev.kind == wachposten_core::Kind::Ransomware {
            7
        } else {
            4
        };
        for line in ev.added_lines.iter().take(n) {
            out.push(escape(&shorten(line)));
        }
    } else if !ev.added_lines.is_empty() {
        out.push(String::new());
        // Lines with findings first, then command lines, then the rest in file order.
        let rank = |line: &String| {
            if ev.findings.iter().any(|f| f.line == line.trim()) {
                0
            } else if line.trim_start().starts_with("Exec") {
                1
            } else {
                2
            }
        };
        let mut lines: Vec<&String> = ev.added_lines.iter().collect();
        lines.sort_by_key(|l| rank(l));
        for line in lines.into_iter().take(MAX_LINES) {
            out.push(format!("+ {}", escape(&shorten(line))));
        }
        let rest = ev.added_lines.len().saturating_sub(MAX_LINES);
        if rest > 0 {
            out.push(format!(
                "{} {rest} {}",
                tr("… und", "… and"),
                tr("weitere Zeilen", "more lines")
            ));
        }
    }
    out.join("\n")
}

/// Show a question for an open event. The decision is sent back over `tx`, together with the
/// hash of the state the person saw. `system` marks events of the root daemon; without
/// `can_decide` the message only informs.
pub fn ask(home: &Path, ev: &Event, tx: Sender<Msg>, system: bool, can_decide: bool) {
    let mut n = Notification::new();
    let mut text = body(home, ev);
    if !can_decide {
        text.push_str(&format!(
            "\n\n{}",
            tr(
                "Darüber entscheidet ein Admin.",
                "An admin decides about this.",
            )
        ));
    }
    let summary = if system {
        format!("{}: {}", tr("System", "System"), i18n::event_title(ev))
    } else {
        i18n::event_title(ev)
    };
    n.appname(APP)
        .summary(&summary)
        .body(&text)
        .timeout(Timeout::Never);
    if can_decide && ev.kind == wachposten_core::Kind::Ransomware {
        n.action("remove", tr("Beenden", "End it"))
            .action("allow", tr("Weiterlaufen lassen", "Let it run"))
            .action("later", i18n::action_later());
    } else if can_decide {
        n.action("remove", i18n::action_remove())
            .action("allow", i18n::action_allow())
            .action("later", i18n::action_later());
    }
    if ev.severity >= Severity::Suspicious {
        n.icon("security-low").urgency(Urgency::Critical);
    } else {
        n.icon("security-medium").urgency(Urgency::Normal);
    }
    let handle = match n.show() {
        Ok(h) => h,
        Err(e) => {
            log::error!("cannot show notification: {e}");
            return;
        }
    };
    let id = ev.id;
    let hash = ev.new_hash().to_string();
    thread::spawn(move || {
        handle.wait_for_action(|action| {
            let decision = match action {
                "allow" => Decision::Allow,
                "remove" => Decision::Remove,
                _ => return,
            };
            let _ = tx.send(Msg::Decide {
                id,
                hash,
                decision,
                system,
            });
        });
    });
}

/// A short message about an event that needs no answer now: a warning for an open event, a
/// hint for a noted one. "Show" opens the window.
pub fn passive(home: &Path, ev: &Event, tx: Sender<Msg>, system: bool) {
    let noted = ev.status == wachposten_core::Status::Noted;
    let title = i18n::event_title(ev);
    let summary = if system {
        format!("{}: {title}", tr("System", "System"))
    } else {
        title
    };
    let footer = if noted {
        tr(
            "Sieht unbedenklich aus und wurde übernommen. Rückgängig machen geht im Verlauf.",
            "Looks harmless and was accepted. You can undo it in the history.",
        )
    } else {
        tr(
            "Etwas ungewöhnlich. Entscheide im Tray oder im Fenster, wenn du Zeit hast.",
            "A little unusual. Decide in the tray or the window when you have time.",
        )
    };
    let mut n = Notification::new();
    n.appname(APP)
        .summary(&summary)
        .body(&format!("{}\n\n{footer}", body(home, ev)))
        .icon(if noted {
            "security-high"
        } else {
            "security-medium"
        })
        .urgency(Urgency::Low)
        .timeout(Timeout::Milliseconds(if noted { 6000 } else { 12000 }))
        .action("default", tr("Ansehen", "Show"))
        .action("show", tr("Ansehen", "Show"));
    let handle = match n.show() {
        Ok(h) => h,
        Err(e) => {
            log::error!("cannot show notification: {e}");
            return;
        }
    };
    thread::spawn(move || {
        handle.wait_for_action(|action| {
            if action == "default" || action == "show" {
                let _ = tx.send(Msg::OpenWindow);
            }
        });
    });
}

/// A plain message without buttons.
pub fn info(summary: &str, body: &str, icon: &str) {
    if let Err(e) = Notification::new()
        .appname(APP)
        .summary(summary)
        .body(&escape(body))
        .icon(icon)
        .timeout(Timeout::Milliseconds(8000))
        .show()
    {
        log::error!("cannot show notification: {e}");
    }
}
