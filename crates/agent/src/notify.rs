//! Desktop notifications with "Allow / Remove / Later" buttons.

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
        Err(_) => i18n::display_name(path),
    }
}

pub fn body(home: &Path, ev: &Event) -> String {
    let mut out = vec![
        escape(i18n::event_sentence(ev)),
        escape(&pretty_path(home, &ev.path)),
    ];
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
    if !ev.added_lines.is_empty() {
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
/// hash of the state the person saw.
pub fn ask(home: &Path, ev: &Event, tx: Sender<Msg>) {
    let mut n = Notification::new();
    n.appname(APP)
        .summary(&i18n::event_title(ev))
        .body(&body(home, ev))
        .action("remove", i18n::action_remove())
        .action("allow", i18n::action_allow())
        .action("later", i18n::action_later())
        .timeout(Timeout::Never);
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
            let _ = tx.send(Msg::Decide { id, hash, decision });
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
