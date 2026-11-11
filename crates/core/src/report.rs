//! Summaries and exports of the history: the weekly report and `wachposten export`.

use serde::Serialize;

use crate::i18n::{self, tr};
use crate::model::{Event, Status};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Changes and program starts noticed.
    pub total: usize,
    /// Of them: removed by the person.
    pub removed: usize,
    /// Allowed by the person.
    pub allowed: usize,
    /// Looked harmless and were accepted with a hint.
    pub noted: usize,
    /// Still waiting for a decision.
    pub open: usize,
    /// Found to be dangerous (known malware, strong rules).
    pub dangerous: usize,
}

impl Summary {
    pub fn of(events: &[Event]) -> Summary {
        let mut s = Summary::default();
        for ev in events {
            // Deletions and package files are recorded without being noticed as such.
            if ev.status == Status::Accepted && ev.findings.is_empty() {
                continue;
            }
            s.total += 1;
            match ev.status {
                Status::Removed => s.removed += 1,
                Status::Allowed => s.allowed += 1,
                Status::Noted => s.noted += 1,
                Status::Open => s.open += 1,
                _ => {}
            }
            if ev.severity == crate::model::Severity::Malicious
                || crate::analyze::alarming(ev.kind, &ev.findings)
            {
                s.dangerous += 1;
            }
        }
        s
    }

    /// Title and text of the weekly notification.
    pub fn weekly_text(&self) -> (String, String) {
        if self.total == 0 {
            return (
                tr("Eine ruhige Woche", "A quiet week").into(),
                tr(
                    "Wachposten hat in den letzten sieben Tagen nichts bemerkt, das deine Aufmerksamkeit braucht.",
                    "Wachposten noticed nothing in the last seven days that needs your attention.",
                )
                .into(),
            );
        }
        let mut parts = vec![format!(
            "{} {}",
            self.total,
            tr("Änderungen bemerkt", "changes noticed")
        )];
        if self.dangerous > 0 {
            parts.push(format!(
                "{} {}",
                self.dangerous,
                tr("gefährlich", "dangerous")
            ));
        }
        if self.removed > 0 {
            parts.push(format!("{} {}", self.removed, tr("entfernt", "removed")));
        }
        if self.allowed > 0 {
            parts.push(format!("{} {}", self.allowed, tr("erlaubt", "allowed")));
        }
        if self.noted > 0 {
            parts.push(format!(
                "{} {}",
                self.noted,
                tr("unbedenklich übernommen", "accepted as harmless")
            ));
        }
        let mut text = parts.join(" · ");
        if self.open > 0 {
            text.push_str(&format!(
                "\n{} {}",
                self.open,
                tr(
                    "warten noch auf deine Entscheidung.",
                    "still wait for your decision."
                )
            ));
        }
        (tr("Wochenbericht", "Weekly report").into(), text)
    }
}

/// One exported row.
#[derive(Debug, Serialize)]
pub struct Row<'a> {
    pub id: i64,
    /// `home` (the agent) or `system` (the daemon).
    pub source: &'a str,
    pub created: String,
    pub updated: String,
    pub kind: &'a str,
    pub change: &'a str,
    pub severity: &'a str,
    pub status: &'a str,
    pub path: &'a str,
    pub findings: String,
    pub actor: &'a str,
}

fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default()
}

pub fn row<'a>(ev: &'a Event, system: bool) -> Row<'a> {
    Row {
        id: ev.id,
        source: if system { "system" } else { "home" },
        created: rfc3339(ev.created_at),
        updated: rfc3339(ev.updated_at),
        kind: ev.kind.as_str(),
        change: ev.change.as_str(),
        severity: ev.severity.as_str(),
        status: ev.status.as_str(),
        path: &ev.path,
        findings: ev
            .findings
            .iter()
            .map(|f| i18n::rule_label(&f.rule))
            .collect::<Vec<_>>()
            .join("; "),
        actor: ev.actor.as_deref().unwrap_or(""),
    }
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) || s.starts_with(['=', '+', '-', '@']) {
        // Quote, and keep spreadsheets from reading a leading = as a formula.
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s.to_string()
        };
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// CSV with a header line.
pub fn to_csv(rows: &[Row<'_>]) -> String {
    let mut out =
        String::from("id,source,created,updated,kind,change,severity,status,path,findings,actor\n");
    for r in rows {
        let fields = [
            r.id.to_string(),
            r.source.to_string(),
            r.created.clone(),
            r.updated.clone(),
            r.kind.to_string(),
            r.change.to_string(),
            r.severity.to_string(),
            r.status.to_string(),
            r.path.to_string(),
            r.findings.clone(),
            r.actor.to_string(),
        ];
        out.push_str(
            &fields
                .iter()
                .map(|f| csv_field(f))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

pub fn to_json(rows: &[Row<'_>]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_defuses_formulas() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
    }
}
