//! YARA-X rules: the built-in set plus folders configured by the person.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

const BUILTIN: &str = include_str!("../rules/linux.yar");
const TIMEOUT: Duration = Duration::from_secs(20);

/// One rule file and how compiling it went.
#[derive(Debug, Clone)]
pub struct RuleSource {
    pub name: String,
    pub path: Option<PathBuf>,
    /// `Err` holds the first compile error; the file was skipped.
    pub result: Result<(), String>,
}

pub struct YaraEngine {
    rules: Rules,
    pub sources: Vec<RuleSource>,
}

/// A rule that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub description: Option<String>,
}

fn rule_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "yar" || e == "yara"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn namespace_for(path: &Path) -> String {
    path.file_stem()
        .map(|s| {
            s.to_string_lossy()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        })
        .unwrap_or_else(|| "extra".into())
}

impl YaraEngine {
    /// Compile the built-in rules and every rule file in `extra_dirs`. Files with errors are
    /// skipped and reported in [`YaraEngine::sources`].
    pub fn new(extra_dirs: &[PathBuf]) -> YaraEngine {
        let mut compiler = Compiler::new();
        let mut sources = Vec::new();

        compiler.new_namespace("wachposten");
        let builtin = compiler
            .add_source(BUILTIN)
            .map(|_| ())
            .map_err(|e| e.to_string());
        sources.push(RuleSource {
            name: "wachposten (built-in)".into(),
            path: None,
            result: builtin,
        });

        for dir in extra_dirs {
            for file in rule_files(dir) {
                let result = fs::read_to_string(&file)
                    .map_err(|e| e.to_string())
                    .and_then(|text| {
                        // Check in a separate compiler first so a broken file cannot leave
                        // half-added rules or clashing identifiers behind.
                        let mut probe = Compiler::new();
                        probe.add_source(text.as_str()).map_err(|e| e.to_string())?;
                        compiler.new_namespace(&namespace_for(&file));
                        compiler
                            .add_source(text.as_str())
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    });
                if let Err(e) = &result {
                    log::warn!("skipping YARA file {}: {e}", file.display());
                }
                sources.push(RuleSource {
                    name: namespace_for(&file),
                    path: Some(file),
                    result,
                });
            }
        }
        YaraEngine {
            rules: compiler.build(),
            sources,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().len()
    }

    pub fn scan_file(&self, path: &Path) -> anyhow::Result<Vec<YaraMatch>> {
        self.scan_file_within(path, TIMEOUT)
    }

    /// Scan with a time limit; a scan that runs out of time is an error.
    pub fn scan_file_within(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> anyhow::Result<Vec<YaraMatch>> {
        let mut scanner = Scanner::new(&self.rules);
        scanner.set_timeout(timeout);
        let results = scanner.scan_file(path)?;
        Ok(results
            .matching_rules()
            .map(|rule| YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                description: rule.metadata().find_map(|(k, v)| match (k, v) {
                    ("description", MetaValue::String(s)) => Some(s.to_string()),
                    _ => None,
                }),
            })
            .collect())
    }
}
