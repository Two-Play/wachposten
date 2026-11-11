//! Core of Wachposten: watched persistence locations, baseline, analysis, decisions and storage.

pub mod analyze;
pub mod crontab;
pub mod guard;
pub mod i18n;
pub mod ipc;
pub mod model;
pub mod pkg;
pub mod report;
pub mod scanner;
pub mod settings;
pub mod store;
pub mod targets;

pub use guard::{Config, DecisionError, FileReport, Guard, Outcome, severity_for};
pub use model::{Change, Entry, Event, Finding, Kind, QuarantineItem, Severity, Status};
pub use scanner::FileScanner;
pub use settings::Settings;
pub use targets::{CRONTAB_PATH, MAX_CONTENT};
