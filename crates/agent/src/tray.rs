//! Tray icon (StatusNotifierItem) with the open events and quick decisions.

use std::sync::mpsc::Sender;

use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, ToolTip};
use wachposten_core::i18n::{self, tr};
use wachposten_core::{Event, Severity};

use crate::{Decision, Msg};

pub struct OpenItem {
    pub id: i64,
    pub title: String,
    pub hash: String,
    pub suspicious: bool,
    /// An event of the root daemon.
    pub system: bool,
    pub can_decide: bool,
}

impl OpenItem {
    pub fn from_event(ev: &Event, system: bool, can_decide: bool) -> OpenItem {
        let title = i18n::event_title(ev);
        let title = if system {
            format!("{}: {title}", tr("System", "System"))
        } else {
            title
        };
        let name = i18n::display_name(&ev.path);
        OpenItem {
            id: ev.id,
            title: if title.contains(&name) {
                title
            } else {
                format!("{title} ({name})")
            },
            hash: ev.new_hash().to_string(),
            suspicious: ev.severity >= Severity::Suspicious,
            system,
            can_decide,
        }
    }
}

pub struct Tray {
    pub open: Vec<OpenItem>,
    pub tx: Sender<Msg>,
}

impl Tray {
    fn summary(&self) -> String {
        match self.open.len() {
            0 => tr("Keine offenen Meldungen", "No open alerts").to_string(),
            1 => tr("1 offene Meldung", "1 open alert").to_string(),
            n => format!("{n} {}", tr("offene Meldungen", "open alerts")),
        }
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "wachposten".into()
    }

    fn title(&self) -> String {
        "Wachposten".into()
    }

    fn icon_name(&self) -> String {
        if self.open.iter().any(|o| o.suspicious) {
            "security-low".into()
        } else if self.open.is_empty() {
            "security-high".into()
        } else {
            "security-medium".into()
        }
    }

    fn status(&self) -> ksni::Status {
        if self.open.is_empty() {
            ksni::Status::Active
        } else {
            ksni::Status::NeedsAttention
        }
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            title: "Wachposten".into(),
            description: self.summary(),
            icon_name: self.icon_name(),
            icon_pixmap: Vec::new(),
        }
    }

    /// A left click opens the window.
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(Msg::OpenWindow);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = vec![
            StandardItem {
                label: tr("Wachposten öffnen", "Open Wachposten").into(),
                icon_name: "security-high".into(),
                activate: Box::new(|t: &mut Tray| {
                    let _ = t.tx.send(Msg::OpenWindow);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: self.summary(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        ];
        for item in &self.open {
            if !item.can_decide {
                items.push(
                    StandardItem {
                        label: format!(
                            "{} ({})",
                            item.title,
                            tr("Admin entscheidet", "admin decides")
                        ),
                        enabled: false,
                        ..Default::default()
                    }
                    .into(),
                );
                continue;
            }
            let decide = |decision: Decision| {
                let (id, hash, system) = (item.id, item.hash.clone(), item.system);
                Box::new(move |t: &mut Tray| {
                    let _ = t.tx.send(Msg::Decide {
                        id,
                        hash: hash.clone(),
                        decision,
                        system,
                    });
                }) as Box<dyn Fn(&mut Tray) + Send>
            };
            items.push(
                SubMenu {
                    label: item.title.clone(),
                    icon_name: if item.suspicious {
                        "security-low".into()
                    } else {
                        "security-medium".into()
                    },
                    submenu: vec![
                        StandardItem {
                            label: i18n::action_allow().into(),
                            activate: decide(Decision::Allow),
                            ..Default::default()
                        }
                        .into(),
                        StandardItem {
                            label: i18n::action_remove().into(),
                            activate: decide(Decision::Remove),
                            ..Default::default()
                        }
                        .into(),
                    ],
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: tr("Jetzt prüfen", "Check now").into(),
                icon_name: "view-refresh".into(),
                activate: Box::new(|t: &mut Tray| {
                    let _ = t.tx.send(Msg::Rescan);
                }),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: tr("Beenden", "Quit").into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Tray| {
                    let _ = t.tx.send(Msg::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}
