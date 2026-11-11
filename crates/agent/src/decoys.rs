//! Decoy files for the ransomware check of the system daemon: small documents nobody opens.
//! The daemon recognises them by name (`wachposten-koeder`) and stops any program that changes,
//! renames or deletes one.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use wachposten_core::settings::{Decoys, xdg_download_dir, xdg_user_dir};

const VISIBLE: &str = "!wachposten-koeder.docx";
const HIDDEN: &str = ".wachposten-koeder.docx";

const TEXT: &str = "Diese Datei schützt vor Erpressungs-Software. Bitte nicht ändern, umbenennen \
oder löschen; Wachposten entfernt sie selbst, wenn du die Köderdateien ausschaltest. \
This file protects against ransomware. Please do not change, rename or delete it.";

/// Folders that get a decoy: documents, pictures, desktop and downloads, if they exist.
pub fn folders(home: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = ["DOCUMENTS", "PICTURES", "DESKTOP"]
        .iter()
        .filter_map(|k| xdg_user_dir(home, k))
        .collect();
    dirs.push(xdg_download_dir(home));
    dirs.sort();
    dirs.dedup();
    dirs.retain(|d| d.is_dir() && d != home);
    dirs
}

/// A minimal valid DOCX document with the explanation.
fn document() -> Result<Vec<u8>> {
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut buf);
    let opts = zip::write::SimpleFileOptions::default();
    let parts = [
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#
                .to_string(),
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#
                .to_string(),
        ),
        (
            "word/document.xml",
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{TEXT}</w:t></w:r></w:p></w:body></w:document>"#
            ),
        ),
    ];
    for (name, content) in parts {
        zip.start_file(name, opts)?;
        zip.write_all(content.as_bytes())?;
    }
    zip.finish()?;
    Ok(buf.into_inner())
}

/// Create, rename or remove the decoys to match `mode`. Returns how many exist afterwards.
pub fn apply(home: &Path, mode: Decoys) -> Result<usize> {
    let want = match mode {
        Decoys::Off => None,
        Decoys::Visible => Some(VISIBLE),
        Decoys::Hidden => Some(HIDDEN),
    };
    let mut doc = None;
    let mut n = 0;
    for dir in folders(home) {
        for name in [VISIBLE, HIDDEN] {
            let path = dir.join(name);
            if Some(name) != want && path.is_file() {
                fs::remove_file(&path)?;
            }
        }
        let Some(name) = want else { continue };
        let path = dir.join(name);
        if !path.is_file() {
            if doc.is_none() {
                doc = Some(document()?);
            }
            fs::write(&path, doc.as_ref().unwrap())?;
        }
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_follow_the_setting() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        fs::create_dir_all(h.join(".config")).unwrap();
        fs::create_dir_all(h.join("Dokumente")).unwrap();
        fs::create_dir_all(h.join("Downloads")).unwrap();
        fs::write(
            h.join(".config/user-dirs.dirs"),
            "XDG_DOCUMENTS_DIR=\"$HOME/Dokumente\"\nXDG_DESKTOP_DIR=\"$HOME/\"\n",
        )
        .unwrap();
        // Assumes XDG_CONFIG_HOME is not set, as in CI.
        assert_eq!(apply(h, Decoys::Visible).unwrap(), 2);
        let doc = fs::read(h.join("Dokumente").join(VISIBLE)).unwrap();
        assert_eq!(&doc[..4], b"PK\x03\x04");
        assert_eq!(apply(h, Decoys::Hidden).unwrap(), 2);
        assert!(!h.join("Dokumente").join(VISIBLE).exists());
        assert!(h.join("Downloads").join(HIDDEN).exists());
        assert_eq!(apply(h, Decoys::Off).unwrap(), 0);
        assert!(!h.join("Downloads").join(HIDDEN).exists());
    }
}
