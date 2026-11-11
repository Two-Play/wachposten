//! ClamAV through a running `clamd`, for the file types it is good at: Windows programs, Office
//! documents, PDFs, archives and scripts for Windows. Linux programs are left to YARA-X.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Sockets of the clamd packages of Fedora, Debian/Ubuntu and Arch.
pub const DEFAULT_SOCKETS: [&str; 4] = [
    "/run/clamd.scan/clamd.sock",
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
];

const CHUNK: usize = 64 * 1024;

/// Where the clamd program lies in the packages of Fedora, Debian/Ubuntu and Arch.
const PROGRAMS: [&str; 3] = ["/usr/sbin/clamd", "/usr/bin/clamd", "/usr/local/sbin/clamd"];

/// Whether clamd is installed, running or not.
pub fn installed() -> bool {
    PROGRAMS.iter().any(|p| Path::new(p).exists())
}

/// Shell commands that set up and start clamd on this distribution, for the person to run.
pub fn setup_commands() -> &'static str {
    setup_commands_for(
        Path::new("/etc/clamd.d/scan.conf").exists() || Path::new("/etc/fedora-release").exists(),
    )
}

fn setup_commands_for(fedora: bool) -> &'static str {
    if fedora {
        // Fedora ships the socket line commented out and no signatures.
        "sudo sed -i '0,/^#LocalSocket /s//LocalSocket /' /etc/clamd.d/scan.conf\n\
         sudo freshclam\n\
         sudo systemctl enable --now clamav-freshclam clamd@scan"
    } else {
        "sudo freshclam\nsudo systemctl enable --now clamav-freshclam clamav-daemon"
    }
}

pub struct ClamAv {
    socket: PathBuf,
    max_bytes: u64,
}

/// Whether ClamAV should look at this file, by its first bytes or its name.
pub fn worth_scanning(path: &Path, head: &[u8]) -> bool {
    const MAGIC: [&[u8]; 9] = [
        b"MZ",                           // Windows programs and libraries
        b"%PDF",                         // PDF
        b"PK\x03\x04",                   // ZIP, Office (docx, xlsx), JAR, APK
        b"\xD0\xCF\x11\xE0",             // old Office, MSI
        b"Rar!",                         // RAR
        b"7z\xBC\xAF",                   // 7-Zip
        b"\x1F\x8B",                     // gzip
        b"{\\rtf",                       // RTF
        b"\x4C\x00\x00\x00\x01\x14\x02", // Windows shortcut (.lnk)
    ];
    const EXT: [&str; 12] = [
        "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "bat", "cmd", "html", "htm", "eml",
    ];
    MAGIC.iter().any(|m| head.starts_with(m))
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXT.contains(&e.to_ascii_lowercase().as_str()))
}

impl ClamAv {
    /// Use `socket`, or the first default socket that exists. `None` if there is no clamd.
    pub fn find(socket: Option<&Path>, max_mb: u64) -> Option<ClamAv> {
        let socket = match socket {
            Some(s) => s.to_path_buf(),
            None => DEFAULT_SOCKETS
                .iter()
                .map(PathBuf::from)
                .find(|p| p.exists())?,
        };
        Some(ClamAv {
            socket,
            max_bytes: max_mb.saturating_mul(1024 * 1024),
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Ask clamd whether it answers.
    pub fn ping(&self) -> Result<()> {
        let mut s = self.connect()?;
        s.write_all(b"zPING\0")?;
        let reply = read_reply(&mut s)?;
        if reply != "PONG" {
            bail!("clamd answered {reply:?}");
        }
        Ok(())
    }

    fn connect(&self) -> Result<UnixStream> {
        let s = UnixStream::connect(&self.socket)
            .with_context(|| format!("cannot reach clamd at {}", self.socket.display()))?;
        s.set_read_timeout(Some(Duration::from_secs(120)))?;
        s.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(s)
    }

    /// Scan a file by streaming it to clamd, so clamd needs no access to it. Returns the
    /// signature name on a hit. Files of other types are skipped.
    pub fn scan(&self, path: &Path) -> Result<Option<String>> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let mut head = [0u8; 8];
        let n = file.read(&mut head)?;
        if !worth_scanning(path, &head[..n]) || size > self.max_bytes {
            return Ok(None);
        }
        let mut s = self.connect()?;
        s.write_all(b"zINSTREAM\0")?;
        let mut send = |data: &[u8]| -> std::io::Result<()> {
            s.write_all(&(data.len() as u32).to_be_bytes())?;
            s.write_all(data)
        };
        send(&head[..n])?;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            send(&buf[..n])?;
        }
        s.write_all(&0u32.to_be_bytes())?;
        parse_reply(&read_reply(&mut s)?)
    }
}

fn read_reply(s: &mut UnixStream) -> Result<String> {
    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte)? == 1 && byte[0] != 0 && reply.len() < 4096 {
        reply.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&reply).trim().to_string())
}

/// `stream: OK`, `stream: Eicar-Test-Signature FOUND` or an error.
fn parse_reply(reply: &str) -> Result<Option<String>> {
    let body = reply.strip_prefix("stream:").unwrap_or(reply).trim();
    if body == "OK" {
        return Ok(None);
    }
    if let Some(name) = body.strip_suffix("FOUND") {
        return Ok(Some(name.trim().to_string()));
    }
    bail!("clamd: {body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn replies() {
        assert_eq!(parse_reply("stream: OK").unwrap(), None);
        assert_eq!(
            parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND")
                .unwrap()
                .as_deref(),
            Some("Win.Test.EICAR_HDB-1")
        );
        assert!(parse_reply("INSTREAM size limit exceeded. ERROR").is_err());
    }

    #[test]
    fn setup_commands_fit_the_distribution() {
        let fedora = setup_commands_for(true);
        assert!(fedora.contains("/etc/clamd.d/scan.conf") && fedora.contains("clamd@scan"));
        assert_eq!(fedora.lines().count(), 3);
        assert!(setup_commands_for(false).contains("clamav-daemon"));
    }

    #[test]
    fn file_types() {
        assert!(worth_scanning(Path::new("a.exe"), b"MZ\x90\x00"));
        assert!(worth_scanning(Path::new("x"), b"%PDF-1.7"));
        assert!(worth_scanning(Path::new("invoice.js"), b"var a"));
        assert!(!worth_scanning(Path::new("tool"), b"\x7fELF"));
        assert!(!worth_scanning(Path::new("notes.txt"), b"hello"));
    }

    /// A tiny clamd that flags streams containing "EVIL".
    fn fake_clamd(socket: PathBuf) {
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut cmd = Vec::new();
                let mut b = [0u8; 1];
                while s.read(&mut b).unwrap() == 1 && b[0] != 0 {
                    cmd.push(b[0]);
                }
                if cmd == b"zPING" {
                    s.write_all(b"PONG\0").unwrap();
                    continue;
                }
                let mut data = Vec::new();
                loop {
                    let mut len = [0u8; 4];
                    s.read_exact(&mut len).unwrap();
                    let len = u32::from_be_bytes(len) as usize;
                    if len == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; len];
                    s.read_exact(&mut chunk).unwrap();
                    data.extend(chunk);
                }
                let found = data.windows(4).any(|w| w == b"EVIL");
                let reply: &[u8] = if found {
                    b"stream: Win.Test.Fake FOUND\0"
                } else {
                    b"stream: OK\0"
                };
                s.write_all(reply).unwrap();
            }
        });
    }

    #[test]
    fn streams_files_to_clamd() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        fake_clamd(socket.clone());
        let clam = ClamAv::find(Some(&socket), 10).unwrap();
        clam.ping().unwrap();

        let evil = dir.path().join("setup.exe");
        let mut content = b"MZ".to_vec();
        content.extend(vec![0u8; 200_000]);
        content.extend(b"EVIL");
        std::fs::write(&evil, &content).unwrap();
        assert_eq!(clam.scan(&evil).unwrap().as_deref(), Some("Win.Test.Fake"));

        let clean = dir.path().join("doc.pdf");
        std::fs::write(&clean, b"%PDF-1.7 fine").unwrap();
        assert_eq!(clam.scan(&clean).unwrap(), None);

        // Linux programs are not sent at all.
        let elf = dir.path().join("tool");
        std::fs::write(&elf, b"\x7fELF EVIL").unwrap();
        assert_eq!(clam.scan(&elf).unwrap(), None);
    }
}
