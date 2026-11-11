//! Ransomware detection: a process that overwrites, renames or deletes many of a person's
//! files in a short time, and whose files afterwards no longer look like what their names say.
//!
//! The rate alone says little (copying a folder, unpacking an archive, a photo export), so it
//! only triggers a look at the content of the files written last. A changed decoy file triggers
//! right away. Each write is counted for the process and for its parent, so a script that runs
//! one `gpg` or `openssl` per file is caught through the script.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// Part of the file name of decoy files, see the agent's `decoys` module.
pub const DECOY_MARK: &str = "wachposten-koeder";

/// Folders that hold program data, not documents, even when they are not hidden.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    "venv",
    "site-packages",
    "vendor",
];

/// Suffixes that tools append for harmless reasons (`x` → `x.bak`).
const HARMLESS_SUFFIXES: &[&str] = &[
    "bak",
    "backup",
    "orig",
    "old",
    "tmp",
    "temp",
    "part",
    "swp",
    "save",
    "new",
    "rej",
    "lock",
    "crdownload",
    "download",
    "partial",
    "kate-swp",
];

/// Extensions whose files are text by nature; random bytes in them mean encryption.
const TEXT_EXTS: &[&str] = &[
    "txt", "md", "csv", "tsv", "json", "xml", "html", "htm", "svg", "log", "ini", "conf", "cfg",
    "yaml", "yml", "toml", "rs", "py", "c", "h", "cpp", "hpp", "js", "ts", "java", "go", "sh",
    "tex", "rtf", "eml", "vcf", "ics", "sql", "css", "php", "rb", "pl", "lua", "kt", "swift",
];

/// Typical names of ransom notes.
const NOTE_PATTERNS: &[&str] = &[
    "decrypt",
    "how_to_recover",
    "how-to-recover",
    "restore_files",
    "restore-files",
    "recover_files",
    "your_files",
    "ransom",
];

/// The file header an extension promises: (offset, bytes), any of them.
fn magic(ext: &str) -> Option<&'static [(usize, &'static [u8])]> {
    const ZIP: &[(usize, &[u8])] = &[(0, b"PK\x03\x04"), (0, b"PK\x05\x06")];
    const OLE: &[(usize, &[u8])] = &[(0, b"\xD0\xCF\x11\xE0")];
    Some(match ext {
        "pdf" => &[(0, b"%PDF")],
        "jpg" | "jpeg" => &[(0, b"\xFF\xD8\xFF")],
        "png" => &[(0, b"\x89PNG")],
        "gif" => &[(0, b"GIF8")],
        "bmp" => &[(0, b"BM")],
        "tif" | "tiff" => &[(0, b"II*\0"), (0, b"MM\0*")],
        "webp" | "wav" | "avi" => &[(0, b"RIFF")],
        "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "odg" | "epub" | "jar"
        | "apk" | "kra" | "ora" => ZIP,
        "doc" | "xls" | "ppt" | "msg" => OLE,
        "gz" | "tgz" => &[(0, b"\x1F\x8B")],
        "xz" | "txz" => &[(0, b"\xFD7zXZ")],
        "bz2" => &[(0, b"BZh")],
        "zst" => &[(0, b"\x28\xB5\x2F\xFD")],
        "7z" => &[(0, b"7z\xBC\xAF")],
        "rar" => &[(0, b"Rar!")],
        "mp4" | "m4a" | "m4v" | "mov" | "heic" | "3gp" => &[(4, b"ftyp")],
        "mkv" | "webm" => &[(0, b"\x1A\x45\xDF\xA3")],
        "ogg" | "opus" | "oga" => &[(0, b"OggS")],
        "flac" => &[(0, b"fLaC")],
        "mp3" => &[
            (0, b"ID3"),
            (0, b"\xFF\xFB"),
            (0, b"\xFF\xF3"),
            (0, b"\xFF\xF2"),
        ],
        "sqlite" | "db" => &[(0, b"SQLite format 3\0")],
        "psd" => &[(0, b"8BPS")],
        "xcf" => &[(0, b"gimp xcf")],
        _ => return None,
    })
}

fn known_ext(ext: &str) -> bool {
    magic(ext).is_some() || TEXT_EXTS.contains(&ext)
}

fn ext_of(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

/// Shannon entropy in bits per byte.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn looks_random(head: &[u8]) -> bool {
    // Short files have too few bytes for a meaningful entropy.
    if head.len() >= 512 {
        return entropy(head) > 7.5;
    }
    let binary = head
        .iter()
        .filter(|b| !(b.is_ascii_graphic() || b.is_ascii_whitespace() || **b >= 0x80))
        .count();
    binary * 10 > head.len() * 3
}

/// Whether a file's first bytes no longer fit its name. `None` if it says nothing (empty,
/// unknown type with ordinary content).
pub fn verdict(name: &str, head: &[u8]) -> Option<bool> {
    if head.is_empty() {
        return None;
    }
    let mut ext = ext_of(name);
    // `report.pdf.locked`: judge by the name it had.
    if let Some(e) = &ext
        && !known_ext(e)
        && let Some(stem) = name.rsplit_once('.').map(|(s, _)| s)
    {
        ext = ext_of(stem).filter(|e| known_ext(e)).or(ext);
    }
    match ext.as_deref() {
        Some(e) if magic(e).is_some() => {
            let ok = magic(e)
                .unwrap()
                .iter()
                .any(|(off, m)| head.len() >= off + m.len() && &head[*off..off + m.len()] == *m);
            Some(!ok)
        }
        Some(e) if TEXT_EXTS.contains(&e) => Some(looks_random(head)),
        _ => looks_random(head).then_some(true),
    }
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    // Paths come from the processes being watched: never follow a link, never wait on a FIFO
    // or device, and only read regular files.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = vec![0; 4096];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    buf.truncate(n);
    Some(buf)
}

/// A path in a person's own files: below a home folder, not in a hidden or build folder.
pub fn user_data(path: &Path) -> bool {
    let rest = if let Ok(r) = path.strip_prefix("/root") {
        r
    } else if let Ok(r) = path.strip_prefix("/home") {
        // Skip the user name.
        let mut c = r.components();
        if c.next().is_none() {
            return false;
        }
        c.as_path()
    } else {
        return false;
    };
    let parts: Vec<_> = rest.components().collect();
    if parts.is_empty() {
        return false;
    }
    parts.iter().all(|c| match c {
        Component::Normal(n) => {
            let n = n.to_string_lossy();
            !n.starts_with('.') && !SKIP_DIRS.contains(&n.as_ref())
        }
        _ => false,
    }) || is_decoy(path)
}

pub fn is_decoy(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().contains(DECOY_MARK))
}

fn is_note(path: &Path) -> bool {
    path.file_name().is_some_and(|n| {
        let n = n.to_string_lossy().to_ascii_lowercase();
        NOTE_PATTERNS.iter().any(|p| n.contains(p))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Opened for writing with these open flags.
    Write {
        flags: u32,
    },
    Rename {
        from: Option<PathBuf>,
    },
    Unlink,
}

const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_EXCL: u32 = libc::O_EXCL as u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Decoy(PathBuf),
    Content { suspicious: usize, sampled: usize },
    Suffix { suffix: String, count: usize },
    Notes { dirs: usize },
}

impl Reason {
    pub fn describe(&self) -> String {
        use wachposten_core::i18n::tr;
        match self {
            Reason::Decoy(p) => format!(
                "{}: {}",
                tr("Köderdatei verändert", "decoy file changed"),
                p.display()
            ),
            Reason::Content {
                suspicious,
                sampled,
            } => format!(
                "{suspicious}/{sampled} {}",
                tr(
                    "geprüfte Dateien sehen verschlüsselt aus",
                    "checked files look encrypted"
                )
            ),
            Reason::Suffix { suffix, count } => format!(
                "{count} {} .{suffix}",
                tr("Dateien umbenannt auf", "files renamed to")
            ),
            Reason::Notes { dirs } => format!(
                "{} {dirs} {}",
                tr("Erpresserbriefe in", "ransom notes in"),
                tr("Ordnern", "folders")
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alarm {
    /// The process the alarm is about (the writer, or its parent for many small helpers).
    pub pid: u32,
    pub reason: Reason,
    /// Files changed in the window, newest first, at most ten.
    pub files: Vec<PathBuf>,
    pub count: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub files: usize,
    pub window: Duration,
}

/// Distinct changed files remembered per process; more than the threshold is never needed.
const MAX_TRACKED: usize = 4096;
/// Changes kept in time order per process.
const MAX_ORDER: usize = 16384;

#[derive(Default)]
struct Track {
    /// Changed files and when they were changed last.
    changed: HashMap<PathBuf, Instant>,
    /// The same changes in time order, so old ones can be dropped without a full scan.
    order: VecDeque<(Instant, PathBuf)>,
    /// Files written or renamed to, newest last, for content samples.
    written: VecDeque<PathBuf>,
    suffixes: HashMap<String, usize>,
    note_dirs: HashSet<PathBuf>,
    last_check: Option<Instant>,
    last_seen: Option<Instant>,
}

impl Track {
    fn prune(&mut self, now: Instant, window: Duration) {
        while let Some((t, _)) = self.order.front() {
            if now.duration_since(*t) <= window && self.order.len() <= MAX_ORDER {
                break;
            }
            let (t, p) = self.order.pop_front().expect("front exists");
            if self.changed.get(&p) == Some(&t) {
                self.changed.remove(&p);
            }
        }
    }

    fn touch(&mut self, path: PathBuf, now: Instant) {
        if self.changed.len() >= MAX_TRACKED && !self.changed.contains_key(&path) {
            return;
        }
        self.changed.insert(path.clone(), now);
        self.order.push_back((now, path));
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        self.order
            .iter()
            .rev()
            .filter(|(_, p)| seen.insert(p))
            .take(10)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

pub struct Detector {
    limits: Limits,
    tracks: HashMap<u32, Track>,
    /// Processes already reported or allowed; they are not reported again.
    silenced: HashSet<u32>,
}

impl Detector {
    pub fn new(limits: Limits) -> Detector {
        Detector {
            limits,
            tracks: HashMap::new(),
            silenced: HashSet::new(),
        }
    }

    /// Do not report this process again.
    pub fn silence(&mut self, pid: u32) {
        self.silenced.insert(pid);
        self.tracks.remove(&pid);
    }

    pub fn is_silenced(&self, pid: u32) -> bool {
        self.silenced.contains(&pid)
    }

    /// Drop processes that were quiet for a while.
    pub fn prune(&mut self, now: Instant) {
        let keep = self.limits.window * 3;
        self.tracks
            .retain(|_, t| t.last_seen.is_some_and(|s| now.duration_since(s) <= keep));
        if self.silenced.len() > 10_000 {
            self.silenced.clear();
        }
    }

    /// Count one file operation of process `pid`, whose parent is `ppid`. Returns an alarm
    /// once one of them looks like ransomware.
    pub fn observe(
        &mut self,
        pid: u32,
        ppid: Option<u32>,
        path: &Path,
        op: &Op,
        now: Instant,
    ) -> Option<Alarm> {
        let decoy = match op {
            Op::Rename { from } => is_decoy(path) || from.as_deref().is_some_and(is_decoy),
            // Creating one with O_EXCL (how the agent does it) cannot change an existing file.
            Op::Write { flags } => {
                is_decoy(path) && flags & (O_TRUNC | O_WRONLY | O_RDWR) != 0 && flags & O_EXCL == 0
            }
            Op::Unlink => is_decoy(path),
        };
        if decoy {
            if self.silenced.contains(&pid) {
                return None;
            }
            let decoy_path = match op {
                Op::Rename { from: Some(f) } if is_decoy(f) => f.clone(),
                _ => path.to_path_buf(),
            };
            return Some(Alarm {
                pid,
                reason: Reason::Decoy(decoy_path.clone()),
                files: vec![decoy_path],
                count: 1,
            });
        }

        let from_user_data = matches!(op, Op::Rename { from: Some(f) } if user_data(f));
        if !user_data(path) && !from_user_data {
            return None;
        }
        let counts = match op {
            Op::Write { flags } => {
                flags & O_TRUNC != 0 || (flags & (O_WRONLY | O_RDWR) != 0 && flags & O_CREAT == 0)
            }
            Op::Rename { .. } | Op::Unlink => true,
        };
        let creates = matches!(op, Op::Write { flags } if flags & O_CREAT != 0);
        let note = creates && is_note(path);
        if !counts && !note && !creates {
            return None;
        }

        let mut alarm = None;
        for key in std::iter::once(pid).chain(ppid.filter(|p| *p > 1 && *p != pid)) {
            if self.silenced.contains(&key) {
                continue;
            }
            let limits = self.limits;
            let t = self.tracks.entry(key).or_default();
            t.last_seen = Some(now);
            t.prune(now, limits.window);
            if counts {
                let changed = match op {
                    Op::Rename { from: Some(f) } => f.clone(),
                    _ => path.to_path_buf(),
                };
                t.touch(changed, now);
            }
            if !matches!(op, Op::Unlink) && (counts || creates) {
                t.written.push_back(path.to_path_buf());
                if t.written.len() > 32 {
                    t.written.pop_front();
                }
            }
            if note && let Some(dir) = path.parent() {
                t.note_dirs.insert(dir.to_path_buf());
            }
            if let Op::Rename { from: Some(from) } = op
                && let (Some(old), Some(new)) = (from.file_name(), path.file_name())
            {
                let (old, new) = (old.to_string_lossy(), new.to_string_lossy());
                if let Some(suffix) = new
                    .strip_prefix(old.as_ref())
                    .and_then(|s| s.strip_prefix('.'))
                {
                    let suffix = suffix.to_ascii_lowercase();
                    if !suffix.is_empty()
                        && suffix.len() <= 24
                        && !HARMLESS_SUFFIXES.contains(&suffix.as_str())
                        && !known_ext(&suffix)
                    {
                        let n = t.suffixes.entry(suffix.clone()).or_default();
                        *n += 1;
                        if *n >= 10 {
                            alarm = Some(Alarm {
                                pid: key,
                                reason: Reason::Suffix { suffix, count: *n },
                                files: t.files(),
                                count: t.changed.len(),
                            });
                            break;
                        }
                    }
                }
            }
            if t.changed.len() < limits.files {
                continue;
            }
            if t.note_dirs.len() >= 3 {
                alarm = Some(Alarm {
                    pid: key,
                    reason: Reason::Notes {
                        dirs: t.note_dirs.len(),
                    },
                    files: t.files(),
                    count: t.changed.len(),
                });
                break;
            }
            if t.last_check
                .is_some_and(|c| now.duration_since(c) < Duration::from_secs(1))
            {
                continue;
            }
            t.last_check = Some(now);
            let (suspicious, sampled) = sample(&t.written);
            if sampled >= 4 && suspicious * 10 >= sampled * 6 {
                alarm = Some(Alarm {
                    pid: key,
                    reason: Reason::Content {
                        suspicious,
                        sampled,
                    },
                    files: t.files(),
                    count: t.changed.len(),
                });
                break;
            }
        }
        if let Some(a) = &alarm {
            self.silence(a.pid);
        }
        alarm
    }
}

/// Look at up to ten of the files written last: (suspicious, judged).
fn sample(written: &VecDeque<PathBuf>) -> (usize, usize) {
    let mut seen = HashSet::new();
    let (mut suspicious, mut sampled) = (0, 0);
    for path in written.iter().rev() {
        if sampled >= 10 {
            break;
        }
        if !seen.insert(path) {
            continue;
        }
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Some(head) = read_head(path) else {
            continue;
        };
        if let Some(bad) = verdict(&name, &head) {
            sampled += 1;
            suspicious += usize::from(bad);
        }
    }
    (suspicious, sampled)
}

/// Whether `/home` lies on btrfs, and which tool takes snapshots of it, if any (snapper,
/// Timeshift, btrbk). Snapshots are what gets files back after an attack.
pub fn home_snapshots() -> (bool, Option<&'static str>) {
    let btrfs = home_fs_type().as_deref() == Some("btrfs");
    let snapper = std::fs::read_dir("/etc/snapper/configs").is_ok_and(|d| {
        d.flatten().any(|e| {
            std::fs::read_to_string(e.path()).is_ok_and(|t| {
                t.lines()
                    .any(|l| l.trim().replace(' ', "") == "SUBVOLUME=\"/home\"")
            })
        })
    });
    let timeshift = std::fs::read_to_string("/etc/timeshift/timeshift.json").is_ok_and(|t| {
        let t = t.replace(' ', "");
        t.contains("\"include_btrfs_home_for_backup\":\"true\"")
            || t.contains("\"include_btrfs_home\":\"true\"")
    });
    let btrbk = std::fs::read_to_string("/etc/btrbk/btrbk.conf").is_ok_and(|t| {
        t.lines()
            .any(|l| l.trim_start().starts_with("subvolume") && l.contains("home"))
    });
    let tool = if snapper {
        Some("snapper")
    } else if timeshift {
        Some("Timeshift")
    } else if btrbk {
        Some("btrbk")
    } else {
        None
    };
    (btrfs, tool)
}

/// File system type of the mount that holds `/home`.
fn home_fs_type() -> Option<String> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in info.lines() {
        // id parent dev root mountpoint options ... - fstype source superoptions
        let mut parts = line.split(" - ");
        let (Some(left), Some(right)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(mount) = left.split(' ').nth(4) else {
            continue;
        };
        let Some(fstype) = right.split(' ').next() else {
            continue;
        };
        if Path::new("/home").starts_with(mount)
            && best.as_ref().is_none_or(|(len, _)| mount.len() > *len)
        {
            best = Some((mount.len(), fstype.to_string()));
        }
    }
    best.map(|(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W_NEW: u32 = O_WRONLY | O_CREAT | O_TRUNC;

    fn noise(n: usize) -> Vec<u8> {
        // A simple generator is enough for high entropy.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_and_headers() {
        assert!(entropy(&noise(4096)) > 7.5);
        assert!(entropy(b"hello hello hello hello") < 4.0);
        assert_eq!(verdict("a.pdf", b"%PDF-1.7 ..."), Some(false));
        assert_eq!(verdict("a.pdf", &noise(4096)), Some(true));
        assert_eq!(verdict("a.jpg", b"\xFF\xD8\xFF\xE0rest"), Some(false));
        assert_eq!(verdict("a.docx", b"PK\x03\x04rest"), Some(false));
        assert_eq!(
            verdict("a.txt", "Liebe Grüße\n".repeat(80).as_bytes()),
            Some(false)
        );
        assert_eq!(verdict("a.txt", &noise(4096)), Some(true));
        // Renamed with a new ending: judged by the old one.
        assert_eq!(verdict("a.pdf.locked", &noise(4096)), Some(true));
        assert_eq!(verdict("a.pdf.locked", b"%PDF-1.7"), Some(false));
        // Unknown type with ordinary content says nothing.
        assert_eq!(verdict("a.weird", b"some text here"), None);
        assert_eq!(verdict("a.txt", b""), None);
    }

    #[test]
    fn user_data_paths() {
        assert!(user_data(Path::new("/home/anna/Dokumente/brief.odt")));
        assert!(user_data(Path::new("/root/notes.txt")));
        assert!(!user_data(Path::new("/home/anna/.cache/x")));
        assert!(!user_data(Path::new("/home/anna/code/app/target/debug/x")));
        assert!(!user_data(Path::new(
            "/home/anna/code/app/node_modules/x/y.js"
        )));
        assert!(!user_data(Path::new("/tmp/x")));
        assert!(!user_data(Path::new("/home/anna")));
        assert!(user_data(Path::new(
            "/home/anna/Bilder/.wachposten-koeder.docx"
        )));
    }

    fn limits() -> Limits {
        Limits {
            files: 25,
            window: Duration::from_secs(20),
        }
    }

    #[test]
    fn encrypting_in_place_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        // Pretend the temporary folder is a home folder by testing the sample directly.
        let mut written = VecDeque::new();
        for i in 0..12 {
            let p = dir.path().join(format!("doc{i}.pdf"));
            std::fs::write(&p, noise(4096)).unwrap();
            written.push_back(p);
        }
        assert_eq!(sample(&written), (10, 10));
        let mut written = VecDeque::new();
        for i in 0..12 {
            let p = dir.path().join(format!("ok{i}.pdf"));
            std::fs::write(&p, b"%PDF-1.7 fine").unwrap();
            written.push_back(p);
        }
        assert_eq!(sample(&written), (0, 10));
    }

    #[test]
    fn rate_without_bad_content_is_quiet() {
        let mut d = Detector::new(limits());
        let now = Instant::now();
        for i in 0..200 {
            // Files that do not exist are not judged, so no content alarm.
            let p = PathBuf::from(format!("/home/anna/Bilder/export/img{i}.jpg"));
            assert!(
                d.observe(10, Some(5), &p, &Op::Write { flags: W_NEW }, now)
                    .is_none()
            );
        }
    }

    #[test]
    fn same_new_suffix_is_caught_through_the_parent() {
        let mut d = Detector::new(limits());
        let now = Instant::now();
        let mut alarm = None;
        for i in 0..10 {
            let from = PathBuf::from(format!("/home/anna/Dokumente/f{i}.odt"));
            let to = PathBuf::from(format!("/home/anna/Dokumente/f{i}.odt.crypt"));
            // A new helper process per file, all started by the same script (pid 7).
            alarm =
                alarm.or(d.observe(100 + i, Some(7), &to, &Op::Rename { from: Some(from) }, now));
        }
        let alarm = alarm.expect("alarm");
        assert_eq!(alarm.pid, 7);
        assert_eq!(
            alarm.reason,
            Reason::Suffix {
                suffix: "crypt".into(),
                count: 10
            }
        );
        // Reported once.
        assert!(d.is_silenced(7));
    }

    #[test]
    fn harmless_suffixes_are_ignored() {
        let mut d = Detector::new(limits());
        let now = Instant::now();
        for i in 0..30 {
            let from = PathBuf::from(format!("/home/anna/Dokumente/f{i}.txt"));
            let to = PathBuf::from(format!("/home/anna/Dokumente/f{i}.txt.bak"));
            assert!(
                d.observe(9, None, &to, &Op::Rename { from: Some(from) }, now)
                    .is_none()
            );
        }
    }

    #[test]
    fn decoy_triggers_at_once() {
        let mut d = Detector::new(limits());
        let now = Instant::now();
        let p = PathBuf::from("/home/anna/Dokumente/!wachposten-koeder.docx");
        let a = d
            .observe(3, None, &p, &Op::Write { flags: O_WRONLY }, now)
            .unwrap();
        assert_eq!(a.reason, Reason::Decoy(p.clone()));
        let a = d.observe(4, None, &p, &Op::Unlink, now).unwrap();
        assert_eq!(a.pid, 4);
        // Reading it, or creating it exclusively as the agent does, is fine.
        assert!(
            d.observe(5, None, &p, &Op::Write { flags: 0 }, now)
                .is_none()
        );
        let create = O_WRONLY | O_CREAT | O_EXCL;
        assert!(
            d.observe(6, None, &p, &Op::Write { flags: create }, now)
                .is_none()
        );
    }

    #[test]
    fn many_events_stay_cheap() {
        let mut d = Detector::new(limits());
        let now = Instant::now();
        let start = Instant::now();
        for i in 0..60_000 {
            let p = PathBuf::from(format!("/home/anna/Notizen/n{i}.txt"));
            d.observe(42, Some(7), &p, &Op::Write { flags: W_NEW }, now);
        }
        assert!(d.tracks[&42].changed.len() <= MAX_TRACKED);
        // Generous for debug builds on slow machines; the old full scan took minutes.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn window_forgets_old_changes() {
        let mut d = Detector::new(Limits {
            files: 3,
            window: Duration::from_secs(1),
        });
        let t0 = Instant::now();
        for i in 0..2 {
            let p = PathBuf::from(format!("/home/anna/Dokumente/a{i}.txt"));
            d.observe(1, None, &p, &Op::Unlink, t0);
        }
        let later = t0 + Duration::from_secs(5);
        d.observe(
            1,
            None,
            Path::new("/home/anna/Dokumente/b.txt"),
            &Op::Unlink,
            later,
        );
        assert_eq!(d.tracks[&1].changed.len(), 1);
    }
}
