# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-12

The first release, with all six stages.

### Added

- **Persistence watch** in the home folder: autostart, systemd user units, shell and session
  files, environment, SSH keys, cron, launchers, Firefox extensions, git hooks and aliases,
  Python `.pth` files and systemd generators. A baseline on the first start, then a
  question, a warning or a hint for every change, with Remove (undo into quarantine), Allow
  and Later.
- **Known malware**: built-in YARA-X rules for Linux, the MalwareBazaar hash list (with your
  own Auth-Key), optional ClamAV through `clamd`. New downloads are scanned when they are
  finished.
- **System daemon** (`wachposten-daemon`, root): fanotify refuses known malware started from
  `/tmp`, `/dev/shm` and `/run/user`, reports other starts from temporary folders, and keeps a
  baseline of system persistence locations in `/etc` and `/var/spool/cron`.
- **eBPF**: scripts started through interpreters, programs started from memory (`memfd`), and
  which process changed a watched file.
- **Ransomware**: mass encryption is found by rate and content, with optional decoy files.
  The process is stopped and its owner decides: End it or Let it run. The status shows
  whether `/home` has snapshots.
- **Window and tray**: overview, alerts, history, quarantine, allowed files and settings, in
  light and dark, German and English. ClamAV is found again every minute or with Check
  again, and the overview shows the commands that set clamd up.
- **Check with Wachposten** in Dolphin and GNOME Files; findings become alerts, and the
  notification offers Quarantine and Show.
- **Command line**: `wachposten status`, `events`, `allow`, `remove`, `restore`,
  `scan-file`, `export`, `integrate` and more, also for the system daemon with `--system`.
- **Packages** for Fedora 44 (RPM), Debian 13 (`.deb`, built on trixie) and Arch Linux.

[Unreleased]: https://github.com/Two-Play/wachposten/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Two-Play/wachposten/releases/tag/v0.1.0
