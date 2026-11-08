# Wachposten

Wachposten guards a Linux desktop against malware that tries to settle in. Malware on
Linux has to start again after a reboot or login, and the places it can use for that are few:
autostart entries, systemd user units, shell startup files, cron, `LD_PRELOAD`, SSH keys.
Wachposten watches these places and asks the person at the computer about every new or
changed entry:

> **New autostart entry** — A program added itself to your autostart.
> `~/.config/autostart/update.desktop` · ⚠ starts something from a temporary folder
> **[Remove] [Allow] [Later]**

Known malware is recognised in later stages with YARA-X rules and hash lists, and ClamAV can
be added for Windows files and mail attachments. The core is the persistence and behaviour
watch, because no maintained open signature database for Linux desktop malware exists.

**Status: stage 2 of 5.** The agent watches the home directory and scans downloads. See [Roadmap](#roadmap).

## What is watched (stage 1)

| Kind | Locations |
|---|---|
| Autostart | `~/.config/autostart/*.desktop`, `~/.config/autostart-scripts/` |
| systemd user | `~/.config/systemd/user/`, `~/.local/share/systemd/user/` (units, drop-ins, enablement links) |
| Shell | `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`, `.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.zlogout`, fish config |
| Session | `.xprofile`, `.xsessionrc`, `.xinitrc`, Plasma `env` and `shutdown` scripts |
| Environment | `~/.config/environment.d/*.conf`, `.pam_environment` |
| SSH | `authorized_keys`, `authorized_keys2`, `~/.ssh/rc` |
| cron | the user's crontab (`crontab -l`, checked every minute) |

On the first start the current state is recorded as the baseline without asking. After that
every change becomes an event:

- **Allow** makes the new version the baseline.
- **Remove** moves the new version into quarantine and puts the old version back (or deletes a
  new entry). systemd units are stopped and systemd is reloaded.
- **Later** keeps the event open in the tray.

Deleted entries are recorded without a question. Changes undone before a decision close the
event. A decision is refused if the entry changed again after the message was shown, so a
click never allows something the person did not see.

New lines are checked against rules for typical persistence tricks: `LD_PRELOAD`, downloads
piped into a shell, embedded interpreter code, base64 blobs, programs in `/tmp`, `/dev/shm`
or hidden folders, reverse shells, background processes and SSH keys with forced commands.
A match marks the event as suspicious and the message stays on screen.

## Known malware (stage 2)

New files in the download folder (`XDG_DOWNLOAD_DIR`, usually `~/Downloads`) are scanned once
the browser has finished them. Programs that a new autostart entry or service starts are
scanned as well. Two checks run:

- **YARA-X** with built-in rules for Linux: XMRig miners, miner-killing cryptojacking scripts,
  reverse shells, `LD_PRELOAD` rootkits, persistence installer scripts, Gafgyt/Mirai botnet
  clients and PHP web shells. Every rule needs several independent indicators; a scan of about
  11,000 files in `/usr/bin`, `/usr/libexec`, `/usr/lib64` and `/usr/share` gave no hits. More
  rule folders can be added, see [rules/SOURCES.md](crates/scan/rules/SOURCES.md).
- **Hash list** of known samples from [MalwareBazaar](https://bazaar.abuse.ch/). It is off until
  you store your own free Auth-Key from [auth.abuse.ch](https://auth.abuse.ch/). The agent then
  downloads the hashes of the last 48 hours every 6 hours; nothing about your files is sent.
  abuse.ch allows this for non-commercial use only. Full dumps can be imported by hand.
  An optional online lookup sends the SHA-256 of scanned files to MalwareBazaar; it is off
  unless you switch it on.

A hit raises a "Malware detected" message. **Remove** moves the file into quarantine,
**Allow** remembers its hash so it is not reported again. To check that everything works, put a
file with the text `WACHPOSTEN-TEST-SIGNATURE-7f3a9c2e-NOT-MALWARE` into the download folder.

## Usage

```bash
cargo install --path crates/agent
cargo install --path crates/app
install -Dm644 packaging/systemd/wachposten-agent.service ~/.config/systemd/user/wachposten-agent.service
systemctl --user enable --now wachposten-agent
```

```
wachposten status            # agent state, baseline size, open events
wachposten events [--all]    # open (or all recent) events
wachposten show <id>         # added lines and findings
wachposten allow <id>
wachposten remove <id>
wachposten quarantine
wachposten restore <id> [--force]
wachposten scan              # check now without the agent
wachposten scan-file <files> # check files for known malware (exit code 1 on a hit)
wachposten rules             # rule files and whether they compiled
wachposten hashes status|update|import <file>
wachposten config [show|set-key <key>|unset-key|online-lookup on|off|downloads on|off]
```

Settings live in `$XDG_CONFIG_HOME/wachposten/config.toml` (mode 0600); restart the agent
after changing them.

Data lives in `$XDG_DATA_HOME/wachposten` (`state.db`, `hashes.db`, `quarantine/`). Set
`WACHPOSTEN_NO_CRONTAB=1` to switch crontab watching off. Messages are German when the locale
starts with `de`, English otherwise.

## Limits

- The agent runs as the user. Malware running as the same user can stop it or change its
  database. The root daemon in stage 3 closes this gap for system locations and process starts.
- Wachposten does not know yet which program made a change (stage 5, eBPF).
- Removing an autostart entry does not stop a program that already runs.
- Archives are not unpacked; only the archive itself is checked. ClamAV (stage 4) covers that.
- Only the top level of the download folder is watched.

## Roadmap

1. **Persistence in the home directory** – agent, tray, notifications, CLI *(done)*
2. **Downloads, hashes, YARA-X** – scan new downloads, local MalwareBazaar hash list (opt-in), curated YARA-X rules *(done)*
3. **Daemon** – fanotify for program starts from `/tmp`, `/var/tmp`, `/dev/shm`, `~/.cache`; system locations such as `/etc/ld.so.preload`, `/etc/cron*`, `/etc/systemd/system`
4. **Slint window and ClamAV** – history, allowed entries, quarantine, settings; optional ClamAV via `clamd`
5. **eBPF and packages** – process starts through interpreters and `memfd`, which program changed a file, RPM

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The workspace has `crates/core` (baseline, analysis, decisions, settings, SQLite),
`crates/watch` (inotify), `crates/scan` (YARA-X, hash list, MalwareBazaar), `crates/agent`
(tray and notifications) and `crates/app` (CLI, later the window).

`yara-x` 1.23 does not build with the newest `rsa` release candidate, so `Cargo.lock` pins
`rsa` to `0.10.0-rc.19`. Keep that pin when running `cargo update`.

## License

GPL-3.0-or-later.
