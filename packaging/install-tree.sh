#!/bin/sh
# Installs the built release binaries and the data files into a staging tree, for packages
# other than the RPM (which has its own %install). Usage: install-tree.sh <destdir>
set -eu
cd "$(dirname "$0")/.."
dest=$1
bin=/usr/bin
rel=${CARGO_TARGET_DIR:-target}/release
install -Dm755 "$rel"/wachposten        "$dest$bin/wachposten"
install -Dm755 "$rel"/wachposten-agent  "$dest$bin/wachposten-agent"
install -Dm755 "$rel"/wachposten-daemon "$dest$bin/wachposten-daemon"
install -Dm644 packaging/systemd/wachposten-daemon.service "$dest/usr/lib/systemd/system/wachposten-daemon.service"
sed -i "s|/usr/local/bin/|$bin/|" "$dest/usr/lib/systemd/system/wachposten-daemon.service"
install -Dm644 packaging/systemd/wachposten-agent.service "$dest/usr/lib/systemd/user/wachposten-agent.service"
sed -i "s|%h/.cargo/bin/|$bin/|" "$dest/usr/lib/systemd/user/wachposten-agent.service"
install -Dm644 packaging/daemon.toml "$dest/etc/wachposten/daemon.toml"
install -Dm644 packaging/wachposten.desktop "$dest/usr/share/applications/wachposten.desktop"
install -Dm644 packaging/wachposten-agent-autostart.desktop "$dest/etc/xdg/autostart/wachposten-agent.desktop"
install -Dm644 crates/app/ui/icon.svg "$dest/usr/share/icons/hicolor/scalable/apps/wachposten.svg"
install -Dm644 packaging/integration/wachposten-scan.desktop "$dest/usr/share/kio/servicemenus/wachposten-scan.desktop"
install -Dm644 packaging/integration/wachposten-nautilus.py "$dest/usr/share/nautilus-python/extensions/wachposten.py"
install -Dm644 LICENSE "$dest/usr/share/licenses/wachposten/LICENSE"
install -Dm644 README.md "$dest/usr/share/doc/wachposten/README.md"
