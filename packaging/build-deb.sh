#!/bin/sh
# Builds a .deb for Debian and Ubuntu from the working tree.
# Needs: cargo, clang, pkg-config, libfontconfig-dev, libxkbcommon-dev, dpkg-dev.
# Output: target/deb/wachposten_<version>_<arch>.deb
set -eu
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(dpkg --print-architecture)
cargo build --release --locked -p wachposten -p wachposten-agent -p wachposten-daemon
root="$PWD/target/deb/root"
rm -rf "$root"
packaging/install-tree.sh "$root"
strip --strip-unneeded "$root"/usr/bin/wachposten*
mkdir -p "$root/DEBIAN"
size=$(du -sk "$root" | cut -f1)
cat > "$root/DEBIAN/control" <<CONTROL
Package: wachposten
Version: $version-1
Architecture: $arch
Maintainer: Two-Play <https://github.com/Two-Play/wachposten>
Installed-Size: $size
Depends: libc6, libfontconfig1, libxkbcommon0, cron | cron-daemon
Recommends: clamav-daemon
Suggests: python3-nautilus
Section: admin
Priority: optional
Homepage: https://github.com/Two-Play/wachposten
Description: Security guard for Linux desktops
 Watches the places malware uses to start again (autostart, systemd units,
 shell files, cron, LD_PRELOAD, SSH keys, browser extensions …), program
 starts from temporary folders and ransomware, and asks the person at the
 computer. Known malware is found with YARA-X rules, a MalwareBazaar hash
 list and optionally ClamAV.
CONTROL
echo /etc/wachposten/daemon.toml > "$root/DEBIAN/conffiles"
echo /etc/xdg/autostart/wachposten-agent.desktop >> "$root/DEBIAN/conffiles"
cat > "$root/DEBIAN/postinst" <<'SCRIPT'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Restart a running daemon after an upgrade; a new install is enabled by the admin.
    systemctl try-restart wachposten-daemon.service || true
fi
SCRIPT
cat > "$root/DEBIAN/prerm" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now wachposten-daemon.service || true
fi
SCRIPT
chmod 755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm"
out="$PWD/target/deb/wachposten_${version}-1_${arch}.deb"
dpkg-deb --root-owner-group --build "$root" "$out" >/dev/null
echo "$out"
