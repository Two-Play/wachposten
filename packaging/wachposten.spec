Name:           wachposten
Version:        0.1.0
Release:        1%{?dist}
Summary:        Guard against malware settling in on Linux desktops
License:        GPL-3.0-or-later
URL:            https://github.com/Two-Play/wachposten
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo >= 1.89
BuildRequires:  rust >= 1.89
BuildRequires:  clang
BuildRequires:  gcc
BuildRequires:  kernel-headers
BuildRequires:  pkgconfig(fontconfig)
BuildRequires:  pkgconfig(xkbcommon)
BuildRequires:  systemd-rpm-macros
Requires:       cronie
Recommends:     clamd
Suggests:       nautilus-python
Suggests:       snapper

%description
Wachposten watches the places malware uses to start again after a reboot or login
(autostart, systemd units, shell files, cron, LD_PRELOAD, SSH keys, sudoers) and asks the
person at the computer about every change. It checks downloads and programs started from
temporary folders with YARA-X, an optional MalwareBazaar hash list and ClamAV, blocks known
malware in /tmp and /dev/shm, and names the program behind a change with eBPF.

%prep
%autosetup

%build
# Crates are vendored in the source archive; nothing is downloaded.
cargo build --release --offline --locked

%install
install -Dm755 target/release/wachposten        %{buildroot}%{_bindir}/wachposten
install -Dm755 target/release/wachposten-agent  %{buildroot}%{_bindir}/wachposten-agent
install -Dm755 target/release/wachposten-daemon %{buildroot}%{_bindir}/wachposten-daemon
install -Dm644 packaging/systemd/wachposten-daemon.service %{buildroot}%{_unitdir}/wachposten-daemon.service
sed -i 's|/usr/local/bin/|%{_bindir}/|' %{buildroot}%{_unitdir}/wachposten-daemon.service
install -Dm644 packaging/systemd/wachposten-agent.service %{buildroot}%{_userunitdir}/wachposten-agent.service
sed -i 's|%%h/.cargo/bin/|%{_bindir}/|' %{buildroot}%{_userunitdir}/wachposten-agent.service
install -Dm644 packaging/daemon.toml %{buildroot}%{_sysconfdir}/wachposten/daemon.toml
install -Dm644 packaging/wachposten.desktop %{buildroot}%{_datadir}/applications/wachposten.desktop
install -Dm644 packaging/wachposten-agent-autostart.desktop %{buildroot}%{_sysconfdir}/xdg/autostart/wachposten-agent.desktop
install -Dm644 crates/app/ui/icon.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/wachposten.svg
install -Dm644 packaging/integration/wachposten-scan.desktop %{buildroot}%{_datadir}/kio/servicemenus/wachposten-scan.desktop
install -Dm644 packaging/integration/wachposten-nautilus.py %{buildroot}%{_datadir}/nautilus-python/extensions/wachposten.py

%post
%systemd_post wachposten-daemon.service

%preun
%systemd_preun wachposten-daemon.service

%postun
%systemd_postun_with_restart wachposten-daemon.service

%files
%license LICENSE
%doc README.md crates/scan/rules/SOURCES.md
%{_bindir}/wachposten
%{_bindir}/wachposten-agent
%{_bindir}/wachposten-daemon
%{_unitdir}/wachposten-daemon.service
%{_userunitdir}/wachposten-agent.service
%dir %{_sysconfdir}/wachposten
%config(noreplace) %{_sysconfdir}/wachposten/daemon.toml
%config(noreplace) %{_sysconfdir}/xdg/autostart/wachposten-agent.desktop
%{_datadir}/applications/wachposten.desktop
%{_datadir}/icons/hicolor/scalable/apps/wachposten.svg
%dir %{_datadir}/kio
%dir %{_datadir}/kio/servicemenus
%{_datadir}/kio/servicemenus/wachposten-scan.desktop
%dir %{_datadir}/nautilus-python
%dir %{_datadir}/nautilus-python/extensions
%{_datadir}/nautilus-python/extensions/wachposten.py

%changelog
* Sun Nov 08 2026 Philippe <twoplay19@gmail.com> - 0.1.0-1
- First package: agent, window, root daemon with fanotify and eBPF
