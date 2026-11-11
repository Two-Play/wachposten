#!/usr/bin/env python3
"""A Fedora KDE Plasma VM to try Wachposten by hand: popups, tray, window, file manager menu.

Usage: test/desktop-vm.py [--update] [--reset] [--no-gl]

The first run builds the VM: Fedora Cloud image, KDE Plasma, German locale and keyboard, a user
"anna" (admin, logged in automatically, password "wachposten" for sudo), the newest RPM from
target/rpm (packaging/build-rpm.sh) and test scripts in ~/Tests. That downloads about 2 GB and
takes 15-20 minutes. Later runs only open the VM window; changes inside the VM are kept.

--update   install the newest RPM from target/rpm into the VM before using it
--reset    throw the VM away and build it again
--no-gl    plain virtio graphics, if the window stays black with OpenGL

The disk lives in ~/.cache/wachposten-vm/desktop (or $VM_CACHE/desktop). Needs no root on the
host: QEMU with KVM and user networking, like test/vm.py. While the VM runs:
ssh -i ~/.cache/wachposten-vm/desktop/id -p 2348 fedora@127.0.0.1
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vm import CACHE, ROOT, TEST_SIGNATURE, cloud_image  # noqa: E402

DIR = os.path.join(CACHE, "desktop")
KEY = os.path.join(DIR, "id")
DISK = os.path.join(DIR, "disk.qcow2")
DONE = os.path.join(DIR, "setup-done")
SSH_PORT = int(os.environ.get("VM_DESKTOP_SSH_PORT", "2348"))
USER = "anna"
PASSWORD = "wachposten"  # test VM only


def ssh(cmd, timeout=600, user_cmd=False):
    argv = ["ssh", "-i", KEY, "-p", str(SSH_PORT), "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
            "fedora@127.0.0.1", f"sudo -u {USER} sh -s" if user_cmd else "sudo sh -s"]
    return subprocess.run(argv, input=cmd, capture_output=True, text=True, timeout=timeout)


def scp(src, dst):
    subprocess.run(["scp", "-q", "-i", KEY, "-P", str(SSH_PORT), "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                    src, f"fedora@127.0.0.1:{dst}"], check=True)


def wait_ssh(proc, limit=600):
    deadline = time.time() + limit
    while time.time() < deadline:
        if proc.poll() is not None:
            sys.exit("the VM stopped while booting")
        try:
            if ssh("true", timeout=15).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(3)
    sys.exit("the VM did not come up; see " + os.path.join(DIR, "serial.log"))


def newest_rpm():
    rpms = sorted(glob.glob(f"{ROOT}/target/rpm/RPMS/*/wachposten-[0-9]*.rpm"), key=os.path.getmtime)
    if not rpms:
        sys.exit("no RPM found; run packaging/build-rpm.sh first")
    return rpms[-1]


def create():
    os.makedirs(DIR, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", KEY], check=True)
    pub = open(f"{KEY}.pub").read().strip()
    seed = os.path.join(DIR, "seed")
    os.makedirs(seed)
    with open(f"{seed}/user-data", "w") as f:
        f.write("#cloud-config\n" + json.dumps({
            "users": [
                {"name": "fedora", "groups": ["wheel"], "sudo": "ALL=(ALL) NOPASSWD:ALL",
                 "ssh_authorized_keys": [pub]},
                {"name": USER, "gecos": "Anna Test", "groups": ["wheel"],
                 "plain_text_passwd": PASSWORD, "lock_passwd": False},
            ],
        }))
    with open(f"{seed}/meta-data", "w") as f:
        f.write("instance-id: wachposten-desktop\nlocal-hostname: wachposten-desktop\n")
    subprocess.run(["xorrisofs", "-quiet", "-output", os.path.join(DIR, "seed.iso"), "-volid", "cidata",
                    "-joliet", "-rock", seed], check=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", cloud_image(),
                    DISK, "40G"], check=True)


def qemu(display, gl):
    if display:
        gfx = ["-device", "virtio-vga-gl", "-display", "gtk,gl=on,zoom-to-fit=on"] if gl \
            else ["-device", "virtio-vga", "-display", "gtk,zoom-to-fit=on"]
    else:
        gfx = ["-display", "none"]
    return subprocess.Popen(
        ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "4096", "-smp", "4",
         "-name", "Wachposten test desktop", *gfx,
         "-serial", f"file:{os.path.join(DIR, 'serial.log')}",
         "-device", "virtio-tablet-pci", "-device", "virtio-keyboard-pci",
         "-drive", f"file={DISK},if=virtio",
         "-drive", f"file={os.path.join(DIR, 'seed.iso')},media=cdrom,readonly=on",
         "-nic", f"user,model=virtio,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22"])


SETUP = f"""set -e
dnf -y -q install @kde-desktop dolphin konsole kwrite glibc-langpack-de langpacks-de xdg-user-dirs python3
localectl set-locale LANG=de_DE.UTF-8
localectl set-keymap de
localectl set-x11-keymap de
# Skip the first-run wizard and log the test user in with Plasma Login Manager.
systemctl disable plasma-setup.service 2>/dev/null || true
dnf -y -q remove plasma-setup 2>/dev/null || true
rm -f /etc/plasmalogin.conf.d/99-plasma-setup.conf
mkdir -p /etc/plasmalogin.conf.d
printf '[Autologin]\\nUser={USER}\\nSession=plasma\\n' > /etc/plasmalogin.conf.d/50-wachposten-test.conf
systemctl enable plasmalogin
systemctl set-default graphical.target
"""

INSTALL = """set -e
dnf -y -q reinstall /tmp/wachposten.rpm || dnf -y -q install /tmp/wachposten.rpm
rm -f /tmp/wachposten.rpm
systemctl enable wachposten-daemon
systemctl restart wachposten-daemon
"""


def install_rpm():
    rpm = newest_rpm()
    print(f"installing {os.path.basename(rpm)}", flush=True)
    scp(rpm, "/tmp/wachposten.rpm")
    r = ssh(INSTALL, timeout=900)
    if r.returncode != 0:
        sys.exit(r.stdout[-2000:] + r.stderr[-2000:])


def copy_tests():
    tests = os.path.join(DIR, "Tests")
    shutil.rmtree(tests, ignore_errors=True)
    os.makedirs(tests)
    for name, text in TESTS.items():
        path = os.path.join(tests, name)
        with open(path, "w") as f:
            f.write(text.replace("@SIGNATURE@", TEST_SIGNATURE))
        os.chmod(path, 0o755 if name.endswith(".sh") else 0o644)
    subprocess.run(["tar", "cf", os.path.join(DIR, "tests.tar"), "-C", DIR, "Tests"], check=True)
    scp(os.path.join(DIR, "tests.tar"), "/tmp/tests.tar")
    r = ssh(f"set -e\nrm -rf /home/{USER}/Tests\ntar xf /tmp/tests.tar -C /home/{USER}\n"
            f"chown -R {USER}: /home/{USER}/Tests\nrm /tmp/tests.tar\n")
    if r.returncode != 0:
        sys.exit(r.stderr)


def setup():
    print("building the desktop VM (first run, about 15-20 minutes)", flush=True)
    if not os.path.exists(DISK):
        create()
    proc = qemu(display=False, gl=False)
    try:
        wait_ssh(proc)
        print("installing KDE Plasma and German language support", flush=True)
        r = ssh(SETUP, timeout=3600)
        if r.returncode != 0:
            sys.exit(r.stdout[-2000:] + r.stderr[-2000:])
        install_rpm()
        copy_tests()
        ssh("systemctl poweroff", timeout=30)
        proc.wait(timeout=120)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
    open(DONE, "w").close()


def main():
    args = sys.argv[1:]
    unknown = [a for a in args if a not in ("--update", "--reset", "--no-gl")]
    if unknown:
        sys.exit(__doc__)
    if "--reset" in args and os.path.isdir(DIR):
        shutil.rmtree(DIR)
    if not os.path.exists(DONE):
        setup()  # an unfinished setup goes on with the same disk; every step can run again
    proc = qemu(display=True, gl="--no-gl" not in args)
    if "--update" in args:
        wait_ssh(proc)
        install_rpm()
        copy_tests()
        print("updated; log out and in again in the VM to restart the agent", flush=True)
    print(f"VM is running. Close its window to stop it. ssh: ssh -i {KEY} -p {SSH_PORT} fedora@127.0.0.1",
          flush=True)
    proc.wait()


# Scripts put into ~/Tests in the VM. Each one says what should happen.
TESTS = {
    "LIESMICH.txt": """Wachposten tests. Open Konsole here (right click in Dolphin: "Open Terminal Here")
and run the scripts one by one. Each prints what Wachposten should do.

1-autostart-harmless.sh   an ordinary autostart entry      -> short notice only
2-autostart-evil.sh       autostart runs a file from /tmp  -> popup
3-known-malware.sh        starts a test "malware" in /tmp  -> start refused, notice
4-normal-work.sh          copy, unpack, rename 200 files   -> nothing at all
5-ransomware.sh           encrypts ~/Dokumente/wp-test     -> process stopped, popup
6-decoy.sh                changes a decoy file             -> process stopped, popup at once
                          (first switch on decoys in the window under Settings)
cleanup.sh                removes everything the tests made

The program window: "Wachposten" in the start menu, or the shield in the tray.
Right click a file in Dolphin -> "Check with Wachposten" / "Mit Wachposten pruefen".
""",
    "1-autostart-harmless.sh": """#!/bin/sh
mkdir -p ~/.config/autostart
printf '[Desktop Entry]\\nType=Application\\nName=Notizen\\nExec=/usr/bin/kwrite\\n' > ~/.config/autostart/wp-harmless.desktop
echo "Expected: a short notice only (no popup with buttons). It shows up in the window's history."
""",
    "2-autostart-evil.sh": """#!/bin/sh
mkdir -p ~/.config/autostart
printf '[Desktop Entry]\\nType=Application\\nName=Update\\nExec=/tmp/.x/run\\nNoDisplay=true\\n' > ~/.config/autostart/wp-evil.desktop
echo "Expected: a popup. 'Remove' deletes the entry again."
""",
    "3-known-malware.sh": """#!/bin/sh
printf '#!/bin/sh\\necho @SIGNATURE@\\n' > /tmp/wp-evil.sh
chmod +x /tmp/wp-evil.sh
/tmp/wp-evil.sh
echo "exit code $? (expected: 126, the start was refused, and a notice)"
""",
    "4-normal-work.sh": """#!/bin/sh
set -e
d=$(xdg-user-dir DOCUMENTS)/wp-normal
mkdir -p "$d"
python3 - "$d" <<'EOF'
import os, sys
d = sys.argv[1]
for i in range(100):
    open(f"{d}/brief{i:03}.txt", "w").write("Hallo, viele Gruesse. " * 60)
    open(f"{d}/foto{i:03}.jpg", "wb").write(b"\\xff\\xd8\\xff\\xe0" + os.urandom(8000))
EOF
cp -r "$d" "$d-kopie"
tar cf /tmp/wp.tar -C "$d" . && mkdir -p "$d-entpackt" && tar xf /tmp/wp.tar -C "$d-entpackt"
for f in "$d-kopie"/*.txt; do mv "$f" "$f.bak"; done
echo "Done. Expected: no popup and no notice."
""",
    "5-ransomware.sh": """#!/bin/sh
d=$(xdg-user-dir DOCUMENTS)/wp-test
mkdir -p "$d"
python3 - "$d" <<'EOF'
import sys
d = sys.argv[1]
for i in range(100):
    open(f"{d}/brief{i:03}.txt", "w").write("Hallo, viele Gruesse. " * 60)
    open(f"{d}/rechnung{i:03}.pdf", "wb").write(b"%PDF-1.7\\n" + b"1 0 obj << >> endobj\\n" * 100)
EOF
cat > ~/Tests/encrypt.py <<'EOF'
import os, sys, time
d = sys.argv[1]
for n in sorted(os.listdir(d)):
    p = os.path.join(d, n)
    data = open(p, "rb").read()
    with open(p + ".locked", "wb") as f:
        f.write(os.urandom(max(len(data), 1024)))
    os.unlink(p)
    time.sleep(0.02)
time.sleep(600)
EOF
# Detached from this shell, so only the script is stopped.
setsid -f python3 ~/Tests/encrypt.py "$d"
echo "Started. Expected within seconds: a popup, the script is stopped."
echo "Then: ls $d | grep -c locked   (expected: well below 200)"
""",
    "6-decoy.sh": """#!/bin/sh
f=$(ls "$(xdg-user-dir DOCUMENTS)"/*wachposten-koeder* "$(xdg-user-dir DOCUMENTS)"/.*wachposten-koeder* 2>/dev/null | head -1)
if [ -z "$f" ]; then
    echo "No decoy found. Switch decoys on in the window under Settings first."
    exit 1
fi
cat > ~/Tests/decoy.py <<'EOF'
import sys, time
with open(sys.argv[1], "r+b") as f:
    f.write(b"X")
time.sleep(600)
EOF
# A script file of its own, so "End it" quarantines the script and not python3.
setsid -f python3 ~/Tests/decoy.py "$f"
echo "Changed $f. Expected: a popup at once, the program is stopped."
""",
    "cleanup.sh": """#!/bin/sh
pkill -f 'Tests/(encrypt|decoy).py' 2>/dev/null
docs=$(xdg-user-dir DOCUMENTS)
rm -rf "$docs/wp-test" "$docs/wp-normal" "$docs/wp-normal-kopie" "$docs/wp-normal-entpackt" \\
    ~/.config/autostart/wp-harmless.desktop ~/.config/autostart/wp-evil.desktop \\
    /tmp/wp-evil.sh /tmp/wp.tar ~/Tests/encrypt.py ~/Tests/decoy.py
echo "Cleaned up. Open questions in the window can be dismissed with 'Allow' or 'Remove'."
""",
}

if __name__ == "__main__":
    main()
