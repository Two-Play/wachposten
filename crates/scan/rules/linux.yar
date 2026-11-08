// Wachposten built-in rules for Linux desktops.
// License: GPL-3.0-or-later, like Wachposten. Written for Wachposten, not copied from other sets.
// Rules are kept narrow: every rule needs several independent indicators.

rule Wachposten_Test_Signature
{
    meta:
        description = "Harmless test file for Wachposten (like EICAR)"
        severity = "test"
    strings:
        $a = "WACHPOSTEN-TEST-SIGNATURE-7f3a9c2e-NOT-MALWARE"
    condition:
        $a
}

rule Linux_Miner_XMRig
{
    meta:
        description = "XMRig cryptocurrency miner or a dropper configuring it"
        severity = "high"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "xmrig" ascii nocase
        $s4 = "--donate-level" ascii
        $s5 = "randomx" ascii nocase
        $s6 = "\"donate-level\"" ascii
        $s7 = "cryptonight" ascii nocase
    condition:
        filesize < 20MB and
        ($s3 and 2 of ($s1, $s2, $s4, $s5, $s6, $s7))
}

rule Linux_Miner_Competitor_Killer
{
    meta:
        description = "Cryptojacking script that kills competing miners (Kinsing/TeamTNT style)"
        severity = "high"
    strings:
        $k1 = "kdevtmpfsi" ascii
        $k2 = "kinsing" ascii
        $k3 = "xmrig" ascii
        $k4 = "kthreaddi" ascii
        $k5 = "sysupdate" ascii
        $k6 = "networkservice" ascii
        $kill1 = "pkill" ascii
        $kill2 = "killall" ascii
        $kill3 = "kill -9" ascii
    condition:
        filesize < 1MB and 3 of ($k*) and any of ($kill*)
}

rule Linux_ReverseShell_Script
{
    meta:
        description = "Script that opens a reverse shell"
        severity = "high"
    strings:
        $bash1 = /bash\s+-i\s*>&\s*\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]+/ ascii
        $bash2 = /\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]+\s+0>&1/ ascii
        $py_sock = "socket.socket(" ascii
        $py_connect = ".connect((" ascii
        $py_dup = "os.dup2(" ascii
        $py_pty = "pty.spawn(" ascii
        $nc = /\bnc(at)?\s+(-[a-z]*\s+)*[0-9a-zA-Z.\-]+\s+[0-9]+\s+-e\s+\/bin\/(ba)?sh/ ascii
        $mkfifo = /mkfifo\s+\/tmp\/[a-z0-9_.]+;\s*(nc|cat)\b/ ascii
    condition:
        filesize < 512KB and
        (any of ($bash*) or $nc or $mkfifo or
         ($py_sock and $py_connect and $py_dup and $py_pty))
}

rule Linux_LDPreload_Rootkit
{
    meta:
        description = "Shared library that installs itself via /etc/ld.so.preload and hooks directory listing"
        severity = "high"
    strings:
        $preload = "/etc/ld.so.preload" ascii
        $readdir = "readdir" ascii
        $dlsym = "dlsym" ascii
        $hide1 = "process_to_filter" ascii
        $hide2 = "/proc/self/fd/%d" ascii
        $hide3 = "/proc/%s/stat" ascii
        $hide4 = "fopen64" ascii
    condition:
        uint32(0) == 0x464c457f and uint16(16) == 3 and filesize < 2MB and
        $preload and $readdir and $dlsym and 1 of ($hide*)
}

rule Linux_Persistence_Installer_Script
{
    meta:
        description = "Shell script that downloads a payload, hides it and installs it for autostart"
        severity = "high"
    strings:
        $sh = "#!" ascii
        $dl1 = "curl " ascii
        $dl2 = "wget " ascii
        $p1 = "crontab -" ascii
        $p2 = ".config/autostart" ascii
        $p3 = "systemctl --user enable" ascii
        $p4 = ">> ~/.bashrc" ascii
        $p5 = ">>~/.bashrc" ascii
        $p6 = "/etc/ld.so.preload" ascii
        $p7 = ".ssh/authorized_keys" ascii
        $h1 = "nohup " ascii
        $h2 = "/dev/shm/" ascii
        $h3 = "history -c" ascii
        $h4 = "chattr +i" ascii
        $h5 = "> /dev/null 2>&1 &" ascii
        $h6 = "unset HISTFILE" ascii
    condition:
        $sh at 0 and filesize < 1MB and any of ($dl*) and any of ($p*) and 2 of ($h*)
}

rule Linux_Botnet_Gafgyt_Mirai
{
    meta:
        description = "IoT/Linux botnet client (Gafgyt/Mirai family) command strings"
        severity = "high"
    strings:
        $c1 = "KILLATTK" ascii
        $c2 = "LOLNOGTFO" ascii
        $c3 = "HTTPFLOOD" ascii
        $c4 = "UDPRAW" ascii
        $c5 = "STDHEX" ascii
        $c6 = "GETLOCALIP" ascii
        $c7 = "/bin/busybox" ascii
        $c8 = "POST /cdn-cgi/" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and 3 of them
}

rule Web_PHP_Webshell_Eval
{
    meta:
        description = "PHP web shell that runs code sent in a request"
        severity = "high"
    strings:
        $php = "<?php" ascii nocase
        $e1 = /(eval|assert|system|passthru|shell_exec)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $e2 = /(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ ascii nocase
    condition:
        filesize < 1MB and $php and any of ($e*)
}
