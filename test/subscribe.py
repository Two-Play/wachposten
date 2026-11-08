#!/usr/bin/env python3
"""Subscribes to the daemon like an agent and prints every pushed line (used by test/vm.py)."""
import socket
import sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1] if len(sys.argv) > 1 else "/run/wachposten/daemon.sock")
s.sendall(b'{"request":"subscribe"}\n')
buf = b""
while True:
    data = s.recv(65536)
    if not data:
        break
    buf += data
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        print(line.decode(), flush=True)
