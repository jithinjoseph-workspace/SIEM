#!/usr/bin/env python3
"""UDP syslog receivers: udp_recv.py <out dir> <port>... ; one file per port, one line per datagram."""
import os, select, socket, sys

out = sys.argv[1]
socks = {}
for p in map(int, sys.argv[2:]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", p))
    socks[s] = p
open(os.path.join(out, "udp_ready"), "w").close()
while True:
    r, _, _ = select.select(list(socks), [], [])
    for s in r:
        d = s.recv(70000)
        with open(os.path.join(out, "udp-%d.log" % socks[s]), "ab") as f:
            f.write(d.replace(b"\n", b"\\n") + b"\n")
