#!/usr/bin/env python3
"""Fake analysisd queue: binds queue/sockets/queue in the cwd and writes one
line per datagram (newlines escaped) to out/queue.log."""
import os, socket
os.makedirs('queue/sockets', exist_ok=True)
p = 'queue/sockets/queue'
if os.path.exists(p):
    os.unlink(p)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(p)
os.chmod(p, 0o777)
open('out/queue_ready', 'w').close()
while True:
    d = s.recv(70000)
    with open('out/queue.log', 'ab') as f:
        f.write(d.replace(b'\\', b'\\\\').replace(b'\n', b'\\n') + b'\n')
