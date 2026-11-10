#!/usr/bin/env python3
"""Sends requests to queue/sockets/agentless (4-byte little-endian framing); one reply per line."""
import socket, struct, sys
for req in [b'getconfig agentless', b'getconfig other', b'getconfig', b'hello']:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect('queue/sockets/agentless')
        s.sendall(struct.pack('<I', len(req)) + req)
        n = struct.unpack('<I', s.recv(4))[0]
        b = b''
        while len(b) < n:
            b += s.recv(n - len(b))
        print(req.decode(), '=>', b.decode())
    except Exception as e:
        print(req.decode(), '=> ERROR', e)
