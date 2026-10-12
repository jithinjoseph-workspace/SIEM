#!/usr/bin/env python3
"""Send one request to the logcollector socket (4-byte little-endian
length framing) and print the answer.

usage: lccom.py <socket path> <request>
"""
import socket
import struct
import sys

path, req = sys.argv[1], sys.argv[2].encode()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall(struct.pack("<I", len(req)) + req)
hdr = b""
while len(hdr) < 4:
    c = s.recv(4 - len(hdr))
    if not c:
        break
    hdr += c
n = struct.unpack("<I", hdr)[0] if len(hdr) == 4 else 0
body = b""
while len(body) < n:
    c = s.recv(n - len(body))
    if not c:
        break
    body += c
print(sys.argv[2] + " => " + body.decode(errors="replace"))
