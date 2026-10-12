#!/usr/bin/env python3
"""A unix datagram socket that records every message it receives
(the agentd queue or a <socket> target in the logcollector oracle test).

usage: sink.py <socket path> <log file>
"""
import os
import socket
import sys

path, logpath = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
os.chmod(path, 0o777)
with open(logpath, "w") as log:
    while True:
        data = s.recv(70000)
        log.write(repr(data)[2:-1] + "\n")
        log.flush()
