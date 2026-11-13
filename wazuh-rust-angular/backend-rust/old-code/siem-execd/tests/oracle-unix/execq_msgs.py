#!/usr/bin/env python3
"""Sends analysisd-style AR messages to execd's queue: execq_msgs.py <queue/alerts/execq>."""
import json, socket, sys, time

q = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)


def ar(cmd, srcip, extra=None):
    m = {"version": 1, "origin": {"name": "node01", "module": "wazuh-analysisd"}, "command": cmd,
         "parameters": {"extra_args": extra or [], "alert": {"timestamp": "2026-10-17T10:00:00.000+0000", "rule": {"level": 10, "id": "5712"}, "data": {"srcip": srcip}}}}
    return json.dumps(m, separators=(",", ":"))


msgs = [
    ar("reckeys3", "1.2.3.4"),
    ar("reckeys3", "1.2.3.4"),          # same key while blocked: abort
    ar("reckeys3", "5.6.7.8", ["-x"]),
    ar("rec0", "9.9.9.9"),              # timeout 0: no delete
    "{not json",
    json.dumps({"version": 1, "command": 5}),
    ar("unknowncmd", "1.1.1.1"),
    ar("noscript5", "2.2.2.2"),         # the script does not exist
]
for m in msgs:
    s.sendto(m.encode() + b"\0", q)
    time.sleep(0.4)
