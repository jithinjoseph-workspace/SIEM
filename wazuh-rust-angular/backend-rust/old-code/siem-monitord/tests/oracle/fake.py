#!/usr/bin/env python3
"""Fake wazuh-db (queue/db/wdb), analysisd queue (queue/sockets/queue) and
authd (queue/sockets/auth) for the monitord oracle. Run in a Wazuh home:
  fake.py <script.json>
script: {"wdb": [[prefix, [reply, ...]], ...], "auth": [reply, ...]}
Replies may contain {now-N}. Each prefix's replies are used in order (the
last one repeats). Records go to out/wdb.log, out/queue.log, out/auth.log."""
import json, os, socket, struct, sys, threading, time

script = json.load(open(sys.argv[1]))
os.makedirs('out', exist_ok=True)
os.makedirs('queue/db', exist_ok=True)
os.makedirs('queue/sockets', exist_ok=True)
lock = threading.Lock()
used = {}


def rec(name, s):
    with lock, open('out/' + name, 'a') as f:
        f.write(s + '\n')


def fill(r):
    now = int(time.time())
    while '{now-' in r:
        i = r.index('{now-')
        j = r.index('}', i)
        r = r[:i] + str(now - int(r[i + 5:j])) + r[j + 1:]
    return r


def wdb_reply(q):
    for k, (prefix, replies) in enumerate(script.get('wdb', [])):
        if q.startswith(prefix):
            n = used.get(k, 0)
            used[k] = n + 1
            return fill(replies[min(n, len(replies) - 1)])
    return 'err unknown query'


def recv_frame(c):
    h = b''
    while len(h) < 4:
        x = c.recv(4 - len(h))
        if not x:
            return None
        h += x
    n = struct.unpack('<I', h)[0]
    b = b''
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x:
            return None
        b += x
    return b


def send_frame(c, b):
    c.sendall(struct.pack('<I', len(b)) + b)


def serve_stream(path, handler):
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(16)

    def conn(c):
        while True:
            q = recv_frame(c)
            if q is None:
                break
            send_frame(c, handler(q))
        c.close()
    while True:
        c, _ = s.accept()
        threading.Thread(target=conn, args=(c,), daemon=True).start()


def wdb(q):
    q = q.split(b'\0')[0].decode()
    rec('wdb.log', q)
    return wdb_reply(q).encode() + b'\0'


auth_n = [0]


def auth(q):
    rec('auth.log', q.decode())
    r = script.get('auth', ['{"error":0}'])
    a = r[min(auth_n[0], len(r) - 1)]
    auth_n[0] += 1
    return a.encode()


def queue():
    p = 'queue/sockets/queue'
    if os.path.exists(p):
        os.unlink(p)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(p)
    while True:
        m = s.recv(70000)
        rec('queue.log', repr(m))


for t in (lambda: serve_stream('queue/db/wdb', wdb), lambda: serve_stream('queue/sockets/auth', auth), queue):
    threading.Thread(target=t, daemon=True).start()
open('out/ready', 'w').close()
while True:
    time.sleep(3600)
