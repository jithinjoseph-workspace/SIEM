#!/usr/bin/env python3
"""Fake HTTP endpoint + analysisd queue for the integrations oracle.
  fake_http.py <port> <script.json> <home>
script: {"routes": [[path-prefix, status, body], ...]}  (first match; default 200 {"ok": true})
Writes <home>/out/http.log (one JSON per request) and <home>/out/queue.log."""
import json, os, socket, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port, script, home = int(sys.argv[1]), json.load(open(sys.argv[2])), sys.argv[3]
out = os.path.join(home, "out")
KEEP = ["content-type", "accept-charset", "accept", "authorization", "accept-encoding"]
lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    def handle_one(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode("latin-1") if n else ""
        hdr = {k: v for k, v in ((k.lower(), v) for k, v in self.headers.items()) if k in KEEP}
        # the VirusTotal script sets its own User-Agent; others leave the library's
        ua = self.headers.get("user-agent", "")
        if "VirusTotal" in ua:
            hdr["user-agent"] = ua
        with lock, open(os.path.join(out, "http.log"), "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "headers": dict(sorted(hdr.items())), "body": body}) + "\n")
        status, rbody = 200, '{"ok": true}'
        for prefix, st, b in script.get("routes", []):
            if self.path.startswith(prefix):
                status, rbody = st, b
                break
        data = rbody.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = handle_one

    def log_message(self, *a):
        pass


def queue():
    p = os.path.join(home, "queue", "sockets", "queue")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if os.path.exists(p):
        os.unlink(p)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(p)
    while True:
        m = s.recv(200000)
        with lock, open(os.path.join(out, "queue.log"), "a") as f:
            f.write(m.decode("latin-1") + "\n")


threading.Thread(target=queue, daemon=True).start()
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
open(os.path.join(out, "ready"), "w").close()
srv.serve_forever()
