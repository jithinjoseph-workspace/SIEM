#!/usr/bin/env python3
"""Fake SMTP server on 127.0.0.1:25 for the maild oracle (run as root).
  fake_smtp.py <script.json> <out dir>
script: {"rcpt_fail": [addr...], "helo_reply": "...", "data_reply": "...", "end_reply": "..."}
Every session's client bytes go to <out>/smtp.log (Date: headers masked)."""
import json, os, re, socket, sys, threading, time

script = json.load(open(sys.argv[1])).get("smtp", {})
out = sys.argv[2]
lock = threading.Lock()
n = [0]


def session(c, idx):
    rec = bytearray()
    buf = bytearray()
    data = False

    def reply(s):
        # a list is sent as separate packets (two banners from a scanning proxy)
        for part in (s if isinstance(s, list) else [s]):
            c.sendall(part.encode())
            if isinstance(s, list):
                time.sleep(0.3)

    reply(script.get("banner", "220 fake.local ESMTP\r\n"))
    try:
        while True:
            x = c.recv(65536)
            if not x:
                break
            rec += x
            buf += x
            while True:
                if data:
                    i = buf.find(b"\r\n.\r\n")
                    if i < 0:
                        break
                    del buf[:i + 5]
                    data = False
                    reply(script.get("end_reply", "250 2.0.0 queued\r\n"))
                    continue
                i = buf.find(b"\r\n")
                if i < 0:
                    break
                line = bytes(buf[:i]).decode("latin-1")
                del buf[:i + 2]
                u = line.upper()
                if u.startswith("HELO") or u.startswith("EHLO"):
                    reply(script.get("helo_reply", "250 fake.local\r\n"))
                elif u.startswith("MAIL FROM"):
                    reply(script.get("from_reply", "250 2.1.0 ok\r\n"))
                elif u.startswith("RCPT TO"):
                    addr = line[line.find("<") + 1:line.rfind(">")]
                    reply("550 5.1.1 no such user\r\n" if addr in script.get("rcpt_fail", []) else "250 2.1.5 ok\r\n")
                elif u == "DATA":
                    reply(script.get("data_reply", "354 go ahead\r\n"))
                    data = not script.get("data_reply", "354").startswith("5")
                elif u == "QUIT":
                    reply("221 bye\r\n")
                else:
                    reply("500 what\r\n")
    except OSError:
        pass
    c.close()
    text = re.sub(rb"Date: [^\r\n]*", b"Date: <date>", bytes(rec))
    with open(os.path.join(out, "smtp-%03d.log" % idx), "wb") as f:
        f.write(text)


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 25))
s.listen(16)
open(os.path.join(out, "smtp_ready"), "w").close()
while True:
    c, _ = s.accept()
    n[0] += 1
    threading.Thread(target=session, args=(c, n[0]), daemon=True).start()
