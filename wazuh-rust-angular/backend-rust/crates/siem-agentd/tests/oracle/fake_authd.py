#!/usr/bin/env python3
"""A stand-in for wazuh-authd (port 1515 protocol) for the agentd oracle
test: it logs each enrollment request line and replies with a fixed key
(mode "ok") or with "ERROR: Invalid password" (mode "error").

usage: fake_authd.py <port> <cert> <key> <ok|error> <key line> <log file>
"""
import socket
import ssl
import sys

port, cert, keyfile, mode, keyline, logpath = sys.argv[1:7]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, keyfile)
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(port)))
srv.listen(5)
log = open(logpath, "w")
while True:
    conn, _ = srv.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        data = b""
        while not data.endswith(b"\n"):
            chunk = tls.recv(70000)
            if not chunk:
                break
            data += chunk
        log.write("REQUEST %r\n" % data)
        log.flush()
        if mode == "ok":
            tls.sendall(b"OSSEC K:'%s'\n\n" % keyline.encode())
        else:
            tls.sendall(b"ERROR: Invalid password\n\n")
        tls.close()
    except Exception as e:  # handshake failures etc.
        log.write("FAIL %s\n" % type(e).__name__)
        log.flush()
        conn.close()
