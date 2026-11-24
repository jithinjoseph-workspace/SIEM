#!/usr/bin/env python3
"""Deploy webhook — receives an authenticated POST (from CI, right after a
release.sh push) and touches the same .update-requested flag file the
in-app "Apply Update" button already writes. All actual deploy/rollback
logic lives in update-watcher.sh, which already polls for this flag —
this script's only job is deciding whether a request is allowed to set it.
"""
import http.server
import os
import secrets
import sys

SECRET = os.environ.get("DEPLOY_WEBHOOK_SECRET", "")
FLAG    = os.environ.get("UPDATE_FLAG_PATH", "/opt/ndr/scripts/.update-requested")
PORT    = int(os.environ.get("DEPLOY_WEBHOOK_PORT", "8099"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/deploy-webhook":
            self.send_response(404)
            self.end_headers()
            return

        provided = self.headers.get("X-Deploy-Secret", "")
        # Constant-time comparison — a naive `==` here would leak the secret
        # one byte at a time via response-timing, same class of bug as a
        # plain string-equality password check.
        if not SECRET or not secrets.compare_digest(provided, SECRET):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return

        try:
            with open(FLAG, "w") as f:
                f.write("webhook\n")
        except OSError as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"error":"{e}"}}'.encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"update triggered"}')

    def log_message(self, fmt, *args):
        print(f"[deploy-webhook] {self.address_string()} - {fmt % args}", file=sys.stderr)


if __name__ == "__main__":
    if not SECRET:
        print("DEPLOY_WEBHOOK_SECRET not set — refusing to start", file=sys.stderr)
        raise SystemExit(1)
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[deploy-webhook] listening on :{PORT}, flag={FLAG}")
    server.serve_forever()
