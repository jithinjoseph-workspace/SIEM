# TLS / HTTPS Encryption Setup — NDR Platform

## What Was Done

The NDR platform previously communicated entirely over plain HTTP, meaning
all traffic between the browser, Nginx, and remote sensors was unencrypted.

This change adds **end-to-end TLS encryption (TLSv1.3, AES-256-GCM)** to the
platform. All HTTP traffic is now permanently redirected to HTTPS. The
WebSocket connection used for live alerts automatically upgrades to `wss://`.
The backend CORS policy is updated to match the new HTTPS origin.

**Verified result:**
```
Protocol : TLSv1.3
Cipher   : TLS_AES_256_GCM_SHA384
Subject  : CN=10.0.2.15
Redirect : http://10.0.2.15:3080 → 301 → https://10.0.2.15:3000/
```

---

## Files Changed

### 1. `config/nginx/nginx.conf`
**What changed:**
- Added Docker's embedded DNS resolver (`127.0.0.11`) so Nginx can resolve
  container names dynamically — required for `nginx -s reload` to work.
- Split the single HTTP server block (port 80) into two blocks:
  - **Port 80** — issues a `301 Moved Permanently` redirect to
    `https://$host:3000$request_uri`
  - **Port 443 ssl** — the new HTTPS listener with:
    - TLS certificate paths (`/etc/nginx/ssl/ndr.crt` and `ndr.key`)
    - `ssl_protocols TLSv1.2 TLSv1.3`
    - `ssl_ciphers HIGH:!aNULL:!MD5`
    - All original proxy rules (API, WebSocket `/ws`, health check) preserved

---

### 2. `docker-compose.yml`  — nginx service
**What changed:**
- Port mapping updated from `3000:80` to:
  - `3000:443` — HTTPS primary entry point
  - `3080:80`  — HTTP redirect (port 3001 was already used by the NDR Agent)
- Added SSL certificate volume mount:
  ```yaml
  - ${INSTALL_DIR}/config/nginx/ssl:/etc/nginx/ssl:ro
  ```

---

### 3. `.env`
**What changed:**
```diff
- CORS_ORIGIN=http://10.0.2.15:3000
+ CORS_ORIGIN=https://10.0.2.15:3000
```
The Rust backend reads this value and uses it as the exact allowed origin in
CORS response headers. Without this change the browser's HTTPS origin would
be rejected by the backend.

---

### 4. `ndr-ui/src/services/websocket/websocket.ts`
**What changed:**
```diff
- const wsUrl = `ws://localhost:3000/ws?token=${token}`;
+ const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
+ const wsUrl = `${wsProtocol}//${location.host}/ws?token=${token}`;
```
The WebSocket URL is now derived dynamically from the page's own protocol.
If the UI loads over `https:`, it connects via `wss:` — preventing the
browser mixed-content block that would otherwise kill live alerts.

---

### 5. `install.sh`
**What changed (3 places):**

**a) TLS certificate auto-generation** (inserted before `docker compose up`):
```bash
SSL_DIR="$INSTALL_DIR/config/nginx/ssl"
if [ ! -f "$SSL_DIR/ndr.crt" ] || [ ! -f "$SSL_DIR/ndr.key" ]; then
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
        -keyout "$SSL_DIR/ndr.key" \
        -out    "$SSL_DIR/ndr.crt" \
        -subj   "/CN=$HOST_IP" \
        -addext "subjectAltName=IP:$HOST_IP,IP:127.0.0.1,DNS:localhost"
    chmod 600 "$SSL_DIR/ndr.key"
fi
```
- Skipped automatically if a cert already exists (admin can place a CA-signed
  cert before running install and it will never be overwritten).
- SAN covers: the host IP, `127.0.0.1`, and `localhost` — so both
  `https://10.0.2.15:3000` and `https://localhost:3000` work without a
  hostname mismatch warning.

**b) Angular dev-server proxy** (`proxy.conf.json` written by install):
```diff
- "target": "http://localhost:3000"  →  "target": "https://localhost:3000"
- "target": "ws://localhost:3000"    →  "target": "wss://localhost:3000"
```

**c) Completion banner:**
```diff
- API Gateway     http://${HOST_IP}:3000
+ API Gateway     https://${HOST_IP}:3000
```

---

### 6. `start.sh`
**What changed:**
```diff
- echo "   API:    http://localhost:3000"
+ echo "   API:    https://localhost:3000"
```
Cosmetic — startup banner now correctly reflects the HTTPS endpoint.

---

### 7. `config/nginx/ssl/` *(new directory — not tracked by git)*
**What was created:**
- `ndr.crt` — self-signed X.509 certificate (valid 2 years)
- `ndr.key` — RSA-2048 private key (`chmod 600`)

> ⚠️ This directory contains the private key. It must never be committed
> to version control. Ensure `config/nginx/ssl/` is in `.gitignore`.

---

## Port Map After This Change

| Host Port | Container Port | Purpose |
|-----------|---------------|---------|
| `3000`    | `443`         | **HTTPS** — primary browser entry point |
| `3080`    | `80`          | HTTP → issues 301 redirect to HTTPS |
| `3001`    | —             | NDR Agent internal HTTP server (unchanged) |

---

## For New Deployments

Running `./install.sh` on a fresh machine is fully self-sufficient.
The script will automatically generate the TLS certificate before starting
Docker, so no manual `openssl` command is needed.

For remote sensors, pass HTTPS when deploying:
```bash
./scripts/install-sensor.sh \
  --cloud-url https://10.0.2.15:3000 \
  --tenant-id <tenant> \
  --api-key <key>
```

For existing deployed sensors, update `/etc/ndr/sensor.conf` on each sensor:
```diff
- CLOUD_URL=http://10.0.2.15:3000
+ CLOUD_URL=https://10.0.2.15:3000
```

---

## Replacing the Self-Signed Certificate with a CA-Signed One

Place your CA-signed files at:
```
config/nginx/ssl/ndr.crt   ← full chain certificate
config/nginx/ssl/ndr.key   ← private key (chmod 600)
```
Then reload Nginx:
```bash
sudo docker exec ndr-nginx nginx -s reload
```
The install script skips cert generation if these files already exist,
so a CA-signed cert placed before running `./install.sh` is always preserved.

---

## Verification Commands

```bash
# 1. Docker port mapping
sudo docker ps --filter name=ndr-nginx --format "{{.Ports}}"

# 2. TLS handshake (expect TLSv1.3 + AES-256-GCM)
echo | openssl s_client -connect 10.0.2.15:3000 2>/dev/null \
  | grep -E "Protocol|Cipher|subject"

# 3. HTTP redirect (expect 301 → https://10.0.2.15:3000/)
curl -sI http://10.0.2.15:3080 | grep -E "HTTP|Location"

# 4. Certificate SAN (expect IP:10.0.2.15, IP:127.0.0.1, DNS:localhost)
echo | openssl s_client -connect 10.0.2.15:3000 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative"
```

---

*Proma Alpha NDR Platform — TLS rollout completed 2026-07-14*
