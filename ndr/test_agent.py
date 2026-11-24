#!/usr/bin/env python3
"""NDR Sensor Agent v2 — monitors and restarts all services"""
import os, time, subprocess, threading, requests, json, hashlib
from datetime import datetime

config = {}
with open('/etc/ndr/sensor.conf') as f:
    for line in f:
        if '=' in line and not line.startswith('#'):
            k, v = line.strip().split('=', 1)
            config[k] = v

CLOUD_URL = config.get('CLOUD_URL', '').rstrip('/')
TENANT_ID = config.get('TENANT_ID', '')
API_KEY   = config.get('API_KEY', '')
IFACE     = config.get('IFACE', 'eth0')

# Prevents check_and_restart from undoing an intentional stop command
MANUALLY_STOPPED = False

def derive_arkime_pass(key):
    return hashlib.sha256(key.encode())\
        .hexdigest()[:16]

ARKIME_PASS = derive_arkime_pass(API_KEY)

def is_running(pattern):
    return subprocess.run(
        ['pgrep', '-f', pattern],
        capture_output=True
    ).returncode == 0

def is_port_open(port):
    """Check if a local port is accepting connections"""
    import socket
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

def is_capture_running():
    return is_running('arkime/bin/capture')

def start_zeek():
    try:
        subprocess.run(['pkill', '-9', '-f', 'zeek'],
            capture_output=True)
        time.sleep(2)
        subprocess.Popen(
            ["/opt/zeek/bin/zeek", "-i", IFACE,
             "local",
             "Log::default_logdir=/var/log/ndr/zeek"],
            stdout=open("/tmp/zeek.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Zeek started")
        return True
    except Exception as e:
        print(f"[NDR] Zeek start failed: {e}")
        return False

def start_suricata():
    try:
        subprocess.run(['pkill', '-9', '-f', 'suricata'],
            capture_output=True)
        time.sleep(2)
        for pid in ['/tmp/suricata.pid',
                    '/var/run/suricata.pid',
                    '/run/suricata.pid',
                    '/var/run/suricata/suricata.pid']:
            try: os.remove(pid)
            except: pass

        subprocess.Popen(
            ["suricata",
             "-c", "/etc/suricata/suricata.yaml",
             "-i", IFACE,
             "-l", "/var/log/ndr/suricata",
             "-D",
             "--pidfile", "/tmp/suricata.pid",
             "--set", "detect.profile=low",
             "--set", "max-pending-packets=128"],
            stdout=open("/tmp/suricata.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Suricata started")
        return True
    except Exception as e:
        print(f"[NDR] Suricata start failed: {e}")
        return False

def start_vector():
    try:
        subprocess.run(['systemctl', 'start',
            'ndr-vector'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Vector started")
        return True
    except Exception as e:
        print(f"[NDR] Vector start failed: {e}")
        return False

def start_capture():
    try:
        subprocess.run(['systemctl', 'start',
            'arkime-capture'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Arkime capture started")
        return True
    except Exception as e:
        print(f"[NDR] Arkime capture failed: {e}")
        return False

def discover_subnets():
    """Read network interface CIDRs and write to ipam.log so the engine
    can build per-tenant subnet maps and detect IP conflicts."""
    ipam_log = "/var/log/ndr/zeek/ipam.log"
    try:
        import ipaddress as _ipaddress
        out = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True).stdout
        now = time.time()
        iface = None
        entries = []
        for line in out.splitlines():
            m = re.match(r'^\d+:\s+(\S+):', line)
            if m:
                iface = m.group(1).rstrip(':')
                continue
            m = re.match(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m and iface:
                ip, prefix = m.group(1), int(m.group(2))
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                network = _ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                cidr = str(network)
                gateway = str(network.network_address + 1)
                entries.append(json.dumps({
                    "ts": now, "log_type": "ipam",
                    "interface": iface, "cidr": cidr,
                    "local_ip": ip, "gateway": gateway
                }))
        if entries:
            os.makedirs(os.path.dirname(ipam_log), exist_ok=True)
            with open(ipam_log, 'a') as f:
                for e in entries:
                    f.write(e + '\n')
        print(f"[NDR] Subnet discovery: {len(entries)} subnets written")
    except Exception as e:
        print(f"[NDR] discover_subnets error: {e}")

def arp_scan(iface):
    """ARP scan the local subnet on startup.
    Only real devices reply to ARP — no ghost placeholders possible.
    Zeek captures the ARP replies via ndr-arp.zeek and enriches assets."""
    try:
        subprocess.run(
            ['sudo', 'arp-scan', f'--interface={iface}', '--localnet', '--quiet'],
            capture_output=True, timeout=60
        )
        print("[NDR] ✅ ARP scan complete")
    except Exception as e:
        print(f"[NDR] ARP scan error: {e}")

def arp_probe_unknown():
    """Background loop: every 5 min, ARP-probe internal IPs seen in traffic
    that have no ARP entry — so Zeek captures the reply and enriches the asset.
    Uses arping (Layer 2) instead of ping to avoid creating ghost placeholders."""
    import ipaddress
    conn_log = "/var/log/ndr/zeek/conn.log"
    while True:
        time.sleep(300)
        try:
            arp_out = subprocess.run(["ip", "neigh", "show"],
                                     capture_output=True, text=True).stdout
            known = {line.split()[0] for line in arp_out.splitlines() if line}

            seen = set()
            if os.path.exists(conn_log):
                with open(conn_log) as f:
                    for line in f.readlines()[-500:]:
                        try:
                            obj = json.loads(line)
                            for key in ("id.orig_h", "id.resp_h"):
                                ip = obj.get(key, "")
                                if ip:
                                    seen.add(ip)
                        except Exception:
                            pass

            for ip in seen - known:
                try:
                    if ipaddress.IPv4Address(ip).is_private:
                        subprocess.run(
                            ['sudo', 'arping', '-c', '1', '-w', '1', '-I', IFACE, ip],
                            capture_output=True, timeout=3
                        )
                except Exception:
                    pass
        except Exception:
            pass

def snmp_router_discovery():
    """Query the router's ARP table via SNMP to get all connected devices.
    Auto-detects gateway, tries common community strings."""
    import re as _re
    arp_log = "/var/log/ndr/zeek/arp.log"
    try:
        gw_out = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True).stdout
        m = _re.search(r'default via (\d+\.\d+\.\d+\.\d+)', gw_out)
        if not m:
            return
        gateway = m.group(1)
    except Exception:
        return

    entries = []
    for community in ["public", "private", "community", "admin"]:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "0",
                 gateway, "1.3.6.1.2.1.4.22.1.2"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            now = time.time()
            for line in result.stdout.splitlines():
                ip_m = _re.search(r'\.(\d+\.\d+\.\d+\.\d+)\s*=', line)
                mac_m = _re.search(r'(?:Hex-STRING:|STRING:)\s*([0-9A-Fa-f :]+)', line)
                if not ip_m or not mac_m:
                    continue
                ip = ip_m.group(1)
                mac_raw = mac_m.group(1).strip()
                mac = ":".join(mac_raw.split()).lower() if " " in mac_raw else mac_raw.lower()
                if len(mac) != 17:
                    continue
                entries.append(json.dumps({
                    "ts": now, "operation": "reply",
                    "mac": mac, "dst_mac": "", "ip": ip, "dst_ip": ""
                }))
            if entries:
                print(f"[NDR] SNMP: {len(entries)} devices from router {gateway} (community={community})")
                break
        except Exception:
            continue

    if entries:
        os.makedirs(os.path.dirname(arp_log), exist_ok=True)
        with open(arp_log, "a") as f:
            f.write("\n".join(entries) + "\n")

def bootstrap_from_arp_cache():
    """On startup, read the kernel ARP cache and write entries to arp.log
    so Vector ships them instantly — existing devices appear without any scanning."""
    arp_log = "/var/log/ndr/zeek/arp.log"
    try:
        out = subprocess.run(["ip", "neigh", "show"],
                             capture_output=True, text=True).stdout
        now = time.time()
        entries = []
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" not in parts:
                continue
            idx = parts.index("lladdr")
            ip_str = parts[0]
            mac = parts[idx + 1] if idx + 1 < len(parts) else ""
            state = parts[-1]
            if state in ("FAILED", "INCOMPLETE") or not mac:
                continue
            try:
                import ipaddress as _ip
                addr = _ip.ip_address(ip_str)
                if not addr.is_private or addr.is_loopback:
                    continue
            except Exception:
                continue
            entries.append(json.dumps({
                "ts": now, "operation": "reply",
                "mac": mac, "dst_mac": "",
                "ip": ip_str, "dst_ip": ""
            }))
        if entries:
            os.makedirs(os.path.dirname(arp_log), exist_ok=True)
            with open(arp_log, "a") as f:
                f.write("\n".join(entries) + "\n")
            print(f"[NDR] Bootstrapped {len(entries)} known devices from ARP cache")
    except Exception as e:
        print(f"[NDR] ARP cache bootstrap error: {e}")

def check_and_restart():
    statuses = {}

    if MANUALLY_STOPPED:
        # Services were intentionally stopped — report stopped, do not restart
        statuses['agent-z']       = 'stopped'
        statuses['agent-s']       = 'stopped'
        statuses['vector']        = 'stopped'
        statuses['arkime_capture'] = 'stopped'
        return statuses

    if not is_running('zeek'):
        print("[NDR] Zeek down — restarting")
        start_zeek()
        statuses['agent-z'] = 'restarting'
    else:
        statuses['agent-z'] = 'running'

    if not is_running('suricata'):
        print("[NDR] Suricata down — restarting")
        start_suricata()
        statuses['agent-s'] = 'restarting'
    else:
        statuses['agent-s'] = 'running'

    if not is_running('vector'):
        print("[NDR] Vector down — restarting")
        start_vector()
        statuses['vector'] = 'restarting'
    else:
        statuses['vector'] = 'running'

    if not is_capture_running():
        print("[NDR] Arkime capture down — restarting")
        start_capture()
        statuses['arkime_capture'] = 'restarting'
    else:
        statuses['arkime_capture'] = 'running'

    return statuses

def report_status(statuses):
    import socket
    try:
        sensor_ip = socket.gethostbyname(
            socket.gethostname())
    except:
        sensor_ip = '127.0.0.1'

    payload = {
        'tenant_id':   TENANT_ID,
        'timestamp':   datetime.utcnow().isoformat(),
        'sensor_ip':   sensor_ip,
        **statuses
    }
    try:
        requests.post(
            f'{CLOUD_URL}/api/sensor/heartbeat',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        print(f"[NDR] Heartbeat sent: "
              f"agent-z={statuses.get('agent-z')} "
              f"agent-s={statuses.get('agent-s')} "
              f"capture={statuses.get('arkime_capture')}")
    except Exception as e:
        print(f"[NDR] Heartbeat failed: {e}")

def get_pending_pcap():
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/pcap/pending',
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            # Handle both formats:
            # old: ["cid1","cid2"]
            # new: {"pending":[{"community_id":"..."}]}
            if isinstance(data, list):
                return data
            items = data.get('pending', [])
            result = []
            for p in items:
                if isinstance(p, str):
                    result.append(p)
                elif isinstance(p, dict):
                    result.append(p.get('community_id', ''))
            return [x for x in result if x]
    except Exception as e:
        print(f"[NDR] pending poll error: {e}")
    return []

def process_pcap_uploads():
    pending = get_pending_pcap()
    if not pending:
        return

    print(f"[NDR] {len(pending)} PCAP uploads pending")
    for cid in pending[:5]:
        if not cid:
            continue
        try:
            result = subprocess.run(
                ['python3',
                 '/opt/ndr-sensor/pcap-uploader.py',
                 str(cid)],
                capture_output=True,
                text=True, timeout=120
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.returncode != 0:
                print(f"[NDR] Upload failed for "
                      f"{cid[:20]}: "
                      f"{result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"[NDR] Upload timeout: {cid[:20]}")
        except Exception as e:
            print(f"[NDR] Upload error: {e}")

def execute_command(cmd):
    """Execute a received command string. Called by do_checkin() and
    the legacy check_and_execute_command() for backward compat."""
    global MANUALLY_STOPPED
    print(f"[NDR] *** COMMAND RECEIVED: {cmd} ***")
    if cmd == 'stop':
        MANUALLY_STOPPED = True
        subprocess.run(['pkill', '-9', '-f', 'zeek'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'suricata'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'ndr-vector'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'vector --config'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', '/usr/local/bin/vector'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'arkime-capture'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'arkime-capture'], capture_output=True)
        print("[NDR] All services stopped")
    elif cmd == 'start':
        MANUALLY_STOPPED = False
        discover_subnets()
        bootstrap_from_arp_cache()
        snmp_router_discovery()
        start_zeek()
        start_suricata()
        start_vector()
        start_capture()
        threading.Thread(target=arp_scan, args=(IFACE,), daemon=True).start()
        threading.Thread(target=arp_probe_unknown, daemon=True).start()
        print("[NDR] All services started")
    elif cmd == 'restart':
        MANUALLY_STOPPED = False
        subprocess.run(['systemctl', 'restart', 'zeek'], capture_output=True)
        subprocess.run(['systemctl', 'restart', 'suricata'], capture_output=True)
        subprocess.run(['pkill', '-f', 'vector'], capture_output=True)
        time.sleep(2)
        start_vector()
        subprocess.run(['pkill', '-f', 'arkime-capture'], capture_output=True)
        time.sleep(2)
        start_capture()
        print("[NDR] All services restarted")
    elif cmd.startswith('suppress_sid:'):
        # Formats:
        #   suppress_sid:2066052               → blanket SID suppress
        #   suppress_sid:2066052:by_dst:1.2.3.4 → suppress SID to specific dst IP
        #   suppress_sid:2066052:by_src:1.2.3.4 → suppress SID from specific src IP
        parts = cmd.split(':')
        sid = parts[1].strip()
        threshold_file = '/etc/suricata/threshold.conf'
        if len(parts) >= 4:
            track_type = parts[2].strip()
            track_ip   = parts[3].strip()
            track_kw   = 'by_dst' if track_type == 'by_dst' else 'by_src'
            suppress_line = (
                f'suppress gen_id 1, sig_id {sid}, '
                f'track {track_kw}, ip {track_ip}\n'
            )
        else:
            suppress_line = f'suppress gen_id 1, sig_id {sid}\n'
        try:
            with open(threshold_file, 'r') as f:
                existing = f.read()
        except FileNotFoundError:
            existing = ''
        if suppress_line.strip() not in existing:
            with open(threshold_file, 'a') as f:
                f.write(suppress_line)
            print(f"[NDR] Suppressed SID {sid} ({suppress_line.strip()})")
            reloaded = False
            try:
                pid_out = subprocess.run(['pidof', 'suricata'], capture_output=True, text=True)
                pid = pid_out.stdout.strip().split()[0]
                subprocess.run(['kill', '-USR2', pid], check=True)
                reloaded = True
            except Exception:
                pass
            if not reloaded:
                subprocess.run(['suricatasc', '-c', 'reload-rules'], capture_output=True)

            # ── Zeek collection-layer filter ──────────────────────────────
            # Map known SIDs to Zeek log_policy hooks so noise never reaches logs
            ZEEK_SID_FILTERS = {
                '2049049': ('dns',  '"ngrok" in rec$query'),
                '2066052': ('ssl',  '"ngrok" in rec$server_name'),
                '2066057': ('ssl',  '"ngrok" in rec$server_name'),
                '2022973': ('dhcp', 'rec?$host_name && "kali" in to_lower(rec$host_name)'),
            }
            zeek_filter_file = '/opt/zeek/share/zeek/site/ndr-suppress.zeek'
            if sid in ZEEK_SID_FILTERS:
                log_type, condition = ZEEK_SID_FILTERS[sid]
                hook_map = {
                    'dns':  ('DNS', 'DNS::Info', 'DNS::log_policy'),
                    'ssl':  ('SSL', 'SSL::Info', 'SSL::log_policy'),
                    'dhcp': ('DHCP', 'DHCP::Info', 'DHCP::log_policy'),
                }
                module, rec_type, hook_name = hook_map[log_type]
                hook_block = (
                    f'\nhook {hook_name}(rec: {rec_type}, '
                    f'id: Log::ID, filter: Log::Filter) {{\n'
                    f'    if ({condition}) break;\n}}\n'
                )
                try:
                    existing_zeek = open(zeek_filter_file).read() if os.path.exists(zeek_filter_file) else ''
                except Exception:
                    existing_zeek = ''
                if hook_block.strip() not in existing_zeek:
                    os.makedirs(os.path.dirname(zeek_filter_file), exist_ok=True)
                    with open(zeek_filter_file, 'a') as zf:
                        if not existing_zeek:
                            zf.write('# NDR auto-generated Zeek suppression filters\n')
                        zf.write(hook_block)
                    # Add @load to local.zeek if not already there
                    local_zeek = '/opt/zeek/share/zeek/site/local.zeek'
                    load_line = '@load ndr-suppress\n'
                    try:
                        lz = open(local_zeek).read()
                    except Exception:
                        lz = ''
                    if load_line.strip() not in lz:
                        with open(local_zeek, 'a') as lf:
                            lf.write(load_line)
                    # Restart Zeek to apply new filter
                    try:
                        subprocess.run(['pkill', '-f', 'zeek'], capture_output=True)
                        import time as _time; _time.sleep(1)
                        iface = open('/opt/ndr/.runtime/ndr_interface').read().strip()
                        subprocess.Popen(
                            ['/opt/zeek/bin/zeek', '-i', iface, 'local',
                             'Log::default_logdir=/var/log/ndr/zeek'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                        print(f"[NDR] Zeek filter added for SID {sid}, Zeek restarted")
                    except Exception as e:
                        print(f"[NDR] Zeek restart failed: {e}")
        else:
            print(f"[NDR] SID {sid} already suppressed")
    else:
        print(f"[NDR] Unknown command ignored: {cmd}")

def check_and_execute_command():
    """Legacy single-poll command handler — kept for backward compat.
    New sensors use do_checkin() which combines this with heartbeat
    and pcap pending into one request."""
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/sensor/command',
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        if resp.status_code != 200:
            return
        cmd = resp.json().get('command', '').strip()
        if cmd:
            execute_command(cmd)
    except Exception as e:
        print(f"[NDR] Command poll error: {e}")

def do_checkin():
    """Single combined check-in — replaces the old 3 separate polls
    (heartbeat, command, pcap pending) with one request.
    Returns the server-requested interval in seconds (default 30)."""
    import socket
    try:
        sensor_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        sensor_ip = '127.0.0.1'

    statuses = check_and_restart()

    payload = {
        'tenant_id':      TENANT_ID,
        'sensor_ip':      sensor_ip,
        'arkime_url':     f'http://{sensor_ip}:8005',
        'arkime_pass':    ARKIME_PASS,
        'agent-z':        statuses.get('agent-z', 'unknown'),
        'agent-s':        statuses.get('agent-s', 'unknown'),
        'vector':         statuses.get('vector', 'unknown'),
        'arkime_capture': statuses.get('arkime_capture', 'unknown'),
        'arkime_viewer':  statuses.get('arkime_viewer', 'unknown'),
    }

    try:
        resp = requests.post(
            f'{CLOUD_URL}/api/sensor/checkin',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        if resp.status_code != 200:
            print(f"[NDR] Checkin HTTP {resp.status_code}")
            return 30

        data = resp.json()
        print(f"[NDR] Checkin ok — "
              f"agent-z={payload['agent-z']} "
              f"agent-s={payload['agent-s']} "
              f"arkime={payload['arkime_capture']}")

        cmd = data.get('command', '').strip()
        if cmd:
            execute_command(cmd)

        pending = data.get('pcap_pending', [])
        if pending:
            print(f"[NDR] {len(pending)} PCAP uploads pending")
            for cid in pending[:5]:
                if not cid:
                    continue
                try:
                    result = subprocess.run(
                        ['python3',
                         '/opt/ndr-sensor/pcap-uploader.py',
                         str(cid)],
                        capture_output=True,
                        text=True, timeout=120
                    )
                    if result.stdout.strip():
                        print(result.stdout.strip())
                    if result.returncode != 0:
                        print(f"[NDR] Upload failed for "
                              f"{cid[:20]}: "
                              f"{result.stderr.strip()}")
                except subprocess.TimeoutExpired:
                    print(f"[NDR] Upload timeout: {cid[:20]}")
                except Exception as e:
                    print(f"[NDR] PCAP upload error: {e}")

        return int(data.get('checkin_interval_secs', 30))

    except Exception as e:
        print(f"[NDR] Checkin failed: {e}")
        return 30

if __name__ == '__main__':
    print(f"[NDR] Agent starting — "
          f"tenant={TENANT_ID}")
    print(f"[NDR] Cloud={CLOUD_URL}")

    os.makedirs("/var/log/ndr/suricata",
        exist_ok=True)
    os.makedirs("/var/log/ndr/zeek",
        exist_ok=True)

    # Start all services
    print("[NDR] Starting all services...")
    discover_subnets()
    bootstrap_from_arp_cache()
    start_zeek()
    start_suricata()
    start_vector()
    start_capture()
    threading.Thread(target=arp_scan, args=(IFACE,), daemon=True).start()
    threading.Thread(target=arp_probe_unknown, daemon=True).start()
    time.sleep(10)  # wait for capture to init

    checkin_interval = 30  # server will update this on first response
    while True:
        checkin_interval = do_checkin() or checkin_interval
        time.sleep(checkin_interval)

