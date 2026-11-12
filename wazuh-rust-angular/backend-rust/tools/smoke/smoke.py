#!/usr/bin/env python3
"""ProVigil smoke test: checks the running platform end to end in about two minutes.

Run it after start-all.bat or a release:

    python tools/smoke/smoke.py --analyst jithin12 --admin aa3
    python tools/smoke/smoke.py --analyst jithin12 --admin aa3 --edr-local
    python tools/smoke/smoke.py --analyst jithin12 --admin aa3 --edr-local --wait-unblock

Passwords are asked for (or read from SMOKE_ANALYST_PASSWORD / SMOKE_ADMIN_PASSWORD); nothing
is saved. --edr-local runs the response actions on an agent installed on THIS machine, with
safe targets only: a reserved test address (198.51.100.77, 10 minutes), a dummy ping process
it starts itself, and a test file it creates in the temp folder. Host isolation and tamper
lock are never run. Exit code 0 when every check passes.
"""
import argparse, getpass, json, os, re, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request

AUTH = 'http://127.0.0.1:3011'
API = 'http://127.0.0.1:8088'
TEST_IP = '198.51.100.77'
RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -  ' + detail) if detail else ''}", flush=True)
    return bool(ok)


def login(user, password):
    req = urllib.request.Request(AUTH + '/api/auth/login', data=json.dumps({'username': user, 'password': password}).encode(),
                                 headers={'Content-Type': 'application/json'})
    r = urllib.request.urlopen(req, timeout=30)
    token = re.search(r'ndr_token=([^;]+)', r.headers.get('Set-Cookie', ''))
    return token.group(1) if token else None, json.loads(r.read() or b'{}').get('user', {})


def call(token, method, path, body=None, tenant=None, raw=False, timeout=120):
    h = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if tenant:
        h['X-Tenant-Id'] = tenant
    req = urllib.request.Request(API + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        b = r.read()
        if raw:
            return r.status, b
        return r.status, (json.loads(b) if b.strip()[:1] in (b'{', b'[') else b)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]
    except Exception as e:  # connection refused, timeout
        return 0, str(e)


def items(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys + ('data', 'items', 'agents', 'alerts', 'cases'):
            if isinstance(body.get(k), list):
                return body[k]
    return []


def port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- sections

def services():
    print('\n[1] Services')
    for name, port in [('auth service', 3011), ('siem-api', 8088), ('gateway gRPC', 8089), ('gateway HTTPS', 8443), ('console dev server', 4200)]:
        check(f'{name} listening on {port}', port_open(port))


def apis(analyst, admin, tenant):
    print('\n[2] Console APIs')
    analyst_paths = ['/api/server-info', '/api/v1/agents', '/api/v1/alerts?limit=5', '/api/v1/events?limit=5', '/api/v1/stats',
                     '/api/v1/vulnerabilities', '/api/v1/compliance', '/api/v1/parsers', '/api/v1/intent/summary',
                     '/api/v1/risk-fabric/summary', '/api/v1/deception/summary', '/api/soar/cases', '/api/soar/native/playbooks',
                     '/api/soar/runs', '/api/v1/posture', '/api/v1/posture/history', '/api/v1/posture/agents']
    for p in analyst_paths:
        s, b = call(analyst, 'GET', p, tenant=tenant)
        check(f'analyst GET {p}', s == 200, '' if s == 200 else f'HTTP {s} {str(b)[:80]}')
    s, b = call(analyst, 'GET', '/api/v1/parsers', tenant=tenant)
    check('learned parsers loaded (not empty on first visit)', s == 200 and len(items(b)) > 0, f'{len(items(b))} parsers')
    if admin:
        for p in ['/api/v1/syslog/devices', '/api/v1/syslog/sources', '/api/v1/tenant/alert-mail', '/api/v1/reports/schedule',
                  '/api/v1/agents/deactivated']:
            s, b = call(admin, 'GET', p, tenant=tenant)
            check(f'tenant admin GET {p}', s == 200, '' if s == 200 else f'HTTP {s}')
        s, _ = call(analyst, 'GET', '/api/v1/syslog/devices', tenant=tenant)
        check('analyst is refused a tenant-admin page', s == 403, f'HTTP {s}')


def agent_health(token, tenant, agent_id):
    print('\n[3] Agent and data flow')
    s, b = call(token, 'GET', '/api/v1/agents', tenant=tenant)
    agents = items(b)
    active = [a for a in agents if a.get('status') == 'active']
    check('at least one active agent', active, f'{len(active)} of {len(agents)} active')
    a = next((x for x in agents if x.get('id') == agent_id), None) if agent_id else (active[0] if active else None)
    if not a:
        check('agent to test found', False, agent_id or 'none active')
        return None
    check(f"agent {a['id']} ({a.get('name')}) is active", a.get('status') == 'active', a.get('version', ''))
    s, b = call(token, 'GET', '/api/v1/events?limit=200', tenant=tenant)
    mine = [e for e in items(b, 'events') if a['id'] in (str(e.get('agent_id', '')), str((e.get('agent') or {}).get('id', '')))]
    check(f"agent {a['id']} events among the newest 200", mine, f'{len(mine)} found')
    return a['id']


def workflows(token, tenant):
    print('\n[4] Workflows')
    s, b = call(token, 'GET', '/api/v1/alerts?limit=1', tenant=tenant)
    alert = (items(b) or [{}])[0]
    s, b = call(token, 'POST', '/api/soar/cases', {'title': '[SMOKE TEST] safe to ignore', 'description': 'created by tools/smoke/smoke.py',
                                                    'severity': 'LOW', 'priority': 'P4', 'hit_ids': [alert.get('id')] if alert.get('id') else [],
                                                    'tags': ['smoke-test']}, tenant=tenant)
    cid = b.get('id') if isinstance(b, dict) else None
    if check('case: create from an alert', s == 200 and cid, (b.get('case_number', '') if isinstance(b, dict) else str(b)[:80])):
        check('case: comment', call(token, 'POST', f'/api/soar/cases/{cid}/comments', {'comment': 'smoke test'}, tenant=tenant)[0] == 200)
        check('case: In Progress', call(token, 'PUT', f'/api/soar/cases/{cid}/status', {'status': 'In Progress'}, tenant=tenant)[0] == 200)
        check('case: Closed', call(token, 'PUT', f'/api/soar/cases/{cid}/status', {'status': 'Closed'}, tenant=tenant)[0] == 200)
        time.sleep(2)
        s, b = call(token, 'GET', '/api/soar/cases', tenant=tenant)
        case = next((c for c in items(b) if c.get('id') == cid), {})
        check('case: status reads back as Closed', case.get('status') == 'Closed', str(case.get('status')))
    s, b = call(token, 'POST', '/api/v1/vulnerabilities', {}, tenant=tenant)
    check('vulnerability re-scan accepted', s == 200, (b.get('message', '') if isinstance(b, dict) else '')[:80])
    t0 = time.time()
    s, b = call(token, 'GET', '/api/v1/compliance?refresh=1', tenant=tenant)
    fw = b.get('frameworks', []) if isinstance(b, dict) else []
    check('compliance refresh', s == 200 and fw, f"{len(fw)} frameworks, {int((time.time() - t0) * 1000)} ms")
    s, b = call(token, 'GET', '/api/v1/vulnerabilities/report.xlsx', tenant=tenant, raw=True)
    check('Excel vulnerability report', s == 200 and isinstance(b, bytes) and b[:2] == b'PK', f'{len(b) if isinstance(b, bytes) else 0} bytes')


def _firewall_has(ip):
    out = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=PROVIGIL ACTIVE RESPONSE BLOCKED IP'],
                         capture_output=True, text=True).stdout
    return ip in out


def edr_local(token, tenant, agent_id, wait_unblock):
    print('\n[5] Response actions on the agent on this machine (safe targets)')
    if os.name != 'nt':
        check('response actions (Windows agent on this machine)', False, 'needs Windows')
        return
    since = time.strftime('%Y/%m/%d %H:%M:%S')

    def send(body):
        return call(token, 'POST', '/api/v1/agent/commands', dict(body, agent_id=agent_id), tenant=tenant)

    # block a reserved documentation address
    s, b = send({'action': 'block_ip', 'target': TEST_IP, 'duration_seconds': 600})
    ok = s in (200, 201)
    for _ in range(12):
        if ok and _firewall_has(TEST_IP):
            break
        time.sleep(3)
    check(f'block IP {TEST_IP} (firewall rule appears)', ok and _firewall_has(TEST_IP), f'HTTP {s}')

    # kill a dummy process started here, by PID and by file name
    p = subprocess.Popen(['ping', '-n', '600', '127.0.0.1'], stdout=subprocess.DEVNULL, creationflags=0x08000000)
    s, b = send({'action': 'kill_process', 'pid': p.pid, 'image': 'PING.EXE'})
    for _ in range(12):
        if p.poll() is not None:
            break
        time.sleep(3)
    check('kill process (dummy ping, image given as file name)', p.poll() is not None, f'HTTP {s}')
    if p.poll() is None:
        p.kill()

    # quarantine a test file, then restore it
    path = os.path.join(tempfile.gettempdir(), 'provigil-smoke-quarantine.txt')
    with open(path, 'w') as f:
        f.write('ProVigil smoke test file - harmless\n')
    s, b = send({'action': 'quarantine_file', 'path': path})
    for _ in range(12):
        if not os.path.exists(path):
            break
        time.sleep(3)
    gone = not os.path.exists(path)
    check('quarantine test file (file moved away)', gone, f'HTTP {s}')
    qid = None
    for base in [r'C:\Program Files (x86)\ProVigil Agent', r'C:\Program Files\ProVigil Agent']:
        log = os.path.join(base, 'active-response', 'active-responses.log')
        if os.path.exists(log):
            with open(log, encoding='utf-8', errors='replace') as f:
                for l in reversed(f.readlines()[-200:]):
                    m = re.search(r'"File quarantined","id":"([^"]+)","path":"([^"]+)"', l)
                    if m and m.group(2).replace('\\\\', '\\').lower() == path.lower():
                        qid = m.group(1)
                        break
    if gone and qid:
        s, b = send({'action': 'restore_file', 'quarantine_id': qid})
        for _ in range(12):
            if os.path.exists(path):
                break
            time.sleep(3)
        check('restore quarantined file (back, content intact)', os.path.exists(path) and 'smoke test' in open(path).read(), f'HTTP {s}')
    else:
        check('restore quarantined file', False, 'quarantine id not found in the agent log')
    if os.path.exists(path):
        os.remove(path)

    if wait_unblock:
        print('  ...  waiting up to 11 minutes for the timed unblock')
        for _ in range(132):
            if not _firewall_has(TEST_IP):
                break
            time.sleep(5)
        check('timed unblock after 10 minutes (rule removed)', not _firewall_has(TEST_IP))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--analyst', required=True, help='analyst user name')
    ap.add_argument('--admin', help='tenant admin user name (tenant-admin pages)')
    ap.add_argument('--tenant', default='acm')
    ap.add_argument('--agent', help='agent id to test (default: the first active agent)')
    ap.add_argument('--edr-local', action='store_true', help='run the safe response actions on the agent on this machine')
    ap.add_argument('--wait-unblock', action='store_true', help='also wait for the 10-minute timed unblock')
    a = ap.parse_args()

    apw = os.environ.get('SMOKE_ANALYST_PASSWORD') or getpass.getpass(f'password for {a.analyst}: ')
    services()
    try:
        analyst, _ = login(a.analyst, apw)
    except Exception as e:
        check('analyst login', False, str(e))
        return report()
    check('analyst login', analyst)
    admin = None
    if a.admin:
        dpw = os.environ.get('SMOKE_ADMIN_PASSWORD') or getpass.getpass(f'password for {a.admin}: ')
        try:
            admin, user = login(a.admin, dpw)
            check('tenant admin login', admin and user.get('role') == 'tenant_admin', user.get('role', ''))
        except Exception as e:
            check('tenant admin login', False, str(e))
    apis(analyst, admin, a.tenant)
    agent_id = agent_health(analyst, a.tenant, a.agent)
    workflows(analyst, a.tenant)
    if a.edr_local and agent_id:
        edr_local(analyst, a.tenant, agent_id, a.wait_unblock)
    return report()


def report():
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    for name, _, detail in failed:
        print(f'  FAILED: {name}  {detail}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
