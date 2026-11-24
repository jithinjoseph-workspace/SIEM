import os
import requests
import urllib3
import time

# Disable insecure request warnings if using self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Monkey-patch requests to avoid Nginx 429 Too Many Requests (limit_req rate=120r/m burst=30)
original_get = requests.get
def throttled_get(*args, **kwargs):
    time.sleep(0.6)
    return original_get(*args, **kwargs)
requests.get = throttled_get

original_post = requests.post
def throttled_post(*args, **kwargs):
    time.sleep(0.6)
    return original_post(*args, **kwargs)
requests.post = throttled_post

# ==============================================================================
# CONFIGURATION - Set these parameters before running on your Linux VM
# ==============================================================================
BASE_URL = "https://10.0.2.15:3000"

# Passwords come from the environment, never from this file (it is in git):
#   QA_ADMIN_PASSWORD, QA_TENANT_ADMIN_PASSWORD, QA_AUTO_ADMIN_PASSWORD, QA_ANALYST_PASSWORD
# A missing one keeps the "your_..." placeholder, which fetch_token skips.
ADMIN_PASSWORD = os.environ.get("QA_ADMIN_PASSWORD", "your_admin_password_here")
TENANT_ADMIN_PASSWORD = os.environ.get("QA_TENANT_ADMIN_PASSWORD", "your_tenant_admin_password_here")
AUTO_ADMIN_PASSWORD = os.environ.get("QA_AUTO_ADMIN_PASSWORD", "your_auto_admin_password_here")
ANALYST_PASSWORD = os.environ.get("QA_ANALYST_PASSWORD", "your_analyst_password_here")

def fetch_token(username, password, tenant_id=None):
    if password == "your_admin_password_here" or "your_" in password:
        return "PLACEHOLDER_TOKEN"
    payload = {"username": username, "password": password}
    if tenant_id:
        payload["tenant_id"] = tenant_id
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=payload, verify=False)
        if resp.status_code == 200:
            return resp.json().get("user", {}).get("token")
        else:
            print(f"[!] Failed to login {username}: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Request error logging in {username}: {e}")
    return "INVALID_TOKEN"

SUPER_ADMIN_TOKEN = fetch_token("admin", ADMIN_PASSWORD)
TENANT_ADMIN_TOKEN = fetch_token("tenant-admin", TENANT_ADMIN_PASSWORD)
DISPOSABLE_TENANT_ID = "automated-test-tenant"
DISPOSABLE_TENANT_USER_TOKEN = fetch_token("auto_admin", AUTO_ADMIN_PASSWORD, DISPOSABLE_TENANT_ID)
ANALYST_TOKEN = fetch_token("defaultAnalyst", ANALYST_PASSWORD)

sa_headers = {
    "Authorization": f"Bearer {SUPER_ADMIN_TOKEN}",
    "Content-Type": "application/json"
}

analyst_headers = {
    "Authorization": f"Bearer {ANALYST_TOKEN}",
    "Content-Type": "application/json"
}

def print_result(tc_id, status, details=""):
    color = "\033[92m" if status == "PASS" else "\033[91m"
    if status == "SKIP":
        color = "\033[93m"
    reset = "\033[0m"
    print(f"{color}{tc_id} = {status}{reset} | {details}")

def test_tc_026():
    """List NDR Engines"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/engines", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-026", "PASS", f"Retrieved engines list. Count: {len(resp.json())}")
        else:
            print_result("TC-026", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-026", "FAIL", str(e))

def test_tc_027():
    """View Global Telemetry"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/telemetry", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-027", "PASS", "Successfully retrieved global telemetry.")
        else:
            print_result("TC-027", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-027", "FAIL", str(e))

def test_tc_028():
    """View Active Sessions Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/active-sessions", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-028", "PASS", f"Successfully retrieved active sessions. Count: {len(resp.json())}")
        else:
            print_result("TC-028", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-028", "FAIL", str(e))

def test_tc_029():
    """Check Component Version"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/version", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-029", "PASS", f"Retrieved version.")
        else:
            print_result("TC-029", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-029", "FAIL", str(e))

def test_tc_030():
    """Check Cluster Leader Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/leader-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-030", "PASS", f"Leader status OK.")
        else:
            print_result("TC-030", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-030", "FAIL", str(e))

def test_tc_031():
    """View Cross-Tenant Statistics"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/stats-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-031", "PASS", "Successfully retrieved cross-tenant statistics.")
        else:
            print_result("TC-031", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-031", "FAIL", str(e))

def test_tc_032():
    """Add Global AI Provider"""
    try:
        payload = {"name": "test-ai", "provider_type": "openai", "api_key": "test"}
        resp = requests.post(f"{BASE_URL}/api/settings/ai/providers", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-032", "PASS", "Successfully added AI provider.")
        else:
            print_result("TC-032", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-032", "FAIL", str(e))

def test_tc_033():
    """Sync Community Rules"""
    try:
        resp = requests.post(f"{BASE_URL}/api/rules/sync-community", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-033", "PASS", "Successfully triggered community rules sync.")
        else:
            print_result("TC-033", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-033", "FAIL", str(e))

def test_tc_034():
    """Apply System Update"""
    try:
        resp = requests.post(f"{BASE_URL}/api/admin/apply-update", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-034", "PASS", "Successfully triggered system update.")
        else:
            print_result("TC-034", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-034", "FAIL", str(e))

def test_tc_035():
    """View Scaling Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scale-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-035", "PASS", "Successfully retrieved scaling status.")
        else:
            print_result("TC-035", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-035", "FAIL", str(e))

def test_tc_036():
    """List Client UI Errors"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/client-errors", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-036", "PASS", "Successfully retrieved client UI errors.")
        else:
            print_result("TC-036", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-036", "FAIL", str(e))

def test_tc_037():
    """Top IPs Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/top-ips-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-037", "PASS", "Successfully retrieved top IPs.")
        else:
            print_result("TC-037", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-037", "FAIL", str(e))

def test_tc_038():
    """Protocols Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/protocols-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-038", "PASS", "Successfully retrieved protocol stats.")
        else:
            print_result("TC-038", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-038", "FAIL", str(e))

def test_tc_039():
    """Global Threat Intel Matches"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/threat-intel-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-039", "PASS", "Successfully retrieved TI matches.")
        else:
            print_result("TC-039", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-039", "FAIL", str(e))

def test_tc_040():
    """Global Threat Map Data"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/threat-map-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-040", "PASS", "Successfully retrieved threat map data.")
        else:
            print_result("TC-040", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-040", "FAIL", str(e))

def test_tc_041():
    """Scale Engines"""
    try:
        payload = {"replicas": 3}
        resp = requests.post(f"{BASE_URL}/api/admin/engines/scale", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-041", "PASS", "Successfully triggered engine scaling.")
        else:
            print_result("TC-041", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-041", "FAIL", str(e))

def test_tc_042():
    """List Licenses"""
    try:
        resp = requests.get(f"{BASE_URL}/api/licenses", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-042", "PASS", "Successfully retrieved licenses.")
        else:
            print_result("TC-042", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-042", "FAIL", str(e))

def test_tc_043():
    """Generate License"""
    try:
        payload = {"tenant_id": "test-tenant", "features": ["ndr"]}
        resp = requests.post(f"{BASE_URL}/api/license/generate", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-043", "PASS", "Successfully generated license.")
        else:
            print_result("TC-043", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-043", "FAIL", str(e))

def test_tc_044():
    """Delete License"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/licenses/test-license-id", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-044", "PASS", "Successfully deleted license.")
        else:
            print_result("TC-044", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-044", "FAIL", str(e))

def test_tc_045():
    """View Global IPAM Subnets"""
    try:
        resp = requests.get(f"{BASE_URL}/api/ipam/subnets", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-045", "PASS", "Successfully retrieved subnets.")
        else:
            print_result("TC-045", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-045", "FAIL", str(e))

def test_tc_046():
    """List Honeypots"""
    try:
        resp = requests.get(f"{BASE_URL}/api/honeypots", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-046", "PASS", "Successfully retrieved honeypots.")
        else:
            print_result("TC-046", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-046", "FAIL", str(e))

def test_tc_047():
    """Create Honeypot"""
    try:
        payload = {"ip": "10.0.0.100", "name": "Decoy"}
        resp = requests.post(f"{BASE_URL}/api/honeypots", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-047", "PASS", "Successfully created honeypot.")
        else:
            print_result("TC-047", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-047", "FAIL", str(e))

def test_tc_048():
    """Delete Honeypot"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/honeypots/1", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-048", "PASS", "Successfully deleted honeypot.")
        else:
            print_result("TC-048", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-048", "FAIL", str(e))

def test_tc_049():
    """AI Suggest Trusted Domains"""
    try:
        resp = requests.post(f"{BASE_URL}/api/trusted-domains/ai-suggest", headers=sa_headers, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-049", "PASS", "Successfully generated AI suggestions.")
        else:
            print_result("TC-049", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-049", "FAIL", str(e))

def test_tc_050():
    """Add Manual IOC"""
    try:
        payload = {"ioc_type": "ip", "value": "1.2.3.4"}
        resp = requests.post(f"{BASE_URL}/api/threat-intel/add", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-050", "PASS", "Successfully added IOC.")
        else:
            print_result("TC-050", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-050", "FAIL", str(e))


def test_tc_051():
    """View Global Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-051", "PASS", "Successfully retrieved settings.")
        else:
            print_result("TC-051", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-051", "FAIL", str(e))

def test_tc_052():
    """Update Global Settings"""
    try:
        payload = {'session_timeout': 30}
        resp = requests.post(f"{BASE_URL}/api/settings", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-052", "PASS", "Successfully updated settings.")
        else:
            print_result("TC-052", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-052", "FAIL", str(e))

def test_tc_053():
    """View Global SMTP"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/smtp", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-053", "PASS", "Successfully retrieved SMTP settings.")
        else:
            print_result("TC-053", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-053", "FAIL", str(e))

def test_tc_054():
    """Update Global SMTP"""
    try:
        payload = {'host': 'smtp.example.com', 'port': 587}
        resp = requests.post(f"{BASE_URL}/api/settings/smtp", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-054", "PASS", "Successfully updated SMTP settings.")
        else:
            print_result("TC-054", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-054", "FAIL", str(e))

def test_tc_055():
    """View AI Config"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/ai", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-055", "PASS", "Successfully retrieved AI config.")
        else:
            print_result("TC-055", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-055", "FAIL", str(e))

def test_tc_056():
    """Update AI Config"""
    try:
        payload = {'enabled': True}
        resp = requests.post(f"{BASE_URL}/api/settings/ai", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-056", "PASS", "Successfully updated AI config.")
        else:
            print_result("TC-056", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-056", "FAIL", str(e))

def test_tc_057():
    """View Trusted Domains"""
    try:
        resp = requests.get(f"{BASE_URL}/api/trusted-domains", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-057", "PASS", "Successfully retrieved trusted domains.")
        else:
            print_result("TC-057", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-057", "FAIL", str(e))

def test_tc_058():
    """Add Trusted Domain"""
    try:
        payload = {'domain': 'example.com'}
        resp = requests.post(f"{BASE_URL}/api/trusted-domains", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-058", "PASS", "Successfully added trusted domain.")
        else:
            print_result("TC-058", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-058", "FAIL", str(e))

def test_tc_059():
    """Delete Trusted Domain"""
    try:
        payload = {'domain': 'example.com'}
        resp = requests.post(f"{BASE_URL}/api/trusted-domains/delete", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-059", "PASS", "Successfully deleted trusted domain.")
        else:
            print_result("TC-059", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-059", "FAIL", str(e))

def test_tc_060():
    """View DoH Providers"""
    try:
        resp = requests.get(f"{BASE_URL}/api/doh-providers", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-060", "PASS", "Successfully retrieved DoH providers.")
        else:
            print_result("TC-060", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-060", "FAIL", str(e))

def test_tc_061():
    """Add DoH Provider"""
    try:
        payload = {'ip': '8.8.8.8', 'name': 'Google'}
        resp = requests.post(f"{BASE_URL}/api/doh-providers", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-061", "PASS", "Successfully added DoH provider.")
        else:
            print_result("TC-061", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-061", "FAIL", str(e))

def test_tc_062():
    """View Sensor Keys"""
    try:
        resp = requests.get(f"{BASE_URL}/api/sensor-keys", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-062", "PASS", "Successfully retrieved sensor keys.")
        else:
            print_result("TC-062", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-062", "FAIL", str(e))

def test_tc_063():
    """View AI Activity"""
    try:
        resp = requests.get(f"{BASE_URL}/api/ai-activity", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-063", "PASS", "Successfully retrieved AI activity.")
        else:
            print_result("TC-063", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-063", "FAIL", str(e))

def test_tc_064():
    """Monitor Kafka"""
    try:
        resp = requests.get(f"{BASE_URL}/api/monitor/kafka", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-064", "PASS", "Successfully retrieved Kafka status.")
        else:
            print_result("TC-064", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-064", "FAIL", str(e))

def test_tc_065():
    """View Retrospective Scans"""
    try:
        resp = requests.get(f"{BASE_URL}/api/retrospective/scans", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-065", "PASS", "Successfully retrieved retrospective scans.")
        else:
            print_result("TC-065", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-065", "FAIL", str(e))

def test_tc_066():
    """View Global Severity"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/severity-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-066", "PASS", "Successfully retrieved severity stats.")
        else:
            print_result("TC-066", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-066", "FAIL", str(e))

def test_tc_067():
    """View Interfaces"""
    try:
        resp = requests.get(f"{BASE_URL}/api/interfaces", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-067", "PASS", "Successfully retrieved interfaces.")
        else:
            print_result("TC-067", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-067", "FAIL", str(e))

def test_tc_068():
    """View Agent Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/agent-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-068", "PASS", "Successfully retrieved agent status.")
        else:
            print_result("TC-068", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-068", "FAIL", str(e))

def test_tc_069():
    """View Unified Stats"""
    try:
        resp = requests.get(f"{BASE_URL}/api/stats/unified", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-069", "PASS", "Successfully retrieved unified stats.")
        else:
            print_result("TC-069", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-069", "FAIL", str(e))

def test_tc_070():
    """View Network Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/network-map", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-070", "PASS", "Successfully retrieved network map.")
        else:
            print_result("TC-070", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-070", "FAIL", str(e))

def test_tc_071():
    """View Scale Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scale-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-071", "PASS", "Successfully retrieved scale status.")
        else:
            print_result("TC-071", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-071", "FAIL", str(e))

def test_tc_072():
    """View Rule Hit Counts"""
    try:
        resp = requests.get(f"{BASE_URL}/api/rules/hit-counts", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-072", "PASS", "Successfully retrieved rule hit counts.")
        else:
            print_result("TC-072", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-072", "FAIL", str(e))

def test_tc_073():
    """View Threat Intel Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel-map", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-073", "PASS", "Successfully retrieved threat intel map.")
        else:
            print_result("TC-073", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-073", "FAIL", str(e))

def test_tc_074():
    """View Threat Intel Watchlist"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel/watchlist", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-074", "PASS", "Successfully retrieved TI watchlist.")
        else:
            print_result("TC-074", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-074", "FAIL", str(e))

def test_tc_075():
    """Trigger Global Export"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-075", "PASS", "Successfully retrieved export.")
        else:
            print_result("TC-075", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-075", "FAIL", str(e))

def test_tc_076():
    """View License Public Key"""
    try:
        resp = requests.get(f"{BASE_URL}/api/license/public-key", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-076", "PASS", "Successfully retrieved public key.")
        else:
            print_result("TC-076", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-076", "FAIL", str(e))

def test_tc_077():
    """View Tenant Features"""
    try:
        resp = requests.get(f"{BASE_URL}/api/tenant/features", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-077", "PASS", "Successfully retrieved tenant features.")
        else:
            print_result("TC-077", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-077", "FAIL", str(e))

def test_tc_078():
    """View AI Providers"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/ai/providers", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-078", "PASS", "Successfully retrieved AI providers.")
        else:
            print_result("TC-078", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-078", "FAIL", str(e))

def test_tc_079():
    """View Trusted Cloud Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/trusted-cloud", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-079", "PASS", "Successfully retrieved trusted cloud settings.")
        else:
            print_result("TC-079", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-079", "FAIL", str(e))

def test_tc_080():
    """View Subnet Roles"""
    try:
        resp = requests.get(f"{BASE_URL}/api/assets/subnet-roles", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-080", "PASS", "Successfully retrieved subnet roles.")
        else:
            print_result("TC-080", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-080", "FAIL", str(e))

def test_tc_081():
    """Force Logout User"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/admin/sessions/testuser", headers=sa_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-081", "PASS", "Successfully triggered force logout.")
        else:
            print_result("TC-081", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-081", "FAIL", str(e))

def test_tc_082():
    """View System Health"""
    try:
        resp = requests.get(f"{BASE_URL}/api/health", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-082", "PASS", "Successfully retrieved system health.")
        else:
            print_result("TC-082", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-082", "FAIL", str(e))

def test_tc_083():
    """Export System Logs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export-logs", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-083", "PASS", "Successfully retrieved system logs.")
        else:
            print_result("TC-083", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-083", "FAIL", str(e))

def test_tc_084():
    """View Announcements"""
    try:
        resp = requests.get(f"{BASE_URL}/api/announcements", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-084", "PASS", "Successfully retrieved announcements.")
        else:
            print_result("TC-084", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-084", "FAIL", str(e))

def test_tc_085():
    """View Support Messages"""
    try:
        resp = requests.get(f"{BASE_URL}/api/support/messages", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-085", "PASS", "Successfully retrieved support messages.")
        else:
            print_result("TC-085", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-085", "FAIL", str(e))

def test_tc_086():
    """View Threat Predictions"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat/predictions", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-086", "PASS", "Successfully retrieved threat predictions.")
        else:
            print_result("TC-086", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-086", "FAIL", str(e))

def test_tc_087():
    """View Threat Exposure"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat/exposure", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-087", "PASS", "Successfully retrieved threat exposure.")
        else:
            print_result("TC-087", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-087", "FAIL", str(e))

def test_tc_088():
    """View All Assets"""
    try:
        resp = requests.get(f"{BASE_URL}/api/assets", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-088", "PASS", "Successfully retrieved assets.")
        else:
            print_result("TC-088", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-088", "FAIL", str(e))

def test_tc_089():
    """View Detection Rules"""
    try:
        resp = requests.get(f"{BASE_URL}/api/rules", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-089", "PASS", "Successfully retrieved detection rules.")
        else:
            print_result("TC-089", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-089", "FAIL", str(e))

def test_tc_090():
    """Perform Geo Lookup"""
    try:
        payload = {'ip': '8.8.8.8'}
        resp = requests.post(f"{BASE_URL}/api/geo-lookup", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-090", "PASS", "Successfully retrieved geo lookup data.")
        else:
            print_result("TC-090", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-090", "FAIL", str(e))

def test_tc_091():
    """Analyst - View Assigned Alerts"""
    try:
        resp = requests.get(f"{BASE_URL}/api/xdr/alerts?assigned_to=me", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-091", "PASS", "Successfully retrieved assigned alerts.")
        else:
            print_result("TC-091", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-091", "FAIL", str(e))

def test_tc_092(alert_id="test-alert-id"):
    """Analyst - Acknowledge Alert"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/acknowledge", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-092", "PASS", "Successfully acknowledged alert.")
        else:
            print_result("TC-092", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-092", "FAIL", str(e))

def test_tc_093(alert_id="test-alert-id"):
    """Analyst - Add Alert Comment"""
    try:
        payload = {"comment": "Investigating this issue."}
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/comments", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-093", "PASS", "Successfully added comment to alert.")
        else:
            print_result("TC-093", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-093", "FAIL", str(e))

def test_tc_094(alert_id="test-alert-id"):
    """Analyst - View Alert Details"""
    try:
        resp = requests.get(f"{BASE_URL}/api/xdr/alerts/{alert_id}", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-094", "PASS", "Successfully retrieved alert details.")
        else:
            print_result("TC-094", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-094", "FAIL", str(e))

def test_tc_095():
    """Analyst - Search Logs (Scoped)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/logs?query=error", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-095", "PASS", "Successfully searched logs.")
        else:
            print_result("TC-095", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-095", "FAIL", str(e))

def test_tc_096():
    """Analyst - View Threat Intel"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-096", "PASS", "Successfully retrieved threat intel.")
        else:
            print_result("TC-096", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-096", "FAIL", str(e))

def test_tc_097():
    """Analyst - View Network Map (Read-Only)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/network-map", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-097", "PASS", "Successfully retrieved network map.")
        else:
            print_result("TC-097", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-097", "FAIL", str(e))

def test_tc_098():
    """Analyst - Create Report"""
    try:
        payload = {"type": "daily_summary"}
        resp = requests.post(f"{BASE_URL}/api/reports/generate", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 202]:
            print_result("TC-098", "PASS", "Successfully generated report.")
        else:
            print_result("TC-098", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-098", "FAIL", str(e))

def test_tc_099():
    """Analyst - View Own Profile"""
    try:
        resp = requests.get(f"{BASE_URL}/api/auth/me", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-099", "PASS", "Successfully retrieved user profile.")
        else:
            print_result("TC-099", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-099", "FAIL", str(e))

def test_tc_100():
    """Analyst - Update Own Password"""
    try:
        payload = {"password": "new_secure_password"}
        resp = requests.post(f"{BASE_URL}/api/auth/reset-password", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-100", "PASS", "Successfully updated password.")
        else:
            print_result("TC-100", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-100", "FAIL", str(e))

def test_tc_101():
    """Analyst - View Rules (Read-Only)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/rules", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-101", "PASS", "Successfully retrieved rules.")
        else:
            print_result("TC-101", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-101", "FAIL", str(e))

def test_tc_102(alert_id="test-alert-id"):
    """Analyst - Reject Alert (False Positive)"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/reject", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-102", "PASS", "Successfully rejected alert.")
        else:
            print_result("TC-102", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-102", "FAIL", str(e))

def test_tc_103():
    """Analyst - Access Admin Config (Negative)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/auth/tenants", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-103", "PASS", "Correctly denied access to admin config.")
        else:
            print_result("TC-103", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-103", "FAIL", str(e))

def test_tc_104(user_id="test-user-id"):
    """Analyst - Delete User (Negative)"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/auth/users/{user_id}", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-104", "PASS", "Correctly denied access to delete user.")
        else:
            print_result("TC-104", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-104", "FAIL", str(e))

def test_tc_105(alert_id="test-alert-id"):
    """Analyst - Escalate Alert"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/escalate", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-105", "PASS", "Successfully escalated alert.")
        else:
            print_result("TC-105", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-105", "FAIL", str(e))

def test_tc_106():
    """Analyst - Incidents List"""
    try:
        resp = requests.get(f"{BASE_URL}/api/incidents", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-106", "PASS", "Successfully retrieved incidents.")
        else:
            print_result("TC-106", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-106", "FAIL", str(e))

def test_tc_107():
    """Analyst - SOAR Cases"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/cases", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-107", "PASS", "Successfully retrieved SOAR cases.")
        else:
            print_result("TC-107", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-107", "FAIL", str(e))

def test_tc_108():
    """Analyst - Triage Data"""
    try:
        resp = requests.get(f"{BASE_URL}/api/triage", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-108", "PASS", "Successfully retrieved Triage data.")
        else:
            print_result("TC-108", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-108", "FAIL", str(e))

def test_tc_109():
    """Analyst - Assets"""
    try:
        resp = requests.get(f"{BASE_URL}/api/assets", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-109", "PASS", "Successfully retrieved assets.")
        else:
            print_result("TC-109", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-109", "FAIL", str(e))

def test_tc_110():
    """Analyst - Unified Stats"""
    try:
        resp = requests.get(f"{BASE_URL}/api/stats/unified", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-110", "PASS", "Successfully retrieved unified stats.")
        else:
            print_result("TC-110", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-110", "FAIL", str(e))

def test_tc_111():
    """Analyst - Recent Events"""
    try:
        resp = requests.get(f"{BASE_URL}/api/events", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-111", "PASS", "Successfully retrieved recent events.")
        else:
            print_result("TC-111", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-111", "FAIL", str(e))

def test_tc_112():
    """Analyst - Entity Scores"""
    try:
        resp = requests.get(f"{BASE_URL}/api/entity-scores", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-112", "PASS", "Successfully retrieved entity scores.")
        else:
            print_result("TC-112", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-112", "FAIL", str(e))

def test_tc_113():
    """Analyst - Threat Predictions"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat/predictions", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-113", "PASS", "Successfully retrieved threat predictions.")
        else:
            print_result("TC-113", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-113", "FAIL", str(e))

def test_tc_114():
    """Analyst - AI Activity"""
    try:
        resp = requests.get(f"{BASE_URL}/api/ai-activity", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-114", "PASS", "Successfully retrieved AI activity.")
        else:
            print_result("TC-114", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-114", "FAIL", str(e))

def test_tc_115():
    """Analyst - Retrospective"""
    try:
        resp = requests.get(f"{BASE_URL}/api/retrospective/fired-rules", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-115", "PASS", "Successfully retrieved retro rules.")
        else:
            print_result("TC-115", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-115", "FAIL", str(e))

def test_tc_116():
    """Analyst - SOAR Runs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/runs", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-116", "PASS", "Successfully retrieved SOAR runs.")
        else:
            print_result("TC-116", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-116", "FAIL", str(e))

def test_tc_117():
    """Analyst - Active Blocks"""
    try:
        resp = requests.get(f"{BASE_URL}/api/blocks", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-117", "PASS", "Successfully retrieved blocks.")
        else:
            print_result("TC-117", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-117", "FAIL", str(e))

def test_tc_118():
    """Analyst - Device Isolations"""
    try:
        resp = requests.get(f"{BASE_URL}/api/isolations", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-118", "PASS", "Successfully retrieved isolations.")
        else:
            print_result("TC-118", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-118", "FAIL", str(e))

def test_tc_119():
    """Analyst - Trigger Triage"""
    try:
        resp = requests.post(f"{BASE_URL}/api/triage/run", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-119", "PASS", "Successfully manually triggered triage.")
        else:
            print_result("TC-119", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-119", "FAIL", str(e))

def test_tc_120():
    """Analyst - Health Dashboard"""
    try:
        resp = requests.get(f"{BASE_URL}/health", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-120", "PASS", "Successfully checked dashboard stats.")
        else:
            print_result("TC-120", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-120", "FAIL", str(e))

def test_tc_121():
    """Analyst - RBAC - Global Telemetry"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/telemetry", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-121", "PASS", "Successfully denied access to global telemetry.")
        else:
            print_result("TC-121", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-121", "FAIL", str(e))

def test_tc_122():
    """Analyst - RBAC - Start Services"""
    try:
        resp = requests.post(f"{BASE_URL}/api/start", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-122", "PASS", "Successfully denied access to start services.")
        else:
            print_result("TC-122", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-122", "FAIL", str(e))

def test_tc_123():
    """Analyst - RBAC - Stop Services"""
    try:
        resp = requests.post(f"{BASE_URL}/api/stop", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-123", "PASS", "Successfully denied access to stop services.")
        else:
            print_result("TC-123", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-123", "FAIL", str(e))

def test_tc_124():
    """Analyst - RBAC - Create User"""
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/users", json={"username": "test"}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-124", "PASS", "Successfully denied access to create user.")
        else:
            print_result("TC-124", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-124", "FAIL", str(e))

def test_tc_125():
    """Analyst - RBAC - Edit User"""
    try:
        resp = requests.put(f"{BASE_URL}/api/auth/users/test-user", json={"role": "admin"}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-125", "PASS", "Successfully denied access to edit user.")
        else:
            print_result("TC-125", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-125", "FAIL", str(e))

def test_tc_126():
    """Analyst - RBAC - Create Tenant"""
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/tenants", json={"name": "test"}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-126", "PASS", "Successfully denied access to create tenant.")
        else:
            print_result("TC-126", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-126", "FAIL", str(e))

def test_tc_127():
    """Analyst - RBAC - Scale Engines"""
    try:
        resp = requests.post(f"{BASE_URL}/api/admin/engines/scale", json={"replicas": 2}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-127", "PASS", "Successfully denied access to scale engines.")
        else:
            print_result("TC-127", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-127", "FAIL", str(e))

def test_tc_128():
    """Analyst - RBAC - View Engines"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/engines", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-128", "PASS", "Successfully denied access to view engines.")
        else:
            print_result("TC-128", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-128", "FAIL", str(e))

def test_tc_129():
    """Analyst - RBAC - View Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-129", "PASS", "Successfully denied access to view settings.")
        else:
            print_result("TC-129", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-129", "FAIL", str(e))

def test_tc_130():
    """Analyst - RBAC - Update Settings"""
    try:
        resp = requests.post(f"{BASE_URL}/api/settings", json={}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-130", "PASS", "Successfully denied access to update settings.")
        else:
            print_result("TC-130", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-130", "FAIL", str(e))

def test_tc_131():
    """Analyst - RBAC - View AI Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/ai", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-131", "PASS", "Successfully denied access to view AI settings.")
        else:
            print_result("TC-131", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-131", "FAIL", str(e))

def test_tc_132():
    """Analyst - RBAC - Modify AI Providers"""
    try:
        resp = requests.post(f"{BASE_URL}/api/settings/ai/providers", json={}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-132", "PASS", "Successfully denied access to modify AI providers.")
        else:
            print_result("TC-132", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-132", "FAIL", str(e))

def test_tc_133():
    """Analyst - RBAC - Generate License"""
    try:
        resp = requests.post(f"{BASE_URL}/api/license/generate", json={}, headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-133", "PASS", "Successfully denied access to generate license.")
        else:
            print_result("TC-133", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-133", "FAIL", str(e))

def test_tc_134():
    """Analyst - RBAC - View Licenses"""
    try:
        resp = requests.get(f"{BASE_URL}/api/licenses", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-134", "PASS", "Successfully denied access to view licenses.")
        else:
            print_result("TC-134", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-134", "FAIL", str(e))

def test_tc_135():
    """Analyst - RBAC - Apply Update"""
    try:
        resp = requests.post(f"{BASE_URL}/api/admin/apply-update", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-135", "PASS", "Successfully denied access to apply updates.")
        else:
            print_result("TC-135", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-135", "FAIL", str(e))



def test_tc_136():
    """Analyst - View SOAR Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/status", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-136", "PASS", "Successfully retrieved SOAR status.")
        else:
            print_result("TC-136", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-136", "FAIL", str(e))

def test_tc_137():
    """Analyst - View SOAR Integrations"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/integrations", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-137", "PASS", "Successfully retrieved SOAR integrations.")
        else:
            print_result("TC-137", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-137", "FAIL", str(e))

def test_tc_138():
    """Analyst - Create SOAR Case"""
    try:
        payload = {"title": "Suspicious Login"}
        resp = requests.post(f"{BASE_URL}/api/soar/cases", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-138", "PASS", "Successfully created SOAR case.")
        else:
            print_result("TC-138", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-138", "FAIL", str(e))

def test_tc_139(case_id="test-case-id"):
    """Analyst - Update SOAR Case"""
    try:
        payload = {"description": "Updated investigation notes"}
        resp = requests.put(f"{BASE_URL}/api/soar/cases/{case_id}", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-139", "PASS", "Successfully updated SOAR case.")
        else:
            print_result("TC-139", "FAIL", f"PUT failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-139", "FAIL", str(e))

def test_tc_140(case_id="test-case-id"):
    """Analyst - View SOAR Case Comments"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/cases/{case_id}/comments", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-140", "PASS", "Successfully retrieved SOAR case comments.")
        else:
            print_result("TC-140", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-140", "FAIL", str(e))

def test_tc_141(case_id="test-case-id"):
    """Analyst - Add SOAR Case Comment"""
    try:
        payload = {"comment": "Investigating IP"}
        resp = requests.post(f"{BASE_URL}/api/soar/cases/{case_id}/comments", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-141", "PASS", "Successfully added SOAR case comment.")
        else:
            print_result("TC-141", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-141", "FAIL", str(e))

def test_tc_142(case_id="test-case-id"):
    """Analyst - Update SOAR Case Status"""
    try:
        payload = {"status": "Closed"}
        resp = requests.put(f"{BASE_URL}/api/soar/cases/{case_id}/status", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-142", "PASS", "Successfully updated SOAR case status.")
        else:
            print_result("TC-142", "FAIL", f"PUT failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-142", "FAIL", str(e))

def test_tc_143():
    """Analyst - View Native Playbooks"""
    try:
        resp = requests.get(f"{BASE_URL}/api/soar/native/playbooks", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-143", "PASS", "Successfully retrieved native playbooks.")
        else:
            print_result("TC-143", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-143", "FAIL", str(e))

def test_tc_144():
    """Analyst - Manually Block IP"""
    try:
        payload = {"src_ip": "1.1.1.1"}
        resp = requests.post(f"{BASE_URL}/api/blocks/manual", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-144", "PASS", "Successfully added manual IP block.")
        else:
            print_result("TC-144", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-144", "FAIL", str(e))

def test_tc_145(block_id="test-block-id"):
    """Analyst - Revoke IP Block"""
    try:
        payload = {"id": block_id}
        resp = requests.post(f"{BASE_URL}/api/blocks/revoke", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-145", "PASS", "Successfully revoked IP block.")
        else:
            print_result("TC-145", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-145", "FAIL", str(e))

def test_tc_146():
    """Analyst - Isolate Device"""
    try:
        payload = {"target_ip": "1.1.1.1"}
        resp = requests.post(f"{BASE_URL}/api/isolate", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-146", "PASS", "Successfully isolated device.")
        else:
            print_result("TC-146", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-146", "FAIL", str(e))

def test_tc_147(iso_id="test-iso-id"):
    """Analyst - Unisolate Device"""
    try:
        payload = {"id": iso_id}
        resp = requests.post(f"{BASE_URL}/api/unisolate", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-147", "PASS", "Successfully unisolated device.")
        else:
            print_result("TC-147", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-147", "FAIL", str(e))

def test_tc_148():
    """Analyst - View SIEM Dashboard"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/dashboard", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-148", "PASS", "Successfully retrieved SIEM dashboard.")
        else:
            print_result("TC-148", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-148", "FAIL", str(e))

def test_tc_149():
    """Analyst - View Log Sources"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/sources", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-149", "PASS", "Successfully retrieved log sources.")
        else:
            print_result("TC-149", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-149", "FAIL", str(e))

def test_tc_150(rule_id="test-rule-id"):
    """Analyst - Update SIEM Rule"""
    try:
        payload = {"enabled": False}
        resp = requests.put(f"{BASE_URL}/api/siem/rules/{rule_id}", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-150", "PASS", "Successfully updated SIEM rule.")
        else:
            print_result("TC-150", "FAIL", f"PUT failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-150", "FAIL", str(e))


def test_tc_151():
    """Analyst - View Agent Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/agent-status", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-151", "PASS", "Successfully retrieved agent status.")
        else:
            print_result("TC-151", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-151", "FAIL", str(e))

def test_tc_152():
    """Analyst - View System Stats"""
    try:
        resp = requests.get(f"{BASE_URL}/api/stats", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-152", "PASS", "Successfully retrieved stats.")
        else:
            print_result("TC-152", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-152", "FAIL", str(e))

def test_tc_153():
    """Analyst - View Stats Timeline"""
    try:
        resp = requests.get(f"{BASE_URL}/api/stats/timeline", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-153", "PASS", "Successfully retrieved stats timeline.")
        else:
            print_result("TC-153", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-153", "FAIL", str(e))

def test_tc_154():
    """Analyst - View Top IPs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/top-ips", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-154", "PASS", "Successfully retrieved top IPs.")
        else:
            print_result("TC-154", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-154", "FAIL", str(e))

def test_tc_155():
    """Analyst - View Protocols"""
    try:
        resp = requests.get(f"{BASE_URL}/api/protocols", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-155", "PASS", "Successfully retrieved protocols.")
        else:
            print_result("TC-155", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-155", "FAIL", str(e))

def test_tc_156():
    """Analyst - View Severity Stats"""
    try:
        resp = requests.get(f"{BASE_URL}/api/severity", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-156", "PASS", "Successfully retrieved severity stats.")
        else:
            print_result("TC-156", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-156", "FAIL", str(e))

def test_tc_157():
    """Analyst - View Hits"""
    try:
        resp = requests.get(f"{BASE_URL}/api/hits", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-157", "PASS", "Successfully retrieved hits.")
        else:
            print_result("TC-157", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-157", "FAIL", str(e))

def test_tc_158():
    """Analyst - Search Network Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/network-map/search?q=1.1.1.1", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-158", "PASS", "Successfully searched network map.")
        else:
            print_result("TC-158", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-158", "FAIL", str(e))

def test_tc_159():
    """Analyst - View Scale Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scale-status", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-159", "PASS", "Successfully retrieved scale status.")
        else:
            print_result("TC-159", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-159", "FAIL", str(e))

def test_tc_160():
    """Analyst - View Rule Hit Counts"""
    try:
        resp = requests.get(f"{BASE_URL}/api/rules/hit-counts", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-160", "PASS", "Successfully retrieved rule hit counts.")
        else:
            print_result("TC-160", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-160", "FAIL", str(e))

def test_tc_161():
    """Analyst - View Threat Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-map", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-161", "PASS", "Successfully retrieved threat map.")
        else:
            print_result("TC-161", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-161", "FAIL", str(e))

def test_tc_162():
    """Analyst - View Threat Intel Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel-map", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-162", "PASS", "Successfully retrieved threat intel map.")
        else:
            print_result("TC-162", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-162", "FAIL", str(e))

def test_tc_163():
    """Analyst - Export Report"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-163", "PASS", "Successfully exported report.")
        else:
            print_result("TC-163", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-163", "FAIL", str(e))

def test_tc_164():
    """Analyst - Export Logs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export-logs", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-164", "PASS", "Successfully exported logs.")
        else:
            print_result("TC-164", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-164", "FAIL", str(e))

def test_tc_165():
    """Analyst - View Active Announcements"""
    try:
        resp = requests.get(f"{BASE_URL}/api/announcements/active", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-165", "PASS", "Successfully retrieved active announcements.")
        else:
            print_result("TC-165", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-165", "FAIL", str(e))


def test_tc_166():
    """Analyst - Update Gmail"""
    try:
        payload = {"gmail": "test@example.com"}
        resp = requests.put(f"{BASE_URL}/api/auth/me/gmail", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-166", "PASS", "Successfully updated gmail.")
        else:
            print_result("TC-166", "FAIL", f"PUT failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-166", "FAIL", str(e))

def test_tc_167():
    """Analyst - Regenerate MFA Secret"""
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/me/regenerate-secret", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-167", "PASS", "Successfully regenerated MFA secret.")
        else:
            print_result("TC-167", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-167", "FAIL", str(e))

def test_tc_168():
    """Analyst - View Announcements"""
    try:
        resp = requests.get(f"{BASE_URL}/api/announcements", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-168", "PASS", "Successfully retrieved announcements.")
        else:
            print_result("TC-168", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-168", "FAIL", str(e))

def test_tc_169(announcement_id="1"):
    """Analyst - Mark Announcement Read"""
    try:
        resp = requests.post(f"{BASE_URL}/api/announcements/{announcement_id}/read", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-169", "PASS", "Successfully marked announcement read.")
        else:
            print_result("TC-169", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-169", "FAIL", str(e))

def test_tc_170():
    """Analyst - View Watchlist IOCs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel/watchlist", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-170", "PASS", "Successfully retrieved watchlist.")
        else:
            print_result("TC-170", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-170", "FAIL", str(e))

def test_tc_171():
    """Analyst - Lookup IOC"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel/1.1.1.1", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-171", "PASS", "Successfully looked up IOC.")
        else:
            print_result("TC-171", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-171", "FAIL", str(e))

def test_tc_172():
    """Analyst - Reload Rules"""
    try:
        resp = requests.post(f"{BASE_URL}/api/rules/reload", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-172", "PASS", "Successfully reloaded rules.")
        else:
            print_result("TC-172", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-172", "FAIL", str(e))

def test_tc_173():
    """Analyst - Sync Community Rules"""
    try:
        resp = requests.post(f"{BASE_URL}/api/rules/sync-community", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-173", "PASS", "Successfully synced community rules.")
        else:
            print_result("TC-173", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-173", "FAIL", str(e))

def test_tc_174(rule_id="test-rule-id"):
    """Analyst - Toggle Rule"""
    try:
        payload = {"enabled": True}
        resp = requests.post(f"{BASE_URL}/api/rules/{rule_id}/toggle", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-174", "PASS", "Successfully toggled rule.")
        else:
            print_result("TC-174", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-174", "FAIL", str(e))

def test_tc_175():
    """Analyst - Fetch Jira Tickets"""
    try:
        payload = {"url": "", "email": "", "token": "", "project_key": ""}
        resp = requests.post(f"{BASE_URL}/api/soar/jira/tickets", json=payload, headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-175", "PASS", "Successfully fetched Jira tickets.")
        else:
            print_result("TC-175", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-175", "FAIL", str(e))

def test_tc_176():
    """Analyst - View Interfaces"""
    try:
        resp = requests.get(f"{BASE_URL}/api/interfaces", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-176", "PASS", "Successfully retrieved interfaces.")
        else:
            print_result("TC-176", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-176", "FAIL", str(e))

def test_tc_177():
    """Analyst - View Tenant Features"""
    try:
        resp = requests.get(f"{BASE_URL}/api/tenant/features", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-177", "PASS", "Successfully retrieved tenant features.")
        else:
            print_result("TC-177", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-177", "FAIL", str(e))

def test_tc_178():
    """Analyst - View License Public Key"""
    try:
        resp = requests.get(f"{BASE_URL}/api/license/public-key", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-178", "PASS", "Successfully retrieved license public key.")
        else:
            print_result("TC-178", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-178", "FAIL", str(e))

def test_tc_179():
    """Analyst - View SMTP Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/smtp", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-179", "PASS", "Successfully retrieved SMTP settings.")
        else:
            print_result("TC-179", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-179", "FAIL", str(e))

def test_tc_180():
    """Analyst - View Client Errors"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/client-errors", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-180", "PASS", "Successfully retrieved client errors.")
        else:
            print_result("TC-180", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-180", "FAIL", str(e))


if __name__ == "__main__":
    print("Starting Automated Tests (TC-051 to TC-065)...")
    print("-" * 50)
    # Older tests commented out per instruction
    # test_tc_026()
    # test_tc_027()
    # test_tc_028()
    # test_tc_029()
    # test_tc_030()
    # test_tc_031()
    # test_tc_032()
    # test_tc_033()
    # test_tc_034()
    # test_tc_035()
    # test_tc_036()
    # test_tc_037()
    # test_tc_038()
    # test_tc_039()
    # test_tc_040()
    # test_tc_041()
    # test_tc_042()
    # test_tc_043()
    # test_tc_044()
    # test_tc_045()
    # test_tc_046()
    # test_tc_047()
    # test_tc_048()
    # test_tc_049()
    # test_tc_050()
    # print(f"Starting Automated Tests (TC-081 to TC-090)...")
    # print("-" * 50)
    
    # Execute the tests
    # test_tc_066()
    # test_tc_067()
    # test_tc_068()
    # test_tc_069()
    # test_tc_070()
    # test_tc_071()
    # test_tc_072()
    # test_tc_073()
    # test_tc_074()
    # test_tc_075()
    # test_tc_076()
    # test_tc_077()
    # test_tc_078()
    # test_tc_079()
    # test_tc_080()
    
    # test_tc_081()
    # test_tc_082()
    # test_tc_083()
    # test_tc_084()
    # test_tc_085()
    # test_tc_086()
    # test_tc_087()
    # test_tc_088()
    # test_tc_089()
    # test_tc_090()
    
    # print(f"Starting Analyst Automated Tests (TC-091 to TC-105)...")
    # print("-" * 50)
    
    # Dynamically fetch IDs
    # test_alert_id = "test-alert-id"
    # test_user_id = "test-user-id"
    # try:
    #     # We use sa_headers to fetch them so we are sure they exist
    #     alert_resp = requests.get(f"{BASE_URL}/api/xdr/alerts", headers=sa_headers, verify=False)
    #     if alert_resp.status_code == 200 and 'alerts' in alert_resp.json():
    #         alerts_list = alert_resp.json().get('alerts', [])
    #         if alerts_list:
    #             test_alert_id = alerts_list[0].get('alert_id', 'test-alert-id')
    #         
    #     user_resp = requests.get(f"{BASE_URL}/api/auth/users", headers=sa_headers, verify=False)
    #     if user_resp.status_code == 200 and 'users' in user_resp.json():
    #         users_list = user_resp.json().get('users', [])
    #         if users_list:
    #             test_user_id = users_list[0].get('id', 'test-user-id')
    #         
    #     print(f"[*] Dynamically loaded alert_id: {test_alert_id}")
    #     print(f"[*] Dynamically loaded user_id: {test_user_id}")
    # except Exception as e:
    #     print(f"[!] Warning: Could not fetch dynamic IDs. Using defaults. Error: {e}")
    # print("-" * 50)
    
    # test_tc_091()
    # test_tc_092(test_alert_id)
    # test_tc_093(test_alert_id)
    # test_tc_094(test_alert_id)
    # test_tc_095()
    # test_tc_096()
    # test_tc_097()
    # test_tc_098()
    # test_tc_099()
    # test_tc_100()
    # test_tc_101()
    # test_tc_102(test_alert_id)
    # test_tc_103()
    # test_tc_104(test_user_id)
    # test_tc_105(test_alert_id)

    # print(f"Starting New Analyst Tests (TC-106 to TC-120)...")
    # print("-" * 50)

    # test_tc_106()
    # test_tc_107()
    # test_tc_108()
    # test_tc_109()
    # test_tc_110()
    # test_tc_111()
    # test_tc_112()
    # test_tc_113()
    # test_tc_114()
    # test_tc_115()
    # test_tc_116()
    # test_tc_117()
    # test_tc_118()
    # test_tc_119()
    # test_tc_120()

    # print(f"Starting Analyst RBAC Negative Tests (TC-121 to TC-135)...")
    # print("-" * 50)
    # 
    # test_tc_121()
    # test_tc_122()
    # test_tc_123()
    # test_tc_124()
    # test_tc_125()
    # test_tc_126()
    # test_tc_127()
    # test_tc_128()
    # test_tc_129()
    # test_tc_130()
    # test_tc_131()
    # test_tc_132()
    # test_tc_133()
    # test_tc_134()
    # test_tc_135()

    # print(f"Starting Additional Analyst Action Tests (TC-136 to TC-150)...")
    # print("-" * 50)
    # 
    # test_case_id = "test-case-id"
    # test_rule_id = "test-rule-id"
    # test_block_id = "test-block-id"
    # test_iso_id = "test-iso-id"
    # # Execute the new tests
    # test_tc_136()
    # test_tc_137()
    # test_tc_138()
    # test_tc_139(test_case_id)
    # test_tc_140(test_case_id)
    # test_tc_141(test_case_id)
    # test_tc_142(test_case_id)
    # test_tc_143()
    # test_tc_144()
    # test_tc_145(test_block_id)
    # test_tc_146()
    # test_tc_147(test_iso_id)
    # test_tc_148()
    # test_tc_149()
    # test_tc_150(test_rule_id)

    # print(f"Starting Analyst View & Export Tests (TC-151 to TC-165)...")
    # print("-" * 50)
    # 
    # test_tc_151()
    # test_tc_152()
    # test_tc_153()
    # test_tc_154()
    # test_tc_155()
    # test_tc_156()
    # test_tc_157()
    # test_tc_158()
    # test_tc_159()
    # test_tc_160()
    # test_tc_161()
    # test_tc_162()
    # test_tc_163()
    # test_tc_164()
    # test_tc_165()

    print(f"Starting Analyst Profile, Rules & Integrations Tests (TC-166 to TC-180)...")
    print("-" * 50)
    
    test_rule_id = "test-rule-id"
    test_announcement_id = "1"
    
    test_tc_166()
    test_tc_167()
    test_tc_168()
    test_tc_169(test_announcement_id)
    test_tc_170()
    test_tc_171()
    test_tc_172()
    test_tc_173()
    test_tc_174(test_rule_id)
    test_tc_175()
    test_tc_176()
    test_tc_177()
    test_tc_178()
    test_tc_179()
    test_tc_180()

    print("-" * 50)
    print("Tests complete. Please record the results.")

