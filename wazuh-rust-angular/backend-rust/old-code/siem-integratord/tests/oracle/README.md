# wazuh-integratord oracle

* `run_scripts.sh` (WSL, Python 3 with `requests`): the original `integrations/*.py`
  of Wazuh 4.14.7 and the Rust `integrations` program run the same 24 cases
  (`scenarios.py`) against `fake_http.py` (HTTP endpoint + analysisd queue).
  Compared: every HTTP request (method, path, query, body, script headers), queue
  message, stdout, `logs/integrations.log`, the last traceback line and the exit code.
  The vendor URLs (PagerDuty, VirusTotal) point at the fake server: the Python copy
  is edited, the Rust program reads `SIEM_INTEGRATIONS_URL_OVERRIDE`.
* `loop.sh <wazuh-integratord> debug|nodebug` (root; the daemons drop to `nobody`):
  the real C daemon (`build.sh`) and the Rust one on the same alerts
  (`intg_alerts.py`) with recording `custom-*` scripts; the script calls (argv, alert
  file in json and legacy format, options file) and the log are compared.

2026-10-17: scripts 24/24 identical; daemon: 9/9 script calls identical in both
modes, non-debug log identical, debug log identical except when the socket
thread prints "Local requests thread ready" (thread timing).
