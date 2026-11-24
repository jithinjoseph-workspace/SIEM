#!/usr/bin/env python3
"""NDR Test Case Tracker — ISTQB/IEEE-829-style Excel tracker.

Behaviour:
  - First run  : creates NDR_Test_Case_Tracker.xlsx from scratch with all
                 sheets (Test Cases, Legend, Summary).
  - Re-runs    : opens the EXISTING file and APPENDS only test cases whose
                 TC ID is not already present — existing results, status,
                 and remarks are preserved.

Add new test cases to the ROWS list below and re-run to append them.
"""

import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule
from openpyxl.utils import get_column_letter

OUT_PATH = r"C:\NDRSiem\qa\NDR_Test_Case_Tracker.xlsx"

HEADERS = [
    "Test Case ID", "Module / Feature", "Test Scenario", "Test Case Title",
    "Description", "Preconditions", "Test Steps / Script", "Test Data",
    "Expected Result", "Actual Result", "Status", "Priority",
    "Executed By", "Execution Date", "Defect ID / Remarks",
]

COL_WIDTHS = [12, 18, 22, 26, 34, 24, 42, 22, 32, 32, 12, 10, 14, 14, 22]

# Starter set drawn from real issues found/fixed on this project — replace
# or extend freely; this just proves the format and seeds real coverage.
ROWS = [
    # ── Super Admin Role Test Cases — Batch 2 (TC-019 – TC-025) ───────────
    ("TC-019", "Tenant Management", "Super Admin permanently deletes a tenant",
     "DELETE /api/admin/tenants/:id removes the tenant and all its users",
     "Verify that a super_admin can hard-delete a tenant organisation, which must "
     "cascade-remove all users, roles, and data belonging to that tenant, and that "
     "any active sessions of those users are immediately invalidated.",
     "A disposable test tenant with at least one user and active session exists; "
     "authenticated as super_admin",
     "1. Note the tenant_id and one of its user session tokens\n"
     "2. DELETE /api/admin/tenants/:id as super_admin\n"
     "3. Confirm HTTP 200/204 response\n"
     "4. GET /api/admin/tenants/:id — confirm 404\n"
     "5. Attempt an API call using the deleted tenant user's session token",
     "tenant_id of the disposable test tenant",
     "HTTP 200/204 on delete; tenant returns 404; all tenant users are removed; "
     "existing session tokens for those users return 401 Unauthorized",
     "", "Not Executed", "Critical", "", "", ""),

    ("TC-020", "User Management", "Super Admin force-revokes all sessions of a user",
     "POST /api/admin/users/:id/revoke-sessions invalidates every active token",
     "Verify that super_admin can force-logout any user across all devices by "
     "revoking their active sessions — critical for incident response when an "
     "account is suspected to be compromised.",
     "Target user is logged in on at least one device (active JWT exists); "
     "authenticated as super_admin",
     "1. Obtain a valid session token for the target user\n"
     "2. POST /api/admin/users/:id/revoke-sessions as super_admin\n"
     "3. Confirm HTTP 200\n"
     "4. Attempt an API call using the old target-user token",
     "target user_id; existing JWT of that user",
     "HTTP 200 on revoke; subsequent API calls with the old token return "
     "401 Unauthorized; user must re-authenticate to continue",
     "", "Not Executed", "Critical", "", "", ""),

    ("TC-021", "Tenant Management", "Super Admin enables a feature flag for a specific tenant",
     "PATCH /api/admin/tenants/:id/features toggles a feature on/off per tenant",
     "Verify that super_admin can enable or disable a named feature flag "
     "(e.g. 'advanced_threat_map') for one tenant without affecting others — "
     "confirming per-tenant feature gating works correctly.",
     "At least 2 tenants exist; 'advanced_threat_map' feature flag is available; "
     "authenticated as super_admin",
     "1. PATCH /api/admin/tenants/:id/features {feature:'advanced_threat_map', enabled:true}\n"
     "2. Log in as a user of that tenant — confirm the feature is visible/accessible\n"
     "3. Log in as a user of a DIFFERENT tenant — confirm the feature is NOT visible",
     "tenant_id of target tenant; feature='advanced_threat_map'",
     "Feature is enabled only for the target tenant; other tenants are unaffected; "
     "the UI reflects the flag correctly for each tenant",
     "", "Not Executed", "High", "", "", ""),

    ("TC-022", "Audit & Compliance", "Super Admin exports full audit log as CSV/JSON",
     "GET /api/admin/audit-logs/export downloads a complete cross-tenant log file",
     "Verify that super_admin can trigger a bulk export of the audit log spanning "
     "all tenants within a specified date range, and that the exported file is "
     "complete and correctly formatted.",
     "Audit log entries exist across multiple tenants; authenticated as super_admin",
     "1. GET /api/admin/audit-logs/export?from=<date>&to=<date>&format=csv\n"
     "2. Confirm HTTP 200 and Content-Type: text/csv (or application/json)\n"
     "3. Open the downloaded file and verify it contains records from multiple tenants\n"
     "4. Confirm the date range filter is respected",
     "from=2026-01-01, to=2026-09-09, format=csv",
     "HTTP 200; file downloads successfully; records span multiple tenants; "
     "entries outside the date range are excluded",
     "", "Not Executed", "High", "", "", ""),

    ("TC-023", "System Configuration", "Super Admin assigns super_admin role to another user",
     "Promoting a user to super_admin grants full system-wide privileges",
     "Verify that a super_admin can elevate an existing user to the super_admin "
     "role via PATCH /api/auth/users/:id/role, and that the promoted user "
     "immediately gains full cross-tenant access without needing to re-login.",
     "A target user with a lower role (e.g. tenant_admin) exists; "
     "authenticated as super_admin",
     "1. PATCH /api/auth/users/:id/role {role:'super_admin'} as super_admin\n"
     "2. Confirm HTTP 200\n"
     "3. Using the target user's existing session, call GET /api/admin/tenants\n"
     "4. Confirm the response now returns all tenants",
     "target user_id (currently tenant_admin); new role='super_admin'",
     "HTTP 200; target user's existing session reflects new role; "
     "GET /api/admin/tenants returns all tenants for that user",
     "", "Not Executed", "Critical", "", "", ""),

    ("TC-024", "System Monitoring", "Super Admin views real-time system health dashboard",
     "GET /api/admin/health returns live metrics for all services",
     "Verify that super_admin can access a system health endpoint that reports "
     "live status of all core services (ndr-engine, auth-service, database, "
     "message queue) and that tenant_admin is denied access.",
     "All core services are running; authenticated as super_admin",
     "1. GET /api/admin/health as super_admin\n"
     "2. Confirm HTTP 200 and response includes status for each service\n"
     "3. Check for fields: service name, status (up/down), latency, uptime\n"
     "4. Repeat request as tenant_admin and confirm 403",
     "N/A",
     "Super Admin: HTTP 200 with per-service health data. "
     "Tenant Admin: HTTP 403 Forbidden. "
     "All running services report status='up'",
     "", "Not Executed", "Medium", "", "", ""),

    ("TC-025", "Auth / Access Control", "Super Admin enforces concurrent session limit per user",
     "Oldest session is invalidated when a user exceeds the max concurrent sessions",
     "Verify that when a user logs in beyond the configured max_concurrent_sessions "
     "limit (set by super_admin via global config), the oldest session is "
     "automatically revoked — preventing credential sharing.",
     "max_concurrent_sessions is set to 2 via global config (TC-017 pattern); "
     "a test user account exists",
     "1. Log in as the test user on Device A — obtain Token-A\n"
     "2. Log in as the same user on Device B — obtain Token-B\n"
     "3. Log in as the same user on Device C — obtain Token-C\n"
     "4. Attempt an API call using Token-A",
     "max_concurrent_sessions=2; same user credentials on 3 devices",
     "Token-C is issued successfully; Token-A (oldest) is invalidated and returns "
     "401 on subsequent use; Token-B remains valid",
     "", "Not Executed", "High", "", "", ""),
]

STATUS_COLORS = {
    "Passed":       "C6EFCE",
    "Failed":       "FFC7CE",
    "Blocked":      "FFEB9C",
    "Not Executed": "D9D9D9",
}

def style_header(ws, ncols):
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(color="FFFFFF", bold=True, size=10)
    thin = Side(style="thin", color="B7B7B7")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c in range(1, ncols + 1):
        cell = ws.cell(row=1, column=c)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = border
    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 30


def build_test_cases_sheet(wb):
    ws = wb.active
    ws.title = "Test Cases"
    ws.append(HEADERS)
    style_header(ws, len(HEADERS))

    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical="top")

    for row in ROWS:
        ws.append(row)

    for i, w in enumerate(COL_WIDTHS, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

    last_row = ws.max_row
    for r in range(2, last_row + 1):
        ws.row_dimensions[r].height = 60
        for c in range(1, len(HEADERS) + 1):
            cell = ws.cell(row=r, column=c)
            cell.alignment = wrap
            cell.border = border

    # Data validation dropdowns
    status_dv = DataValidation(
        type="list",
        formula1='"Passed,Failed,Blocked,Not Executed"',
        allow_blank=True, showDropDown=False,
    )
    ws.add_data_validation(status_dv)
    status_dv.add(f"K2:K{max(last_row, 500)}")

    priority_dv = DataValidation(
        type="list",
        formula1='"Critical,High,Medium,Low"',
        allow_blank=True, showDropDown=False,
    )
    ws.add_data_validation(priority_dv)
    priority_dv.add(f"L2:L{max(last_row, 500)}")

    # Conditional formatting on Status column
    status_col = "K"
    rng = f"{status_col}2:{status_col}{max(last_row, 500)}"
    for value, color in STATUS_COLORS.items():
        fill = PatternFill("solid", fgColor=color)
        ws.conditional_formatting.add(
            rng,
            CellIsRule(operator="equal", formula=[f'"{value}"'], fill=fill),
        )

    return ws


def build_legend_sheet(wb):
    ws = wb.create_sheet("Legend & Format Guide")
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 90

    title = ws.cell(row=1, column=1, value="Test Case Tracker — Format Guide")
    title.font = Font(bold=True, size=14, color="1F4E78")
    ws.merge_cells("A1:B1")

    rows = [
        ("Standard followed", "ISTQB / IEEE 829 style test case specification — the same shape "
         "used by TestRail, Zephyr, qTest, and most enterprise QA teams."),
        ("", ""),
        ("Column", "Meaning"),
        ("Test Case ID", "Unique, sequential, never reused (TC-001, TC-002, ...). "
         "Referenced from bug reports and traceability matrices."),
        ("Module / Feature", "Which part of the product this covers (Alerts, SOAR, Rules, Auth, ...)."),
        ("Test Scenario", "The high-level behavior under test — one scenario can have several "
         "test cases (happy path, edge case, negative case)."),
        ("Test Case Title", "Short, specific, searchable name for this exact case."),
        ("Description", "What is being verified and why it matters."),
        ("Preconditions", "State that must exist before running this case (login, data seeded, etc.)."),
        ("Test Steps / Script", "Numbered, reproducible steps — or an actual script/command block "
         "when the case is automatable (curl, API call, CLI command)."),
        ("Test Data", "Concrete inputs used for this run (specific IP, payload, username, etc.)."),
        ("Expected Result", "What should happen if the feature works correctly."),
        ("Actual Result", "What actually happened — filled in during execution, not in advance."),
        ("Status", "Passed / Failed / Blocked / Not Executed. Blocked = couldn't run "
         "(e.g. dependency broken or feature not built yet), distinct from Failed."),
        ("Priority", "Critical / High / Medium / Low — drives what gets fixed/retested first."),
        ("Executed By", "Tester name — accountability + who to ask about the result."),
        ("Execution Date", "When the case was actually run (not authored)."),
        ("Defect ID / Remarks", "Link/ID to the bug tracker entry if Failed, or free-text notes."),
        ("", ""),
        ("Workflow", "1) Write cases before testing (Status = Not Executed). "
         "2) Execute and fill Actual Result + Status + Executed By + Date as you go. "
         "3) File a defect for every Failed case and record its ID here. "
         "4) Re-run failed cases after a fix ships — same row, update Status, "
         "keep the old Actual Result in Remarks if useful for history."),
    ]
    r = 3
    for label, text in rows:
        c1 = ws.cell(row=r, column=1, value=label)
        c2 = ws.cell(row=r, column=2, value=text)
        c1.font = Font(bold=label in ("Column", "Standard followed", "Workflow"))
        c2.alignment = Alignment(wrap_text=True, vertical="top")
        c1.alignment = Alignment(vertical="top")
        ws.row_dimensions[r].height = 34 if text else 8
        r += 1


def build_summary_sheet(wb):
    ws = wb.create_sheet("Summary", 0)  # first tab
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 14

    ws["A1"] = "NDR Test Execution Summary"
    ws["A1"].font = Font(bold=True, size=14, color="1F4E78")
    ws.merge_cells("A1:B1")

    labels = ["Total Test Cases", "Passed", "Failed", "Blocked", "Not Executed", "Pass Rate"]
    formulas = [
        '=COUNTA(\'Test Cases\'!A2:A1000)-COUNTBLANK(\'Test Cases\'!A2:A1000)',
        "=COUNTIF('Test Cases'!K2:K1000,\"Passed\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Failed\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Blocked\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Not Executed\")",
        '=IFERROR(B3/B2,"n/a")',
    ]
    r = 3
    for label, formula in zip(labels, formulas):
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        cell = ws.cell(row=r, column=2, value=formula)
        if label == "Pass Rate":
            cell.number_format = "0.0%"
        r += 1

    ws["A10"] = "Tip: this sheet updates automatically as you fill in Status on the Test Cases tab."
    ws["A10"].font = Font(italic=True, color="808080")
    ws.merge_cells("A10:D10")


def append_new_rows(wb):
    """Append only ROWS entries whose TC ID is not already in the sheet."""
    ws = wb["Test Cases"]

    # Collect TC IDs that already exist
    existing_ids = set()
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=1, max_col=1):
        for cell in row:
            if cell.value:
                existing_ids.add(str(cell.value).strip())

    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical="top")

    added = []
    for row_data in ROWS:
        tc_id = str(row_data[0]).strip()
        if tc_id in existing_ids:
            continue  # already present — skip to preserve existing results
        ws.append(row_data)
        r = ws.max_row
        ws.row_dimensions[r].height = 60
        for c in range(1, len(HEADERS) + 1):
            cell = ws.cell(row=r, column=c)
            cell.alignment = wrap
            cell.border = border
        added.append(tc_id)

    if added:
        print(f"Appended {len(added)} new test case(s): {', '.join(added)}")
    else:
        print("No new test cases to append — all TC IDs already exist in the sheet.")


def main():
    if os.path.exists(OUT_PATH):
        # File exists — open and append only new rows
        print(f"Existing file found: {OUT_PATH}")
        wb = openpyxl.load_workbook(OUT_PATH)
        if "Test Cases" not in wb.sheetnames:
            print("WARNING: 'Test Cases' sheet not found — rebuilding from scratch.")
            wb = openpyxl.Workbook()
            build_test_cases_sheet(wb)
            build_legend_sheet(wb)
            build_summary_sheet(wb)
            wb.active = 0
        else:
            append_new_rows(wb)
    else:
        # Fresh start — build everything
        print("No existing file found — creating from scratch.")
        wb = openpyxl.Workbook()
        build_test_cases_sheet(wb)
        build_legend_sheet(wb)
        build_summary_sheet(wb)
        wb.active = 0

    wb.save(OUT_PATH)
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
