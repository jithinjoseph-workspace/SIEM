//! The vulnerability report as an Excel workbook, `GET /api/v1/vulnerabilities/report.xlsx`:
//! a Summary sheet and the detections, scoped like `/api/v1/vulnerabilities`.
//!
//! Every text in it is external data (CVE feed, agent and package names): cells go through
//! `write_string`, so a value starting with `=`, `+`, `-` or `@` stays text, never a formula.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::extract::{Extension, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rust_xlsxwriter::{DataValidation, Format, FormatAlign, Formula, Url, Workbook, Worksheet, XlsxError};
use serde::Deserialize;

use crate::tenancy::{self, AuthCtx};
use crate::vulnerability::VulnItem;
use crate::AppState;

const RISK: [(&str, u32); 4] = [("Critical", 0xFF0000), ("High", 0xFF6600), ("Medium", 0xFFC000), ("Low", 0x92D050)];
const STATUS: [&str; 5] = ["Open", "In Progress", "Fixed", "False Positive", "Accepted Risk"];
/// Above this many agents: one Details sheet instead of one per agent.
const MAX_SHEETS: usize = 200;
/// Excel's rows per sheet, less the header.
const MAX_ROWS: usize = 1_048_575;
/// Excel's limits: links in a sheet, characters in a cell, characters in a link.
const MAX_LINKS: u32 = 65_530;
const MAX_CELL: usize = 32_767;
const MAX_URL: usize = 2_000;

/// Key in `columns=`, header, width.
type Column = (&'static str, &'static str, f64);
static COLUMNS: [Column; 16] = [
    ("risk", "Risk", 12.0),
    ("cve", "CVE ID", 18.0),
    ("title", "Vulnerability Title", 43.0),
    ("description", "Description", 65.0),
    ("cvss", "CVSS Score", 10.0),
    ("agent", "Agent", 22.0),
    ("package", "Package", 32.0),
    ("installed", "Installed Version", 16.0),
    ("fixed", "Fixed Version", 16.0),
    ("location", "Location", 49.0),
    ("recommendation", "Recommendation", 49.0),
    ("published", "Published", 14.0),
    ("detected", "Detected", 14.0),
    ("reference", "Reference", 40.0),
    ("check", "Check", 22.0),
    ("status", "Status", 15.0),
];

#[derive(Deserialize)]
pub struct ReportParams {
    agents: Option<String>,
    severity: Option<String>,
    columns: Option<String>,
}

/// One agent of the report and its detections per risk (in `RISK` order).
struct AgentLine {
    id: String,
    name: String,
    os: String,
    counts: [u32; 4],
}

impl AgentLine {
    fn label(&self) -> String {
        if self.name.is_empty() { self.id.clone() } else { format!("{} ({})", self.name, self.id) }
    }
}

struct Formats {
    body: Format,
    wrap: Format,
    link: Format,
    head: Format,
    risk: [Format; 4],
}

fn base() -> Format {
    Format::new().set_font_name("Aptos").set_font_size(11).set_align(FormatAlign::Top)
}

fn risk_index(severity: &str) -> Option<usize> {
    RISK.iter().position(|(n, _)| n.eq_ignore_ascii_case(severity))
}

fn list(v: Option<&str>) -> BTreeSet<&str> {
    v.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()).collect()
}

fn pick_columns(names: &str) -> Result<Vec<&'static Column>, String> {
    if names.trim().is_empty() {
        return Ok(COLUMNS.iter().collect());
    }
    names.split(',').map(str::trim).map(|n| COLUMNS.iter().find(|c| c.0 == n).ok_or_else(|| format!("Unknown column: {n}"))).collect()
}

/// `agent_in_scope` for every named agent, from one read of the tenant map.
fn all_in_scope(wanted: &BTreeSet<&str>, tenants: &HashMap<String, String>, scope: &str) -> bool {
    wanted.iter().all(|a| tenancy::tenant_of(tenants, a) == scope)
}

/// The agents of the report, most critical first; named agents stay in with no detections.
fn agent_lines(rows: &[VulnItem], named: Vec<AgentLine>) -> Vec<AgentLine> {
    let mut by_id: BTreeMap<String, AgentLine> = named.into_iter().map(|a| (a.id.clone(), a)).collect();
    for v in rows {
        let a = by_id.entry(v.agent_id.clone()).or_insert_with(|| AgentLine { id: v.agent_id.clone(), name: String::new(), os: String::new(), counts: [0; 4] });
        if a.name.is_empty() {
            a.name.clone_from(&v.agent_name);
        }
        if a.os.is_empty() {
            a.os.clone_from(&v.os);
        }
        if let Some(i) = risk_index(&v.severity) {
            a.counts[i] += 1;
        }
    }
    let mut lines: Vec<AgentLine> = by_id.into_values().collect();
    lines.sort_by(|a, b| (b.counts[0], b.counts[1]).cmp(&(a.counts[0], a.counts[1])).then_with(|| a.name.cmp(&b.name)));
    lines
}

fn file_name(lines: &[AgentLine], date: &str) -> String {
    let who = match lines {
        // an agent's own name: it ends up in a response header
        [a] => (if a.name.is_empty() { &a.id } else { &a.name }).chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' }).collect(),
        _ => "Fleet".to_string(),
    };
    format!("ProVigil-Vulnerabilities-{who}-{date}.xlsx")
}

/// A name Excel accepts as a sheet: no `[]:*?/\`, no outer apostrophes, 31 characters, unique
/// ignoring case. `seen` holds the lower-case names already taken.
fn sheet_name(name: &str, seen: &mut HashSet<String>) -> String {
    let clean: String = name.chars().map(|c| if "[]:*?/\\".contains(c) || c.is_control() { '_' } else { c }).collect();
    let clean = clean.trim_matches('\'');
    let clean = if clean.is_empty() { "Agent" } else { clean };
    let mut n = 1;
    loop {
        let suffix = if n == 1 { String::new() } else { format!(" ({n})") };
        let cut: String = clean.chars().take(31 - suffix.len()).collect();
        let candidate = format!("{}{suffix}", cut.trim_end_matches('\''));
        if seen.insert(candidate.to_lowercase()) {
            return candidate;
        }
        n += 1;
    }
}

/// The address behind a CVE ID. The feed lists references separated by `, `: the first is
/// the link. Only web addresses: the field is external, and a link Excel follows must not
/// reach a file or a program.
fn link_of(reference: &str) -> Option<&str> {
    let first = reference.split([',', ' ']).next()?;
    (first.len() <= MAX_URL && (first.starts_with("https://") || first.starts_with("http://"))).then_some(first)
}

fn text(ws: &mut Worksheet, row: u32, col: u16, value: &str, format: &Format) -> Result<(), XlsxError> {
    let value = match value.char_indices().nth(MAX_CELL) {
        Some((end, _)) => &value[..end],
        None => value,
    };
    ws.write_string_with_format(row, col, value, format).map(drop)
}

fn cell(ws: &mut Worksheet, row: u32, col: u16, key: &str, v: &VulnItem, f: &Formats) -> Result<(), XlsxError> {
    let date = |d: &'_ str| -> Cow<'_, str> { d.get(..10).unwrap_or(d).to_string().into() };
    let (value, format): (Cow<str>, &Format) = match key {
        "risk" => (v.severity.as_str().into(), risk_index(&v.severity).map_or(&f.body, |i| &f.risk[i])),
        "cve" => {
            if let Some(url) = link_of(&v.reference).filter(|_| row <= MAX_LINKS) {
                return ws.write_url_with_options(row, col, Url::new(url), v.cve.as_str(), "", Some(&f.link)).map(drop);
            }
            (v.cve.as_str().into(), &f.body)
        }
        // -1 while under evaluation
        "cvss" if v.cvss_score < 0.0 => return ws.write_blank(row, col, &f.body).map(drop),
        "cvss" => return ws.write_number_with_format(row, col, v.cvss_score, &f.body).map(drop),
        "title" => (v.title.as_str().into(), &f.wrap),
        "description" => (v.description.as_str().into(), &f.wrap),
        "agent" => (format!("{} ({})", v.agent_name, v.agent_id).into(), &f.body),
        "package" => (v.package_name.as_str().into(), &f.body),
        "installed" => (v.installed_version.as_str().into(), &f.body),
        "fixed" => (v.fixed_version.as_deref().unwrap_or("").into(), &f.body),
        "location" => (v.package_path.as_str().into(), &f.wrap),
        "recommendation" => (
            match &v.fixed_version {
                Some(x) => format!("Update {} to {x} or later.", v.package_name).into(),
                None => "No fixed version listed; check the vendor.".into(),
            },
            &f.wrap,
        ),
        "published" => (date(&v.published_at), &f.body),
        "detected" => (date(&v.detected_at), &f.body),
        "reference" => (v.reference.as_str().into(), &f.wrap),
        "check" => (if v.needs_review { "Verify: version numbering differs" } else { "" }.into(), &f.body),
        _ => (STATUS[0].into(), &f.body),
    };
    text(ws, row, col, &value, format)
}

fn details(ws: &mut Worksheet, cols: &[&Column], rows: &[&VulnItem], f: &Formats) -> Result<(), XlsxError> {
    for (c, (_, head, width)) in cols.iter().copied().enumerate() {
        ws.set_column_width(c as u16, *width)?;
        ws.write_string_with_format(0, c as u16, *head, &f.head)?;
    }
    for (r, v) in rows.iter().enumerate() {
        for (c, col) in cols.iter().enumerate() {
            cell(ws, r as u32 + 1, c as u16, col.0, v, f)?;
        }
    }
    let last = rows.len() as u32;
    ws.set_freeze_panes(1, 0)?;
    ws.autofilter(0, 0, last, cols.len() as u16 - 1)?;
    if let Some(c) = cols.iter().position(|c| c.0 == "status").filter(|_| last > 0) {
        ws.add_data_validation(1, c as u16, last, c as u16, &DataValidation::new().allow_list_strings(&STATUS)?)?;
    }
    Ok(())
}

fn summary(ws: &mut Worksheet, rows: &[VulnItem], lines: &[AgentLine], generated_at: &str) -> Result<(), XlsxError> {
    let head = base().set_bold().set_background_color(0xD0CECE);
    let bold = base().set_bold();
    let plain = base();
    let fill = RISK.map(|(_, color)| base().set_background_color(color));
    ws.set_column_width(0, 30)?;
    ws.set_column_width(1, 14)?;
    ws.write_string_with_format(0, 0, "Risk", &head)?;
    ws.write_string_with_format(0, 1, "Total", &head)?;
    let mut total = 0;
    for (i, (name, _)) in RISK.iter().enumerate() {
        let n: u32 = lines.iter().map(|a| a.counts[i]).sum();
        total += n;
        ws.write_string_with_format(i as u32 + 1, 0, *name, &fill[i])?;
        ws.write_number_with_format(i as u32 + 1, 1, n, &plain)?;
    }
    ws.write_string_with_format(5, 0, "Total", &bold)?;
    // the stored result: viewers that do not calculate show it
    ws.write_formula_with_format(5, 1, Formula::new("=SUM(B2:B5)").set_result(total.to_string()), &bold)?;

    let oses: BTreeSet<&str> = lines.iter().map(|a| a.os.as_str()).filter(|o| !o.is_empty()).collect();
    let who = match lines {
        [a] => a.label(),
        _ => format!("{} agents", lines.len()),
    };
    let os = oses.into_iter().collect::<Vec<_>>().join(", ");
    let mut row = 7;
    for (k, v) in [("Agent(s)", who.as_str()), ("OS", os.as_str()), ("Generated at", generated_at)] {
        ws.write_string_with_format(row, 0, k, &bold)?;
        text(ws, row, 1, v, &plain)?;
        row += 1;
    }
    // detections without a score are not in the risk table above, but they are in Details
    let unrated = rows.iter().filter(|v| risk_index(&v.severity).is_none()).count();
    if unrated > 0 {
        ws.write_string_with_format(row, 0, "Not rated yet", &bold)?;
        ws.write_number_with_format(row, 1, unrated as u32, &plain)?;
        row += 1;
    }
    ws.write_string_with_format(row, 0, "Report by ProVigil", &plain)?;
    row += 2;

    if lines.len() > 1 {
        for (c, h) in ["Agent", "Critical", "High", "Medium", "Low", "Total"].iter().enumerate() {
            ws.write_string_with_format(row, c as u16, *h, &head)?;
        }
        for (r, a) in lines.iter().enumerate() {
            let r = row + 1 + r as u32;
            text(ws, r, 0, &a.label(), &plain)?;
            for (c, n) in a.counts.iter().enumerate() {
                ws.write_number_with_format(r, c as u16 + 1, *n, &plain)?;
            }
            ws.write_number_with_format(r, 5, a.counts.iter().sum::<u32>(), &plain)?;
        }
    }
    Ok(())
}

fn build(mut rows: Vec<VulnItem>, lines: &[AgentLine], mut cols: Vec<&'static Column>, generated_at: &str) -> Result<Vec<u8>, XlsxError> {
    rows.sort_by(|a, b| b.cvss_score.total_cmp(&a.cvss_score).then_with(|| a.cve.cmp(&b.cve)));
    if lines.len() == 1 && cols.len() > 1 {
        cols.retain(|c| c.0 != "agent");
    }
    let f = Formats {
        body: base(),
        wrap: base().set_text_wrap(),
        link: base().set_hyperlink(),
        head: base().set_bold().set_font_color(0xFFFFFF).set_background_color(0x7030A0).set_align(FormatAlign::Center),
        risk: RISK.map(|(_, color)| base().set_background_color(color)),
    };
    let mut wb = Workbook::new();
    summary(wb.add_worksheet().set_name("Summary")?, &rows, lines, generated_at)?;
    if lines.len() < 2 || lines.len() > MAX_SHEETS {
        details(wb.add_worksheet().set_name("Details")?, &cols, &rows.iter().collect::<Vec<_>>(), &f)?;
    } else {
        let mut by_agent: HashMap<&str, Vec<&VulnItem>> = HashMap::new();
        for v in &rows {
            by_agent.entry(&v.agent_id).or_default().push(v);
        }
        // "History" is reserved by Excel
        let mut seen = HashSet::from(["summary".to_string(), "history".to_string()]);
        for a in lines {
            let name = sheet_name(if a.name.is_empty() { &a.id } else { &a.name }, &mut seen);
            details(wb.add_worksheet().set_name(name)?, &cols, by_agent.get(a.id.as_str()).map_or(&[], Vec::as_slice), &f)?;
        }
    }
    wb.save_to_buffer()
}

fn refuse(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "status": "error", "message": message }))).into_response()
}

/// `GET /api/v1/vulnerabilities/report.xlsx?agents=079,080&severity=critical,high&columns=...`
pub async fn get_report(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(p): Query<ReportParams>) -> Response {
    let cols = match pick_columns(p.columns.as_deref().unwrap_or("")) {
        Ok(c) => c,
        Err(m) => return refuse(StatusCode::BAD_REQUEST, m),
    };
    let severities = list(p.severity.as_deref());
    if let Some(s) = severities.iter().find(|s| risk_index(s).is_none()) {
        return refuse(StatusCode::BAD_REQUEST, format!("Unknown severity: {s}"));
    }
    let wanted = list(p.agents.as_deref());
    if !all_in_scope(&wanted, &state.agent_tenants.read().unwrap(), &ctx.scope()) {
        return tenancy::forbidden();
    }
    let one = wanted.first().copied().filter(|_| wanted.len() == 1);
    let mut rows = match crate::scoped_vulnerabilities(&state, &ctx, one).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    rows.retain(|v| (wanted.is_empty() || wanted.contains(v.agent_id.as_str())) && (severities.is_empty() || severities.iter().any(|s| s.eq_ignore_ascii_case(&v.severity))));
    if rows.len() > MAX_ROWS {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, format!("{} detections do not fit a sheet: narrow the agents or severities", rows.len()));
    }
    let named = {
        let known = state.agents.read().unwrap();
        wanted.iter().map(|id| AgentLine { id: id.to_string(), name: known.get(*id).map(|a| a.name.clone()).unwrap_or_default(), os: known.get(*id).map(|a| a.os.clone()).unwrap_or_default(), counts: [0; 4] }).collect()
    };
    let lines = agent_lines(&rows, named);
    let now = chrono::Utc::now();
    let file = file_name(&lines, &now.format("%Y-%m-%d").to_string());
    let at = now.format("%Y-%m-%d %H:%M UTC").to_string();
    // a fleet workbook takes seconds of CPU: not on the async workers
    match tokio::task::spawn_blocking(move || build(rows, &lines, cols, &at)).await {
        Ok(Ok(bytes)) => ([(header::CONTENT_TYPE, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\""))], bytes).into_response(),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("the report could not be built: {e}")),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("the report could not be built: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn item(agent: &str, name: &str, cve: &str, sev: &str, score: f64) -> VulnItem {
        VulnItem {
            cve: cve.into(),
            title: format!("{cve} affects curl"),
            severity: sev.into(),
            cvss_score: score,
            package_name: "curl".into(),
            installed_version: "1.0".into(),
            fixed_version: Some("1.2".into()),
            agent_id: agent.into(),
            agent_name: name.into(),
            status: "active".into(),
            detected_at: "2026-11-05T10:00:00Z".into(),
            description: "A flaw".into(),
            reference: "https://nvd.example/1, https://other.example/2".into(),
            category: "Packages".into(),
            os: "Windows 11".into(),
            package_path: "C:\\curl".into(),
            published_at: "2026-01-02T00:00:00Z".into(),
            needs_review: false,
        }
    }

    fn workbook(rows: Vec<VulnItem>, cols: &str) -> Vec<u8> {
        let lines = agent_lines(&rows, Vec::new());
        build(rows, &lines, pick_columns(cols).unwrap(), "2026-11-05 10:00 UTC").unwrap()
    }

    fn part(book: &[u8], name: &str) -> String {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(book)).unwrap();
        let mut out = String::new();
        zip.by_name(name).unwrap().read_to_string(&mut out).unwrap();
        out
    }

    fn data_rows(sheet: &str) -> usize {
        sheet.matches("<row ").count() - 1
    }

    #[test]
    fn fleet_workbook_read_back() {
        let mut risky = item("079", "web", "CVE-3", "Critical", 9.8);
        risky.needs_review = true;
        let rows = vec![item("079", "web", "CVE-1", "High", 7.5), risky, item("080", "db", "CVE-1", "Low", 2.0), item("080", "db", "CVE-2", "-", -1.0)];
        let book = workbook(rows, "");
        let wb = part(&book, "xl/workbook.xml");
        assert!(wb.contains("name=\"Summary\"") && wb.contains("name=\"web\"") && wb.contains("name=\"db\""), "{wb}");

        let summary = part(&book, "xl/worksheets/sheet1.xml");
        assert!(summary.contains("<f>SUM(B2:B5)</f><v>3</v>"), "{summary}");
        let strings = part(&book, "xl/sharedStrings.xml");
        for s in ["Risk", "Generated at", "Report by ProVigil", "Not rated yet", "web (079)", "db (080)", "2 agents", "Update curl to 1.2 or later.", "Verify: version numbering differs"] {
            assert!(strings.contains(s), "{s}");
        }
        // one row per CVE, highest CVSS first; the sheet of `web` comes first (most critical)
        let web = part(&book, "xl/worksheets/sheet2.xml");
        assert_eq!(data_rows(&web), 2);
        assert_eq!(data_rows(&part(&book, "xl/worksheets/sheet3.xml")), 2);
        let order = |s: &str| strings[..strings.find(s).unwrap()].matches("<si>").count();
        assert!(web.find(&format!("<v>{}</v>", order("CVE-3"))).unwrap() < web.find(&format!("<v>{}</v>", order("CVE-1"))).unwrap());
        assert!(web.contains("<pane ySplit=\"1\"") && web.contains("<autoFilter ref=\"A1:P3\""), "{web}");
        assert!(web.contains("<dataValidation") && web.contains("sqref=\"P2:P3\"") && web.contains("Open,In Progress,Fixed,False Positive,Accepted Risk"), "{web}");
        for head in COLUMNS.iter().map(|c| c.1) {
            assert!(strings.contains(&format!(">{head}<")), "{head}");
        }
        let styles = part(&book, "xl/styles.xml");
        for color in ["FF7030A0", "FFD0CECE", "FFFF0000", "FFFF6600", "FFFFC000", "FF92D050", "Aptos"] {
            assert!(styles.contains(color), "{color}");
        }
    }

    #[test]
    fn single_agent_has_details_and_no_agent_column() {
        let book = workbook(vec![item("079", "web", "CVE-1", "High", 7.5)], "");
        assert!(part(&book, "xl/workbook.xml").contains("name=\"Details\""));
        assert!(!part(&book, "xl/sharedStrings.xml").contains(">Agent<"));
        assert!(part(&book, "xl/worksheets/sheet2.xml").contains("ref=\"A1:O2\""), "15 columns");
    }

    #[test]
    fn many_agents_share_one_details_sheet() {
        let rows: Vec<VulnItem> = (0..=MAX_SHEETS).map(|i| item(&format!("{i:03}"), &format!("pc{i}"), "CVE-1", "Low", 2.0)).collect();
        let book = workbook(rows, "");
        assert_eq!(part(&book, "xl/workbook.xml").matches("<sheet ").count(), 2);
        assert_eq!(data_rows(&part(&book, "xl/worksheets/sheet2.xml")), MAX_SHEETS + 1);
        assert!(part(&book, "xl/sharedStrings.xml").contains("pc7 (007)"));
    }

    #[test]
    fn hostile_text_stays_text() {
        let mut v = item("079", "web", "=cmd|'/c calc'!A0", "High", 7.5);
        v.title = "+1+1".into();
        v.description = "@SUM(A1)".into();
        v.package_name = "-2+3".into();
        v.reference = "javascript:alert(1)".into();
        let book = workbook(vec![v], "");
        let sheet = part(&book, "xl/worksheets/sheet2.xml");
        assert!(!sheet.contains("<f>"), "{sheet}");
        assert!(!sheet.contains("<hyperlink "), "not a web address: {sheet}");
        let strings = part(&book, "xl/sharedStrings.xml");
        for s in ["=cmd|", "+1+1", "@SUM(A1)", "-2+3"] {
            assert!(strings.contains(s), "{s}");
        }
    }

    #[test]
    fn link_is_the_first_reference() {
        let book = workbook(vec![item("079", "web", "CVE-1", "High", 7.5)], "");
        assert!(part(&book, "xl/worksheets/_rels/sheet2.xml.rels").contains("Target=\"https://nvd.example/1\""));
    }

    #[test]
    fn excel_limits_do_not_fail_the_report() {
        let mut v = item("079", "web", "CVE-1", "High", 7.5);
        v.description = "é".repeat(MAX_CELL + 10);
        v.reference = format!("https://x.example/{}", "a".repeat(5000));
        workbook(vec![v], "");
        workbook(Vec::new(), "");
    }

    #[test]
    fn columns_pick_order_and_refuse() {
        let book = workbook(vec![item("079", "web", "CVE-1", "High", 7.5), item("080", "db", "CVE-1", "Low", 2.0)], "status,cve");
        let sheet = part(&book, "xl/worksheets/sheet2.xml");
        assert!(sheet.contains("ref=\"A1:B2\"") && sheet.contains("sqref=\"A2\""), "{sheet}");
        let strings = part(&book, "xl/sharedStrings.xml");
        assert!(strings.find(">Status<").unwrap() < strings.find(">CVE ID<").unwrap());
        assert!(!strings.contains(">Package<"));
        assert_eq!(pick_columns("cve,nope").unwrap_err(), "Unknown column: nope");
        assert_eq!(pick_columns(" ").unwrap().len(), COLUMNS.len());
    }

    #[test]
    fn an_agent_of_another_tenant_is_refused() {
        let tenants = HashMap::from([("079".to_string(), "acme".to_string()), ("080".to_string(), "other".to_string())]);
        assert!(all_in_scope(&list(Some("079")), &tenants, "acme"));
        assert!(all_in_scope(&list(None), &tenants, "acme"), "empty: all in scope");
        assert!(!all_in_scope(&list(Some("079,080")), &tenants, "acme"));
        assert!(!all_in_scope(&list(Some("999")), &tenants, "acme"), "an unknown agent is not this tenant's");
    }

    #[test]
    fn sheet_names_excel_accepts() {
        let mut seen = HashSet::from(["summary".to_string()]);
        assert_eq!(sheet_name("Summary", &mut seen), "Summary (2)");
        assert_eq!(sheet_name("a/b[c]", &mut seen), "a_b_c_");
        assert_eq!(sheet_name("'quoted'", &mut seen), "quoted");
        let long = "x".repeat(40);
        assert_eq!(sheet_name(&long, &mut seen), "x".repeat(31));
        assert_eq!(sheet_name(&long, &mut seen), format!("{} (2)", "x".repeat(27)));
        assert_eq!(sheet_name("WEB", &mut seen), "WEB");
        assert_eq!(sheet_name("web", &mut seen), "web (2)");
    }

    #[test]
    fn file_names() {
        let line = |name: &str| AgentLine { id: "079".into(), name: name.into(), os: String::new(), counts: [0; 4] };
        assert_eq!(file_name(&[line("web 1\"\r\nx")], "2026-11-05"), "ProVigil-Vulnerabilities-web_1___x-2026-11-05.xlsx");
        assert_eq!(file_name(&[line("a"), line("b")], "2026-11-05"), "ProVigil-Vulnerabilities-Fleet-2026-11-05.xlsx");
    }
}
