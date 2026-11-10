//! A small PDF writer for the tenant reports (tenant_reports.rs): A4 pages, the built-in
//! Helvetica fonts (no font files), text, tables and vector bar / column charts.
//! Text is WinAnsi (Latin-1); other characters print as '?'.

use std::fmt::Write as _;

const W: f32 = 595.0;
const H: f32 = 842.0;
const M: f32 = 48.0;
/// The ink colours: text, muted text, rules, accent.
pub const INK: [f32; 3] = [0.12, 0.14, 0.18];
pub const MUTED: [f32; 3] = [0.42, 0.45, 0.50];
const LINE: [f32; 3] = [0.85, 0.87, 0.90];
pub const ACCENT: [f32; 3] = [0.15, 0.39, 0.92];

pub struct Pdf {
    pages: Vec<Vec<u8>>,
    cur: Vec<u8>,
    y: f32,
    footer: String,
}

/// The string as a PDF literal: WinAnsi bytes, `( ) \` escaped.
fn lit(s: &str) -> Vec<u8> {
    let mut o = vec![b'('];
    for c in s.chars() {
        let b = match c as u32 {
            0x20..=0x7e => c as u8,
            0xa0..=0xff => c as u32 as u8,
            0x2013 | 0x2014 => b'-',
            0x2018 | 0x2019 => b'\'',
            0x201c | 0x201d => b'"',
            _ => b'?',
        };
        if matches!(b, b'(' | b')' | b'\\') {
            o.push(b'\\');
        }
        o.push(b);
    }
    o.push(b')');
    o
}

/// The width of `s` at `size` points. shortcut: one average width per character (digits
/// exact), so wrapping and right-aligning are close, not exact; use the AFM widths if it shows.
pub fn width(s: &str, size: f32, bold: bool) -> f32 {
    let per = |c: char| match c {
        '0'..='9' => 0.556,
        ' ' | 'i' | 'l' | 'j' | 't' | 'f' | 'I' | '.' | ',' | ':' | ';' | '\'' | '|' | '!' => 0.28,
        'm' | 'w' | 'M' | 'W' => 0.83,
        'A'..='Z' => 0.67,
        _ => 0.52,
    };
    s.chars().map(per).sum::<f32>() * size * if bold { 1.06 } else { 1.0 }
}

/// `s` cut to fit `max` points, with "..." when cut.
pub fn fit(s: &str, size: f32, bold: bool, max: f32) -> String {
    if width(s, size, bold) <= max {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars() {
        if width(&out, size, bold) + width(&format!("{c}..."), size, bold) > max {
            break;
        }
        out.push(c);
    }
    format!("{}...", out.trim_end())
}

/// Words of `s` in lines of at most `max` points.
pub fn wrap(s: &str, size: f32, max: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            let next = if line.is_empty() {
                word.to_string()
            } else {
                format!("{line} {word}")
            };
            if width(&next, size, false) > max && !line.is_empty() {
                lines.push(std::mem::replace(&mut line, word.to_string()));
            } else {
                line = next;
            }
        }
        lines.push(line);
    }
    lines
}

impl Pdf {
    /// A new document; `footer` is printed on every page with its number.
    pub fn new(footer: &str) -> Pdf {
        Pdf {
            pages: Vec::new(),
            cur: Vec::new(),
            y: H - M,
            footer: footer.to_string(),
        }
    }

    fn op(&mut self, s: &str) {
        self.cur.extend_from_slice(s.as_bytes());
        self.cur.push(b'\n');
    }

    /// Text at (x, y), baseline.
    pub fn text_at(&mut self, x: f32, y: f32, s: &str, size: f32, bold: bool, rgb: [f32; 3]) {
        let mut b = format!(
            "BT /{} {size} Tf {} {} {} rg {x:.1} {y:.1} Td ",
            if bold { "F2" } else { "F1" },
            rgb[0],
            rgb[1],
            rgb[2]
        )
        .into_bytes();
        b.extend(lit(s));
        b.extend_from_slice(b" Tj ET\n");
        self.cur.extend(b);
    }

    pub fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, rgb: [f32; 3]) {
        self.op(&format!(
            "{} {} {} rg {x:.1} {y:.1} {w:.1} {h:.1} re f",
            rgb[0], rgb[1], rgb[2]
        ));
    }

    fn hline(&mut self, y: f32) {
        self.rect(M, y, W - 2.0 * M, 0.6, LINE);
    }

    pub fn new_page(&mut self) {
        let page = std::mem::take(&mut self.cur);
        self.pages.push(page);
        self.y = H - M;
    }

    /// Starts a new page unless `h` points fit above the bottom margin.
    pub fn need(&mut self, h: f32) {
        if self.y - h < M + 20.0 {
            self.new_page();
        }
    }

    pub fn gap(&mut self, h: f32) {
        self.y -= h;
    }

    pub fn title(&mut self, s: &str, sub: &str) {
        self.rect(0.0, H - 6.0, W, 6.0, ACCENT);
        self.text_at(M, self.y - 16.0, s, 22.0, true, INK);
        self.text_at(M, self.y - 36.0, sub, 11.0, false, MUTED);
        self.y -= 52.0;
        self.hline(self.y);
        self.y -= 18.0;
    }

    pub fn heading(&mut self, s: &str) {
        self.need(60.0);
        self.y -= 8.0;
        self.text_at(M, self.y - 14.0, s, 14.0, true, INK);
        self.y -= 24.0;
    }

    pub fn paragraph(&mut self, s: &str) {
        for line in wrap(s, 10.0, W - 2.0 * M) {
            self.need(14.0);
            self.text_at(M, self.y - 10.0, &line, 10.0, false, INK);
            self.y -= 14.0;
        }
        self.y -= 4.0;
    }

    /// Big numbers in boxes, four to a row: (label, value, colour).
    pub fn tiles(&mut self, tiles: &[(&str, String, [f32; 3])]) {
        let gap = 10.0;
        let w = (W - 2.0 * M - 3.0 * gap) / 4.0;
        for row in tiles.chunks(4) {
            self.need(62.0);
            for (i, (label, value, rgb)) in row.iter().enumerate() {
                let x = M + i as f32 * (w + gap);
                self.rect(x, self.y - 54.0, w, 54.0, [0.96, 0.97, 0.98]);
                self.rect(x, self.y - 54.0, 3.0, 54.0, *rgb);
                self.text_at(
                    x + 10.0,
                    self.y - 18.0,
                    &fit(label, 8.5, false, w - 14.0),
                    8.5,
                    false,
                    MUTED,
                );
                self.text_at(x + 10.0, self.y - 42.0, value, 18.0, true, INK);
            }
            self.y -= 64.0;
        }
    }

    /// A horizontal bar chart: one row per (label, value, colour), longest bar = the largest value.
    pub fn bars(&mut self, rows: &[(String, u64, [f32; 3])]) {
        if rows.is_empty() {
            self.paragraph("No data in this period.");
            return;
        }
        let label_w = 210.0;
        let num_w = 60.0;
        let bar_x = M + label_w + 8.0;
        let bar_max = W - 2.0 * M - label_w - 8.0 - num_w;
        let max = rows.iter().map(|r| r.1).max().unwrap_or(1).max(1) as f32;
        for (label, v, rgb) in rows {
            self.need(18.0);
            self.text_at(
                M,
                self.y - 11.0,
                &fit(label, 9.0, false, label_w),
                9.0,
                false,
                INK,
            );
            self.rect(bar_x, self.y - 13.0, bar_max, 11.0, [0.95, 0.96, 0.97]);
            self.rect(
                bar_x,
                self.y - 13.0,
                (*v as f32 / max * bar_max).max(1.5),
                11.0,
                *rgb,
            );
            let n = v.to_string();
            self.text_at(
                W - M - width(&n, 9.0, true),
                self.y - 11.0,
                &n,
                9.0,
                true,
                INK,
            );
            self.y -= 17.0;
        }
        self.y -= 6.0;
    }

    /// A column chart with stacked parts: per column (label, parts), parts drawn bottom-up
    /// with `colours`; a legend of `names` under it.
    pub fn columns(&mut self, cols: &[(String, Vec<u64>)], colours: &[[f32; 3]], names: &[&str]) {
        let h = 150.0;
        self.need(h + 50.0);
        let base = self.y - h - 4.0;
        let left = M + 34.0;
        let plot_w = W - M - left;
        let max = cols
            .iter()
            .map(|c| c.1.iter().sum::<u64>())
            .max()
            .unwrap_or(0)
            .max(1);
        // gridlines at 0, 1/2 and the maximum
        for (f, v) in [(0.0, 0), (0.5, max / 2), (1.0, max)] {
            let y = base + h * f;
            self.rect(left, y, plot_w, 0.5, LINE);
            let n = v.to_string();
            self.text_at(
                left - 4.0 - width(&n, 7.5, false),
                y - 2.5,
                &n,
                7.5,
                false,
                MUTED,
            );
        }
        let slot = plot_w / cols.len().max(1) as f32;
        let bw = (slot * 0.62).min(28.0);
        let every = (cols.len() / 12).max(1);
        for (i, (label, parts)) in cols.iter().enumerate() {
            let x = left + i as f32 * slot + (slot - bw) / 2.0;
            let mut y = base;
            for (p, v) in parts.iter().enumerate() {
                let ph = *v as f32 / max as f32 * h;
                if ph > 0.0 {
                    self.rect(x, y, bw, ph, colours[p % colours.len()]);
                    y += ph;
                }
            }
            if i % every == 0 {
                self.text_at(
                    x + bw / 2.0 - width(label, 7.5, false) / 2.0,
                    base - 12.0,
                    label,
                    7.5,
                    false,
                    MUTED,
                );
            }
        }
        let mut x = left;
        let ly = base - 28.0;
        for (i, n) in names.iter().enumerate() {
            self.rect(x, ly, 8.0, 8.0, colours[i % colours.len()]);
            self.text_at(x + 12.0, ly + 1.0, n, 8.0, false, INK);
            x += 24.0 + width(n, 8.0, false);
        }
        self.y = ly - 14.0;
    }

    /// A table: column widths are fractions of the page width; header repeated on new pages.
    pub fn table(&mut self, headers: &[&str], widths: &[f32], rows: &[Vec<String>]) {
        let full = W - 2.0 * M;
        let header = |p: &mut Pdf| {
            p.rect(M, p.y - 16.0, full, 16.0, [0.94, 0.95, 0.97]);
            let mut x = M + 4.0;
            for (h, w) in headers.iter().zip(widths) {
                p.text_at(x, p.y - 11.5, h, 8.5, true, INK);
                x += w * full;
            }
            p.y -= 18.0;
        };
        self.need(40.0);
        header(self);
        for row in rows {
            if self.y - 15.0 < M + 20.0 {
                self.new_page();
                header(self);
            }
            let mut x = M + 4.0;
            for (c, w) in row.iter().zip(widths) {
                self.text_at(
                    x,
                    self.y - 10.5,
                    &fit(c, 8.5, false, w * full - 8.0),
                    8.5,
                    false,
                    INK,
                );
                x += w * full;
            }
            self.y -= 15.0;
            self.hline(self.y + 1.0);
        }
        self.y -= 8.0;
    }

    /// The finished file.
    pub fn finish(mut self) -> Vec<u8> {
        if !self.cur.is_empty() || self.pages.is_empty() {
            self.new_page();
        }
        let n = self.pages.len();
        let footer = self.footer.clone();
        let pages: Vec<Vec<u8>> = std::mem::take(&mut self.pages)
            .into_iter()
            .enumerate()
            .map(|(i, mut content)| {
                self.cur = Vec::new();
                self.rect(M, M - 6.0, W - 2.0 * M, 0.6, LINE);
                self.text_at(M, M - 20.0, &footer, 8.0, false, MUTED);
                let num = format!("Page {} of {n}", i + 1);
                self.text_at(
                    W - M - width(&num, 8.0, false),
                    M - 20.0,
                    &num,
                    8.0,
                    false,
                    MUTED,
                );
                content.extend(std::mem::take(&mut self.cur));
                content
            })
            .collect();

        // objects: 1 catalog, 2 pages, 3-4 fonts, then (page, content) per page
        let mut out: Vec<u8> = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut offsets = Vec::new();
        let mut obj = |out: &mut Vec<u8>, body: &[u8]| {
            offsets.push(out.len());
            out.extend(format!("{} 0 obj\n", offsets.len()).as_bytes());
            out.extend(body);
            out.extend(b"\nendobj\n");
        };
        let kids: String = (0..n).fold(String::new(), |mut s, i| {
            let _ = write!(s, "{} 0 R ", 5 + 2 * i);
            s
        });
        obj(&mut out, b"<< /Type /Catalog /Pages 2 0 R >>");
        obj(
            &mut out,
            format!("<< /Type /Pages /Kids [{kids}] /Count {n} >>").as_bytes(),
        );
        obj(
            &mut out,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        obj(&mut out, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
        for (i, content) in pages.iter().enumerate() {
            obj(&mut out, format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {} 0 R >>", 6 + 2 * i).as_bytes());
            let mut body = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
            body.extend(content);
            body.extend(b"\nendstream");
            obj(&mut out, &body);
        }
        let xref = out.len();
        out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
        for o in &offsets {
            out.extend(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                offsets.len() + 1
            )
            .as_bytes(),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_latin1() {
        assert_eq!(lit("a(b)\\"), b"(a\\(b\\)\\\\)".to_vec());
        assert_eq!(lit("é→"), vec![b'(', 0xe9, b'?', b')']);
    }

    #[test]
    fn wraps_and_fits() {
        let lines = wrap(
            "one two three four five six seven eight nine ten",
            10.0,
            80.0,
        );
        assert!(lines.len() > 1 && lines.iter().all(|l| width(l, 10.0, false) <= 80.0));
        let f = fit(
            "a very long rule description that does not fit",
            9.0,
            false,
            60.0,
        );
        assert!(f.ends_with("...") && width(&f, 9.0, false) <= 60.0);
    }

    #[test]
    fn valid_structure() {
        let mut p = Pdf::new("footer");
        p.title("Report", "sub");
        p.tiles(&[("Alerts", "12".into(), ACCENT)]);
        p.bars(&[("rule".into(), 5, ACCENT)]);
        p.columns(&[("Mon".into(), vec![1, 2])], &[ACCENT, MUTED], &["a", "b"]);
        p.table(
            &["A", "B"],
            &[0.5, 0.5],
            &(0..80)
                .map(|i| vec![i.to_string(), "x".into()])
                .collect::<Vec<_>>(),
        );
        let b = p.finish();
        let s = String::from_utf8_lossy(&b);
        assert!(s.starts_with("%PDF-1.4") && s.ends_with("%%EOF\n"));
        // the long table spilled onto a second page, both numbered
        assert!(!s.contains("/Count 1 ") && s.contains("(Page 2 of "));
        // every xref offset points at its object
        let xref = s.rfind("\nxref\n").unwrap() + 1;
        for (i, line) in s[xref..]
            .lines()
            .skip(3)
            .take_while(|l| l.ends_with(" n "))
            .enumerate()
        {
            let off: usize = line[..10].parse().unwrap();
            assert!(
                b[off..].starts_with(format!("{} 0 obj", i + 1).as_bytes()),
                "object {}",
                i + 1
            );
        }
    }
}
