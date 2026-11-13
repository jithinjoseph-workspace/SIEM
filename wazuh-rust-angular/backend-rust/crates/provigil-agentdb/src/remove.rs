//! `wazuhdb remove <ids>` (spec § 1): deletes the databases of several agents, and the `mitre`
//! actor (`mitre sql <query>` on the read-only ATT&CK database).

use provigil_json::Json;

use crate::text::{answer, near, read_long, split_word, until_nul};
use crate::{Answer, Engine, DB_DIR, INVALID, OK};

/// Words split at spaces; `"…"` groups words (quotes removed), `\` takes the next byte as is.
pub fn quoted_words(s: &[u8]) -> Vec<Vec<u8>> {
    let (mut out, mut cur, mut quoting, mut escaped) = (Vec::new(), Vec::new(), false, false);
    for &c in until_nul(s) {
        match c {
            _ if escaped => {
                cur.push(c);
                escaped = false;
            }
            b'\\' => escaped = true,
            b'"' => quoting = !quoting,
            b' ' if !quoting => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether a decimal text is beyond the 64-bit range.
fn overflows(s: &[u8]) -> bool {
    let t = s.iter().skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')).copied().collect::<Vec<u8>>();
    let neg = t.first() == Some(&b'-');
    let digits = t.iter().skip(usize::from(matches!(t.first(), Some(b'+' | b'-')))).take_while(|c| c.is_ascii_digit());
    let mut v: i128 = 0;
    for d in digits {
        v = v * 10 + (d - b'0') as i128;
        if v > i64::MAX as i128 + 1 {
            return true;
        }
    }
    if neg {
        v > i64::MAX as i128 + 1
    } else {
        v > i64::MAX as i128
    }
}

impl Engine {
    pub(crate) fn remove_actor(&self, rest: &[u8]) -> Answer {
        let (cmd, args) = split_word(rest);
        match (cmd, args) {
            (b"remove", Some(list)) => {
                let printed = self.remove_agents(list).map(|d| d.print_unformatted()).unwrap_or_else(|| b"(null)".to_vec());
                (OK, answer(cat!("ok ", printed)))
            }
            (_, None) => {
                self.debug(b"Invalid DB query syntax.".to_vec());
                self.debug2(cat!("DB query error near: ", rest));
                (INVALID, near("err Invalid DB query syntax", rest))
            }
            _ => {
                self.debug(b"Invalid DB query syntax.".to_vec());
                self.debug2(cat!("DB query error near: ", cmd));
                (INVALID, b"err No agents id provided".to_vec())
            }
        }
    }

    /// `{"agents":{"<id>":"ok"|"Invalid agent ID"|"Can't close"|"Can't delete",…}}`
    fn remove_agents(&self, list: &[u8]) -> Option<Json> {
        let list = until_nul(list);
        if list.is_empty() || list == b" " {
            return None;
        }
        let mut agents = Json::object();
        // once a number overflowed, every later word is refused too (kept)
        let mut overflowed = false;
        // a refused word is reported under the last good id ("" before the first)
        let mut agent = String::new();
        for word in quoted_words(list) {
            let (id, end) = read_long(&word);
            overflowed |= overflows(&word);
            let result = if overflowed || end < word.len() {
                self.warn(cat!("Invalid agent ID when deleting database '", word, "'\n"));
                "Invalid agent ID"
            } else {
                agent = format!("{id:03}");
                let mut r = "ok";
                let open = self.dbs.lock().get(&agent).cloned();
                if let Some(h) = open {
                    let mut h = h.lock();
                    self.close(&mut h, false);
                }
                self.debug(cat!("Removing db for agent '", agent.clone(), "'"));
                let rel = format!("{DB_DIR}/{agent}.db");
                if let Err(e) = std::fs::remove_file(self.path(&rel)) {
                    self.debug(cat!("(1129): Could not unlink file '", rel, "' due to [(", e.raw_os_error().unwrap_or(0), ")-(", crate::agent::os_text(&e), ")]."));
                    r = "Can't delete";
                }
                r
            };
            agents.add(agent.clone(), Json::string(result));
        }
        let mut response = Json::object();
        response.add("agents", agents);
        self.debug(cat!("Deleting databases. JSON output: ", response.print_unformatted()));
        Some(response)
    }

    pub(crate) fn mitre_actor(&self, rest: &[u8], peer: i32) -> Answer {
        let rel = "var/db/mitre.db".to_string();
        self.debug2(cat!("Mitre query: ", rest));
        let mut h = self.cached("mitre");
        if h.db.is_none() && !self.open_into(&mut h, &rel) {
            self.error(cat!("Can't open SQLite database '", rel.clone(), "': ", h.errmsg()));
            self.close(&mut h, false);
            self.debug2(cat!("Couldn't open DB mitre: ", rel));
            return (INVALID, b"err Couldn't open DB mitre".to_vec());
        }
        h.peer = peer;
        let (cmd, args) = split_word(rest);
        let Some(sql) = args else {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query error near: ", rest));
            return (INVALID, near("err Invalid DB query syntax", rest));
        };
        if cmd != b"sql" {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query error near: ", cmd));
            return (INVALID, near("err Invalid DB query syntax", cmd));
        }
        match self.sql(&h, sql) {
            Some(d) => (OK, answer(cat!("ok ", d.print_unformatted()))),
            None => {
                let e = h.errmsg();
                self.debug(cat!("Mitre DB Cannot execute SQL query; err database ", rel, ": ", e.clone()));
                self.debug2(cat!("Mitre DB SQL query: ", until_nul(sql)));
                (INVALID, answer(cat!("err Cannot execute Mitre database query; ", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        let w = quoted_words(br#"1 "2 3" a\ b  \"x c\"#);
        assert_eq!(w, vec![b"1".to_vec(), b"2 3".to_vec(), b"a b".to_vec(), b"\"x".to_vec(), b"c".to_vec()]);
        assert!(overflows(b"99999999999999999999") && !overflows(b"-9223372036854775808") && overflows(b"9223372036854775808"));
    }
}
