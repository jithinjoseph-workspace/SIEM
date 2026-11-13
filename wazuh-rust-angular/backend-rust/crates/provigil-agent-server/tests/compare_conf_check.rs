//! The agent.conf check, old against new: every rule, then generated files built from good and
//! bad pieces. The answers (Ok, or the error text the console shows) must be identical.

/// The old check, as siem-api had it.
mod old {
    struct LocalfileCheck(siem_config::localfile::LogreaderConfig);

    impl siem_config::ConfigHandler for LocalfileCheck {
        fn section(
            &mut self,
            ctx: &mut siem_config::ConfigContext,
            _xml: &siem_xml::OsXml,
            section: siem_config::Section,
            _node: &siem_xml::XmlNode,
            children: Option<&[siem_xml::XmlNode]>,
        ) -> siem_config::Result<()> {
            let ch = children.unwrap_or(&[]);
            match section {
                siem_config::Section::Localfile => siem_config::localfile::read_localfile(ctx, ch, &mut self.0),
                siem_config::Section::LogcollectorSocket => siem_config::socket::read_socket(ch, &mut self.0.socket_list),
                _ => Ok(()),
            }
        }
    }

    pub fn verify_agent_conf(text: &str) -> Result<(), String> {
        use siem_config::modules::*;
        let xml = siem_xml::OsXml::read_string(text, false).map_err(|e| format!("XML error (line {}): {}", e.line, e.message))?;
        let mut ctx = siem_config::ConfigContext::new(siem_config::Platform::MANAGER);
        let mods = CAGENT_CONFIG | CSYSCHECK | CROOTCHECK | CLOCALFILE | CLGCSOCKET | CCLIENT | CBUFFER | CWMODULE | CLABELS;
        let r = siem_config::read_config_xml(&mut ctx, mods, &xml, "agent.conf", &mut LocalfileCheck(Default::default()));
        r.map_err(|e| {
            let errors: Vec<String> = ctx.log.iter().filter(|(l, _)| matches!(l, siem_config::LogLevel::Error)).map(|(_, m)| m.clone()).collect();
            if errors.is_empty() {
                e.0
            } else {
                errors.join(" ")
            }
        })
    }
}

fn same(text: &str) {
    assert_eq!(old::verify_agent_conf(text), provigil_agent_server::conf_check::check(text), "{text}");
}

/// `<localfile>` pieces: good ones and every kind of bad one.
const LOCALFILE: &[&str] = &[
    "<location>/var/log/syslog</location>",
    "<location>C:\\logs\\*.log</location>",
    "<location>/var/log/*.log</location>",
    "<location>/var/log/%Y-%m-%d.log</location>",
    "<location>Application</location>",
    "<location>Microsoft-Windows-Sysmon/Operational</location>",
    "<command>netstat -an</command>",
    "<log_format>syslog</log_format>",
    "<log_format>eventchannel</log_format>",
    "<log_format>eventlog</log_format>",
    "<log_format>full_command</log_format>",
    "<log_format>command</log_format>",
    "<log_format>json</log_format>",
    "<log_format>journald</log_format>",
    "<log_format>macos</log_format>",
    "<log_format>multi-line: 3</log_format>",
    "<log_format>multi-line:0</log_format>",
    "<log_format>multi-line 3</log_format>",
    "<log_format>multi-line:x</log_format>",
    "<log_format>multi-line-regex</log_format>",
    "<LOG_FORMAT>apache</LOG_FORMAT>",
    "<log_format>nonsense</log_format>",
    "<multiline_regex>^\\d+</multiline_regex>",
    "<multiline_regex>(</multiline_regex>",
    "<multiline_regex></multiline_regex>",
    "<frequency>360</frequency>",
    "<frequency>hourly</frequency>",
    "<frequency>5m</frequency>",
    "<frequency></frequency>",
    "<age>1d</age>",
    "<age>0</age>",
    "<age>10x</age>",
    "<age>0x10</age>",
    "<age>-1</age>",
    "<reconnect_time>5s</reconnect_time>",
    "<reconnect_time>5</reconnect_time>",
    "<reconnect_time>0</reconnect_time>",
    "<reconnect_time>3q</reconnect_time>",
    "<ignore_binaries>yes</ignore_binaries>",
    "<ignore_binaries>maybe</ignore_binaries>",
    "<ignore>healthcheck</ignore>",
    "<ignore type=\"osregex\">^\\d+</ignore>",
    "<ignore type=\"osmatch\">abc</ignore>",
    "<ignore type=\"weird\">abc</ignore>",
    "<ignore kind=\"pcre2\">abc</ignore>",
    "<restrict>(</restrict>",
    "<restrict type=\"pcre2\">ok.*</restrict>",
    "<label key=\"app\">sql</label>",
    "<label key=\"\">x</label>",
    "<label>x</label>",
    "<label key=\"_internal\">x</label>",
    "<filter field=\"_SYSTEMD_UNIT\">^ssh</filter>",
    "<filter field=\"\">x</filter>",
    "<filter field=\"U\">(</filter>",
    "<query>Event/System[EventID=4624]</query>",
    "<query type=\"bad\" level=\"loud\">x</query>",
    "<only-future-events>no</only-future-events>",
    "<only-future-events max-size=\"x\">maybe</only-future-events>",
    "<target>agent,custom</target>",
    "<out_format target=\"x\">$(log)</out_format>",
    "<alias>netstat</alias>",
    "<exclude>/var/log/*.gz</exclude>",
    "<Location>x</Location>",
    "<unknown>x</unknown>",
];

const SOCKET: &[&str] = &["<name>s1</name>", "<name>agent</name>", "<name></name>", "<location>/tmp/s.sock</location>", "<location></location>", "<mode>tcp</mode>", "<mode>UDP</mode>", "<mode>x</mode>", "<prefix>p:</prefix>", "<other>x</other>"];

const OTHER: &[&str] = &[
    "<syscheck><frequency>43200</frequency></syscheck>",
    "<rootcheck/>",
    "<client_buffer><disabled>no</disabled></client_buffer>",
    "<labels><label key=\"a\">b</label></labels>",
    "<wodle name=\"syscollector\"><disabled>no</disabled></wodle>",
    "<sca/>",
    "<global/>",
    "<nonsense>1</nonsense>",
    "<var name=\"x\">1</var>",
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn every_rule() {
    // each piece alone, with the usual companions
    for p in LOCALFILE {
        for base in ["", "<location>/var/log/x</location>", "<log_format>syslog</log_format>", "<location>/x</location><log_format>syslog</log_format>"] {
            same(&format!("<agent_config><localfile>{base}{p}</localfile></agent_config>"));
            same(&format!("<agent_config><localfile>{p}{base}</localfile></agent_config>"));
        }
    }
    for p in SOCKET {
        for base in ["", "<name>s</name>", "<location>/l</location>", "<name>s</name><location>/l</location>"] {
            same(&format!("<agent_config><socket>{base}{p}</socket></agent_config>"));
        }
    }
    for p in OTHER {
        same(&format!("<agent_config>{p}</agent_config>"));
    }
    for doc in [
        "",
        "<agent_config></agent_config>",
        "<agent_config/>",
        "<ossec_config/>",
        "<agent_config os=\"Windows\" name=\"pc1\" profile=\"p\" overwrite=\"yes\"><localfile><location>/x</location><log_format>syslog</log_format></localfile></agent_config>",
        "<agent_config color=\"red\"/><agent_config><localfile><location>/x</location></localfile></agent_config>",
        "<agent_config><localfile><log_format>command</log_format><location>/x</location></localfile><socket><name>agent</name></socket></agent_config>",
        "<agent_config><localfile></localfile></agent_config>",
        "<agent_config><localfile/></agent_config>",
        "<agent_config><a>",
        "<agent_config>\n<localfile>\n<location>x</location>\n</agent_config>",
        "<agent_config><localfile><location>x</location><log_format>syslog</log_format></localfile></agent_config><other/>",
    ] {
        same(doc);
    }
}

#[test]
fn generated_files() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    for _ in 0..30_000 {
        let mut doc = String::new();
        for _ in 0..1 + r.below(2) {
            doc.push_str(["<agent_config>", "<agent_config os=\"Linux\">", "<agent_config bad=\"1\">"][r.below(3)]);
            for _ in 0..r.below(4) {
                match r.below(5) {
                    0..=2 => {
                        doc.push_str("<localfile>");
                        for _ in 0..r.below(5) {
                            doc.push_str(LOCALFILE[r.below(LOCALFILE.len())]);
                        }
                        doc.push_str("</localfile>");
                    }
                    3 => {
                        doc.push_str("<socket>");
                        for _ in 0..r.below(4) {
                            doc.push_str(SOCKET[r.below(SOCKET.len())]);
                        }
                        doc.push_str("</socket>");
                    }
                    _ => doc.push_str(OTHER[r.below(OTHER.len())]),
                }
            }
            doc.push_str("</agent_config>\n");
        }
        same(&doc);
    }
}
