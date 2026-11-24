//! SIEM forwarding — emits CEF-formatted alerts to a syslog UDP endpoint.
//!
//! Enable by setting SIEM_SYSLOG_HOST (and optionally SIEM_SYSLOG_PORT, default 514).
//! Each HIGH or CRITICAL alert is sent as an RFC 3164 syslog message with CEF payload.
//!
//! Example: SIEM_SYSLOG_HOST=splunk.corp.local SIEM_SYSLOG_PORT=514
//!
//! CEF format reference: ArcSight CEF Implementation Standard, Rev 23.

use tokio::net::UdpSocket;
use tracing::warn;

pub struct SiemForwarder {
    socket: UdpSocket,
    target: std::net::SocketAddr,
}

impl SiemForwarder {
    pub async fn new(host: &str, port: u16) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target: std::net::SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid SIEM syslog address {}:{} — {}", host, port, e))?;
        Ok(Self { socket, target })
    }

    /// Emit a CEF-formatted alert via UDP syslog (RFC 3164).
    ///
    /// Maps NDR severity → CEF severity (0–10):
    ///   CRITICAL → 10, HIGH → 7, MEDIUM → 5, LOW → 3
    pub async fn send_hit(
        &self,
        src:       &str,
        dst:       &str,
        src_port:  u16,
        dst_port:  u16,
        severity:  &str,
        score:     f32,
        rule_name: &str,
        reasons:   &[String],
        tenant_id: &str,
    ) {
        let cef_sev: u8 = match severity {
            "CRITICAL" => 10,
            "HIGH"     => 7,
            "MEDIUM"   => 5,
            "LOW"      => 3,
            _          => 1,
        };

        // Syslog priority = (facility * 8) + syslog_severity
        // facility 16 = local0; syslog severity 6 = informational
        let priority: u8 = (16 * 8) + 6; // 134

        let now = chrono::Utc::now().format("%b %d %H:%M:%S").to_string();
        let msg = reasons.first().map(|s| s.as_str()).unwrap_or(rule_name);

        // CEF requires '|', '=', and '\' escaped in header and extension values
        let rule_cef = cef_escape_header(rule_name);
        let msg_cef  = cef_escape_ext(msg);

        let cef = format!(
            "<{priority}>{now} ndr-engine \
             CEF:0|PromaAlpha|NDR|1.0|ndr-alert|{rule_cef}|{cef_sev}|\
             src={src} dst={dst} spt={src_port} dpt={dst_port} \
             flexNumber1={score:.0} flexNumber1Label=riskScore \
             flexString1={tenant_id} flexString1Label=tenant \
             msg={msg_cef}"
        );

        if let Err(e) = self.socket.send_to(cef.as_bytes(), self.target).await {
            warn!("SIEM syslog send failed: {}", e);
        }
    }
}

fn cef_escape_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\n', " ")
}
