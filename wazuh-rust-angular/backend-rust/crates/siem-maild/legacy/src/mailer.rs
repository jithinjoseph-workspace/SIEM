//! Wazuh Email Formatting and SMTP Delivery Engine (src/os_maild/sendmail.c, sendcustomemail.c)
//!
//! Formats alerts into RFC 2822 emails and delivers them via RFC 5321 SMTP dialog
//! or local sendmail command pipeline.

use crate::config::{EmailFormat, MailConfig};
use crate::mail_list::MailMsg;
use std::io::{BufRead, BufReader, Read, Write};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum MailerError {
    #[error("SMTP connection failed: {0}")]
    ConnectionFailed(String),
    #[error("SMTP handshake error: {0}")]
    HandshakeFailed(String),
    #[error("SMTP server rejected recipient: {0}")]
    RecipientRejected(String),
    #[error("SMTP data transmission error: {0}")]
    DataRejected(String),
    #[error("No recipients specified for email")]
    NoRecipients,
    #[error("IO error during mail delivery: {0}")]
    Io(String),
}

/// Formatter for Wazuh alert emails matching `sendmail.c`
pub struct AlertMailFormatter;

impl AlertMailFormatter {
    /// Builds email subject matching `MAIL_SUBJECT_FULL` or `SMS_SUBJECT`
    pub fn build_subject(idsname: &str, agent_name: &str, level: u8, desc: &str, format: EmailFormat) -> String {
        match format {
            EmailFormat::Sms => {
                format!("{} {} - {}", idsname, level, desc)
            }
            _ => {
                format!("{} alert - {} - Level {} - {}", idsname, agent_name, level, desc)
            }
        }
    }

    /// Builds single alert body matching `MAIL_BODY` in `maild.h`
    pub fn build_body(
        idsname: &str,
        timestamp: &str,
        agent: &str,
        rule_id: u32,
        level: u8,
        description: &str,
        log: &str,
    ) -> String {
        format!(
            "\r\n{} Notification.\r\n{}\r\n\r\n\
            Received From: {}\r\n\
            Rule: {} fired (level {}) -> \"{}\"\r\n\r\n\
            Portion of the log(s):\r\n\r\n{}\r\n\r\n\
            --END OF NOTIFICATION\r\n\r\n",
            idsname, timestamp, agent, rule_id, level, description, log
        )
    }

    /// Builds an aggregated batch email containing multiple alert messages
    pub fn build_aggregated_email(
        idsname: &str,
        msgs: &[MailMsg],
    ) -> (String, String) {
        if msgs.is_empty() {
            return (format!("{} Notification", idsname), String::new());
        }

        let max_level = msgs.iter().map(|m| m.rule_level).max().unwrap_or(0);
        let first_agent = &msgs[0].agent_name;

        let subject = format!(
            "{} notification - {} - Alert level {}",
            idsname, first_agent, max_level
        );

        let mut body = format!(
            "\r\n{} Notification.\r\n\
            Total Alerts in Digest: {}\r\n\
            =================================================================\r\n\r\n",
            idsname,
            msgs.len()
        );

        for (idx, m) in msgs.iter().enumerate() {
            body.push_str(&format!(
                "--- [Alert {} of {} | Level {} | Rule {}] ---\r\n\
                Timestamp: {}\r\n\
                Agent: {}\r\n\
                Subject: {}\r\n\
                {}\r\n\r\n",
                idx + 1,
                msgs.len(),
                m.rule_level,
                m.rule_id,
                m.timestamp,
                m.agent_name,
                m.subject,
                m.body.trim()
            ));
        }

        body.push_str(" --END OF NOTIFICATION\r\n\r\n");
        (subject, body)
    }

    /// Construct full RFC 2822 email payload including headers
    pub fn build_rfc2822_message(
        config: &MailConfig,
        recipients: &[String],
        subject: &str,
        body: &str,
    ) -> String {
        let date_str = chrono::Utc::now().to_rfc2822();
        let to_headers = recipients.join(", ");

        let mut msg = format!(
            "Date: {}\r\n\
            From: {} <{}>\r\n\
            To: {}\r\n\
            Subject: {}\r\n\
            X-IDS-OSSEC: {}\r\n",
            date_str, config.idsname, config.from, to_headers, subject, config.idsname
        );

        if let Some(ref reply_to) = config.reply_to {
            msg.push_str(&format!("Reply-To: {} <{}>\r\n", config.idsname, reply_to));
        }

        msg.push_str("\r\n"); // End of headers
        msg.push_str(body);
        msg
    }
}

/// SMTP Client for sending email alerts matching `sendmail.c`
pub struct SmtpTransport;

impl SmtpTransport {
    /// Send an email over an SMTP connection (RFC 5321)
    pub fn send<S: Read + Write>(
        stream: &mut S,
        from: &str,
        recipients: &[String],
        rfc2822_content: &str,
    ) -> Result<(), MailerError> {
        if recipients.is_empty() {
            return Err(MailerError::NoRecipients);
        }

        let mut reader = BufReader::new(stream);

        // 1. Read greeting banner (expected 220)
        let mut banner = String::new();
        reader
            .read_line(&mut banner)
            .map_err(|e| MailerError::ConnectionFailed(e.to_string()))?;
        if !banner.starts_with("220") {
            return Err(MailerError::HandshakeFailed(format!("Invalid banner: {}", banner)));
        }

        // 2. Send EHLO
        let writer = reader.get_mut();
        writer
            .write_all(b"EHLO localhost\r\n")
            .map_err(|e| MailerError::Io(e.to_string()))?;
        writer.flush().map_err(|e| MailerError::Io(e.to_string()))?;

        // Read EHLO responses (multi-line 250-... or 250 )
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| MailerError::HandshakeFailed(e.to_string()))?;
            if line.starts_with("250 ") || line.starts_with("250\r\n") {
                break;
            } else if !line.starts_with("250-") {
                return Err(MailerError::HandshakeFailed(format!("EHLO error: {}", line)));
            }
        }

        // 3. Send MAIL FROM
        let writer = reader.get_mut();
        let mail_from = format!("MAIL FROM:<{}>\r\n", from);
        writer
            .write_all(mail_from.as_bytes())
            .map_err(|e| MailerError::Io(e.to_string()))?;
        writer.flush().map_err(|e| MailerError::Io(e.to_string()))?;

        let mut resp = String::new();
        reader
            .read_line(&mut resp)
            .map_err(|e| MailerError::Io(e.to_string()))?;
        if !resp.starts_with("250") {
            return Err(MailerError::HandshakeFailed(format!("MAIL FROM rejected: {}", resp)));
        }

        // 4. Send RCPT TO for each recipient
        for rcpt in recipients {
            let writer = reader.get_mut();
            let rcpt_to = format!("RCPT TO:<{}>\r\n", rcpt);
            writer
                .write_all(rcpt_to.as_bytes())
                .map_err(|e| MailerError::Io(e.to_string()))?;
            writer.flush().map_err(|e| MailerError::Io(e.to_string()))?;

            let mut rcpt_resp = String::new();
            reader
                .read_line(&mut rcpt_resp)
                .map_err(|e| MailerError::Io(e.to_string()))?;
            if !rcpt_resp.starts_with("250") {
                return Err(MailerError::RecipientRejected(format!(
                    "Recipient {} rejected: {}",
                    rcpt, rcpt_resp
                )));
            }
        }

        // 5. Send DATA
        let writer = reader.get_mut();
        writer
            .write_all(b"DATA\r\n")
            .map_err(|e| MailerError::Io(e.to_string()))?;
        writer.flush().map_err(|e| MailerError::Io(e.to_string()))?;

        let mut data_resp = String::new();
        reader
            .read_line(&mut data_resp)
            .map_err(|e| MailerError::Io(e.to_string()))?;
        if !data_resp.starts_with("354") {
            return Err(MailerError::DataRejected(format!("DATA rejected: {}", data_resp)));
        }

        // 6. Transmit content followed by \r\n.\r\n
        let writer = reader.get_mut();
        writer
            .write_all(rfc2822_content.as_bytes())
            .map_err(|e| MailerError::Io(e.to_string()))?;
        if !rfc2822_content.ends_with("\r\n") {
            writer
                .write_all(b"\r\n")
                .map_err(|e| MailerError::Io(e.to_string()))?;
        }
        writer
            .write_all(b".\r\n")
            .map_err(|e| MailerError::Io(e.to_string()))?;
        writer.flush().map_err(|e| MailerError::Io(e.to_string()))?;

        let mut finish_resp = String::new();
        reader
            .read_line(&mut finish_resp)
            .map_err(|e| MailerError::Io(e.to_string()))?;
        if !finish_resp.starts_with("250") {
            return Err(MailerError::DataRejected(format!(
                "Message submission failed: {}",
                finish_resp
            )));
        }

        // 7. Send QUIT
        let writer = reader.get_mut();
        let _ = writer.write_all(b"QUIT\r\n");
        let _ = writer.flush();

        Ok(())
    }
}
