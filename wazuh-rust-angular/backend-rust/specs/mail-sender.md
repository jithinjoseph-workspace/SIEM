# Mail sender: siem-api's own SMTP sending

Written 2026-11-03 (step 3, item 2). Describes what the new code must do. Contains no code.
The new code is written from this description only; nothing under `crates/siem-maild/` or
`old-code/` is opened.

## Purpose

siem-api sends e-mail itself: tenant alert e-mails (`alert_mail.rs`), scheduled and
on-demand report e-mails with a PDF (`tenant_reports.rs`, through `alert_mail::send`), and
the super admin's "send test e-mail" (`mail_settings.rs`). Today these call
`siem_maild::smtp_ext`; afterwards they call the new module and siem-api no longer uses
`siem_maild::smtp_ext`.

## Where

A new module `crates/siem-api/src/mail_send.rs`, declared in `main.rs` next to
`mail_settings`. Built on the `lettre` crate, version 0.11 (already used in the workspace by
auth-service and provigil-common), async with Tokio: features `tokio1`, `tokio1-native-tls`,
`builder`, `smtp-transport` as needed. No other new dependency.

## What it offers

- `SmtpAccount { host: String, port: u16, security: String, user: String, password: String }`
  with `security` one of `tls` (implicit TLS from the start), `starttls` (plain, then
  STARTTLS, which must succeed) or `none` (plain, no TLS; for a local relay on port 25).
  Any other value is an error.
- `Attachment { name: String, mime: String, data: Vec<u8> }`.
- `async fn send(account: &SmtpAccount, from: &str, to: &[String], subject: &str, text: &str, attachment: Option<Attachment>) -> Result<(), String>`
- `async fn send_test(account: &SmtpAccount, from: &str, to: &str) -> Result<(), String>`:
  subject `ProVigil notification - test e-mail`, text
  `This is a test e-mail from the ProVigil manager. Alert e-mails will use these settings.`
  followed by a line end.

## Behaviour

- **Connecting:** to `host:port`. With `tls` and `starttls` the server certificate is checked
  against the system's trusted roots; a TLS or certificate failure is reported with the
  server's name.
- **Waiting:** up to 300 seconds for each step (keep this value; it is what users had).
- **Login:** only when `user` is not empty (PLAIN or LOGIN, whichever the server offers). A
  refused login is an error with the server's reply.
- **Recipients:** at least one (none: error "No recipient"). All go in one session. If the
  server refuses any recipient, the send fails and the error names that address.
- **Errors** are one line of text saying which step failed (connect, TLS, login, sender,
  recipient, message, …), and include the server's reply text when there is one.
- **Message:**
  - `From:` the display name `ProVigil` and the `from` address.
  - `To:` every recipient.
  - `Date:` now. `MIME-Version: 1.0`.
  - `Subject:` with every line break and control character turned into a space first (so
    a subject can never add a header); non-ASCII text encoded as the standard requires.
  - Body: the text as UTF-8 plain text, safe for any line length and any characters
    (`.` at a line start and bare line feeds must arrive intact; the library's encoding
    takes care of it).
  - With an attachment: a multi-part message: the text first, then the file with its
    name and type as an attachment. A name with quotes or line breaks is made safe.
- **Addresses:** `from` and each recipient must be valid e-mail addresses; an invalid one is
  an error naming it.
- The session ends politely (QUIT) after a successful send.

## Callers to change (and nothing else)

- `mail_settings.rs`: `MailSettings::smtp_auth()` returns the new `SmtpAccount` (same
  fields, same rule: `None` when host or user is empty; `security()` as today); the test
  handler `post_smtp_test` calls `mail_send::send_test(...).await` directly (no
  `spawn_blocking`), with the same three answers (ok / 502 with the error / 500).
- `alert_mail.rs`: `send()` builds the account with `smtp_auth()` and calls
  `mail_send::send(...).await`; its `Attached` type maps onto `Attachment` (keep the
  function's signature so `tenant_reports.rs` needs no change).
- `provigil_manager.rs`: it writes `etc/smtp_auth.conf` for the old mail program, using
  the constant `siem_maild::smtp_ext::SMTP_AUTH_FILE`. Replace the constant by a local one
  with the same value `etc/smtp_auth.conf`; the file and its writing stay as they are.
- siem-api's `Cargo.toml`: add `lettre`. Keep `siem-maild` (other code still uses it).

## Tests

- message building, without a network: the `From` display name, `To` with two recipients,
  a subject containing `\r\nBcc: x@y.io` gives no `Bcc` header, a non-ASCII subject is
  encoded, the body comes through as UTF-8, an attachment appears with its name and type
- with a small fake SMTP server started inside the test (a local TCP listener that answers
  220 / 250 / 354 / 250 and records what it gets), security `none`:
  - a message to two recipients: both `RCPT TO` lines arrive, the subject and body arrive
  - the server refuses the second recipient (550): the error names that address
  - no recipient: error without connecting
- `security` other than `tls` / `starttls` / `none`: error
- `smtp_auth()` gives `None` without host or user, and the right security per port

Then: `cargo test -p siem-api --bin siem-api`, `cargo clippy -p siem-api --no-deps` with no
new warnings in the changed files, `cargo build -p siem-api`.
