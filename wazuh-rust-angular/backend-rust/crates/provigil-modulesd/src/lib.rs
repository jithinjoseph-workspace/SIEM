//! The manager modules service (spec `specs/provigil-modulesd.md`): the database module (agents
//! and groups in global.db), the message router and the vulnerability scanner.

pub mod database;
pub mod host;
pub mod router;
