//! Common definitions, return types, and constants for Wazuh shared modules.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnType {
    Success = 0,
    GenericError = 1,
    InvalidParam = 2,
    DatabaseError = 3,
    NetworkError = 4,
    Timeout = 5,
    BufferFull = 6,
    NotFound = 7,
    Conflict = 8,
}

impl fmt::Display for ReturnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReturnType::Success => write!(f, "SUCCESS"),
            ReturnType::GenericError => write!(f, "GENERIC_ERROR"),
            ReturnType::InvalidParam => write!(f, "INVALID_PARAM"),
            ReturnType::DatabaseError => write!(f, "DATABASE_ERROR"),
            ReturnType::NetworkError => write!(f, "NETWORK_ERROR"),
            ReturnType::Timeout => write!(f, "TIMEOUT"),
            ReturnType::BufferFull => write!(f, "BUFFER_FULL"),
            ReturnType::NotFound => write!(f, "NOT_FOUND"),
            ReturnType::Conflict => write!(f, "CONFLICT"),
        }
    }
}

pub type Result<T> = std::result::Result<T, SharedModuleError>;

#[derive(thiserror::Error, Debug)]
pub enum SharedModuleError {
    #[error("Shared module error ({0}): {1}")]
    Failure(ReturnType, String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(String),
}
