//! The exceptions dbsync and rsync throw, as a `Result` error.

/// A C++ exception, by the `catch` clauses that tell them apart.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// `DbSync::dbsync_error` (and its `dbengine_error` / `sqlite_error`
    /// subclasses, whose `what()` carries the "dbEngine: " / "sqlite: "
    /// prefix).
    DbSync { id: i32, what: Vec<u8> },
    /// `DbSync::max_rows_error`
    MaxRows(Vec<u8>),
    /// `nlohmann::detail::exception` (`what()`; the id is in the text).
    Json(Vec<u8>),
    /// `RSync::rsync_error`
    Rsync { id: i32, what: Vec<u8> },
    /// Any other `std::exception` (`std::invalid_argument("stoll")`,
    /// `std::runtime_error`, ...).
    Std(Vec<u8>),
}

pub type R<T = ()> = Result<T, Error>;

impl Error {
    /// `what()`
    pub fn what(&self) -> &[u8] {
        match self {
            Error::DbSync { what, .. } | Error::Rsync { what, .. } => what,
            Error::MaxRows(w) | Error::Json(w) | Error::Std(w) => w,
        }
    }

    /// `dbsync_error(pair)`
    pub fn dbsync(e: (i32, &str)) -> Error {
        Error::DbSync { id: e.0, what: e.1.as_bytes().to_vec() }
    }

    /// `dbengine_error(pair)`
    pub fn dbengine(e: (i32, &str)) -> Error {
        Error::DbSync { id: e.0, what: [b"dbEngine: ".as_slice(), e.1.as_bytes()].concat() }
    }

    /// `sqlite_error(pair)`
    pub fn sqlite(code: i32, msg: &[u8]) -> Error {
        Error::DbSync { id: code, what: [b"sqlite: ".as_slice(), msg].concat() }
    }

    /// `rsync_error(pair)`
    pub fn rsync(e: (i32, &str)) -> Error {
        Error::Rsync { id: e.0, what: e.1.as_bytes().to_vec() }
    }

    pub fn std(what: impl AsRef<[u8]>) -> Error {
        Error::Std(what.as_ref().to_vec())
    }

    /// `ex.id` of a JSON exception.
    pub fn json_id(&self) -> i32 {
        match self {
            Error::Json(w) => siem_njson::exception_id(w),
            _ => 0,
        }
    }
}

/// nlohmann exceptions from siem-njson's `what()` strings.
pub fn j<T>(r: Result<T, Vec<u8>>) -> R<T> {
    r.map_err(Error::Json)
}

// db_exception.h
pub const FACTORY_INSTANTATION: (i32, &str) = (1, "Unspecified type during factory instantiation");
pub const INVALID_HANDLE: (i32, &str) = (2, "Invalid handle value.");
pub const INVALID_TRANSACTION: (i32, &str) = (3, "Invalid transaction value.");
pub const SQLITE_CONNECTION_ERROR: (i32, &str) = (4, "No connection available for executions.");
pub const EMPTY_DATABASE_PATH: (i32, &str) = (5, "Empty database store path.");
pub const EMPTY_TABLE_METADATA: (i32, &str) = (6, "Empty table metadata.");
pub const INVALID_PARAMETERS: (i32, &str) = (7, "Invalid parameters.");
pub const DATATYPE_NOT_IMPLEMENTED: (i32, &str) = (8, "Datatype not implemented.");
pub const SQL_STMT_ERROR: (i32, &str) = (9, "Invalid SQL statement.");
pub const INVALID_PK_DATA: (i32, &str) = (10, "Primary key not found.");
pub const INVALID_COLUMN_TYPE: (i32, &str) = (11, "Invalid column field type.");
pub const INVALID_DATA_BIND: (i32, &str) = (12, "Invalid data to bind.");
pub const INVALID_TABLE: (i32, &str) = (13, "Invalid table.");
pub const INVALID_DELETE_INFO: (i32, &str) = (14, "Invalid information provided for deletion.");
pub const BIND_FIELDS_DOES_NOT_MATCH: (i32, &str) = (15, "Invalid information provided for statement creation.");
pub const STEP_ERROR_CREATE_STMT: (i32, &str) = (16, "Error creating table.");
pub const STEP_ERROR_ADD_STATUS_FIELD: (i32, &str) = (17, "Error adding status field.");
pub const STEP_ERROR_UPDATE_STATUS_FIELD: (i32, &str) = (18, "Error updating status field.");
pub const STEP_ERROR_DELETE_STATUS_FIELD: (i32, &str) = (19, "Error deleting status field.");
pub const DELETE_OLD_DB_ERROR: (i32, &str) = (20, "Error deleting old db.");
pub const MIN_ROW_LIMIT_BELOW_ZERO: (i32, &str) = (21, "Invalid row limit, values below 0 not allowed.");
pub const ERROR_COUNT_MAX_ROWS: (i32, &str) = (22, "Count is less than 0.");
pub const STEP_ERROR_UPDATE_STMT: (i32, &str) = (23, "Error upgrading DB.");

/// `SQLite::MAX_ROWS_ERROR_STRING`
pub const MAX_ROWS_ERROR_STRING: &str = "Too Many Rows.";

// rsync_exception.h
pub const RSYNC_INVALID_HANDLE: (i32, &str) = (1, "Invalid handle value.");
pub const RSYNC_FACTORY_INSTANTATION: (i32, &str) = (2, "Unspecified type during factory instantiation");
pub const RSYNC_INVALID_HEADER: (i32, &str) = (3, "Invalid message header.");
pub const RSYNC_INVALID_OPERATION: (i32, &str) = (4, "Invalid message operation.");
pub const RSYNC_UNEXPECTED_SIZE: (i32, &str) = (5, "Unexpected size value during sync process.");
pub const RSYNC_ERROR_IN_SELECT_DATA: (i32, &str) = (6, "Error during the select of data.");
pub const RSYNC_NOT_SPECIALIZED_FUNCTION: (i32, &str) = (7, "Function not specialized.");
pub const RSYNC_INPUT_JSON_INCOMPLETE: (i32, &str) = (8, "Incomplete json provided.");
pub const RSYNC_COMPONENT_ALREADY_REGISTERED: (i32, &str) = (9, "Component already registered.");
pub const RSYNC_HANDLE_NOT_FOUND: (i32, &str) = (10, "Handle not found.");
