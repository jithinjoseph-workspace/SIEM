# siem-dbsync

Port of Wazuh 4.14.7's `shared_modules/dbsync` and `shared_modules/rsync`:
the agent-side inventory engine (syscollector, FIM) and the integrity sync
protocol that runs on top of it.

| Module | Wazuh source |
| --- | --- |
| `engine.rs` | `dbsync/src/sqlite/sqlite_dbengine.cpp` |
| `sqlite.rs` | `dbsync/src/sqlite/sqlite_wrapper.cpp` (SQLite 3.50.4 via `siem-sqlite`) |
| `dbsync.rs` | `dbsync_implementation.cpp`, `dbsyncPipelineFactory.cpp`, the C++ API of `dbsync.cpp` / `dbsync.hpp` |
| `capi.rs` | the C API of `dbsync.cpp` (cJSON in and out through `siem-cjson`) |
| `rsync.rs` | `rsync.cpp`, `rsyncImplementation.cpp`, the message creators and decoders, `msgDispatcher.h` / `threadDispatcher.h` |
| `cconv.rs` | `std::stoi` / `stoll` / `stoull` / `stod`, `std::to_string(double)` |
| `error.rs` | `db_exception.h`, `rsync_exception.h` |

JSON follows nlohmann 3.11.2: `siem-njson` plus its `ops` module, which
covers `operator[]`, `get<T>` conversions, `operator==` across number
types and the exact exception texts. C++ exceptions are `Error` values,
and each C API function's `catch` clauses are kept. The `std::cerr` lines
go through `set_cerr_hook`. rsync's `std::time` can be pinned with
`rsync::set_clock`.

Faithful details include some that look like bugs:

* **Snapshot deletes keep the rows.** `getPKListLeftOnly` reads every
  primary key from column 0, so `updateWithSnapshot` reports deleted rows
  but leaves them in the table.
* **Values are put into SQL unescaped.** Modified rows of a snapshot are
  updated with literal SQL. Text is quoted without escaping, and doubles
  are written with `%f`.
* **Lenient type conversions.** A JSON integer bound to a DOUBLE column
  binds 0.0. A signed integer bound to an UNSIGNED BIGINT column binds 0.
  Strings go through `stoll` and friends.
* **Transactions:**
  * After `getDeletedRows` the dispatch node is stopped, so the
    transaction's later results are dropped.
  * Rows the snapshot copy inserts come back with the
    `db_status_field_dm` column.
  * Getting deleted rows on a persistent database that was already at
    its version has no open transaction. The C++ crashes there; this port
    panics.
* **rsync:**
  * `rsync_close` / `rsync_teardown` deregister a component, or clear the
    sync ids, before draining the queue. Messages still queued then fail
    with "Synchronization cancelled, component inactivated" or "Handle
    not found.".
  * A `begin` equal to "" makes a single-row `checksum_fail` fall back
    to the start query.

## Verification

`tools/oracle/build.sh <wazuh src> <nlohmann> <cJSON> <sqlite 3.50.4>` builds
`~/dbsync_oracle/dbsync_oracle` (in WSL) from `dbsync_harness.cpp` and
Wazuh's dbsync and rsync sources. The harness runs a script of C API calls
against the real dbsync/rsync and prints:

* return values;
* the dbsync and rsync logs, and the full log;
* callbacks, rsync payloads and `std::cerr` lines;
* every row of the database files.

`tests/dbsync_oracle.rs` runs the same script through this crate and
compares the two outputs. The corpus covers every function on good and
bad input, plus seeded mutations of the JSON inputs, rsync configurations
and protocol messages. Run it with
`SIEM_DBSYNC_ORACLE=~/dbsync_oracle/dbsync_oracle`, plus optionally
`SIEM_DBSYNC_FUZZ`, `SIEM_DBSYNC_SEED` and `SIEM_DBSYNC_KEEP`.

The scripts pause 300 ms before each `rsync_close` / `rsync_teardown`, so
the races above do not decide the outcome.
