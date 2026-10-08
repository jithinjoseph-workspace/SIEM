// Wazuh's Makefile: ${OSSEC_CC} ${OSSEC_CFLAGS} -w -fPIC -DSQLITE_ENABLE_DBSTAT_VTAB=1 -c sqlite3.c
fn main() {
    println!("cargo:rerun-if-changed=sqlite/sqlite3.c");
    println!("cargo:rerun-if-changed=sqlite/sqlite3.h");
    println!("cargo:rerun-if-changed=sqlite/siem_fixed_time.c");
    cc::Build::new()
        .file("sqlite/sqlite3.c")
        .file("sqlite/siem_fixed_time.c")
        .define("SQLITE_ENABLE_DBSTAT_VTAB", "1")
        .warnings(false)
        .opt_level(2)
        .compile("sqlite3");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "windows" {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        if os == "linux" {
            println!("cargo:rustc-link-lib=dl");
        }
    }
}
