use std::{fs, panic};

use silver_common::tracing::initialise_tracing_log;
use tempfile::TempDir;

#[test]
fn panic_reaches_the_log_file() {
    let dir = TempDir::new().unwrap();
    unsafe { std::env::set_var("LOG_PATH", dir.path()) };

    let guard = initialise_tracing_log("smoke", 1, None, false);
    let caught = panic::catch_unwind(|| panic!("marker-from-a-tile"));
    assert!(caught.is_err());
    drop(guard);

    let log = fs::read_dir(dir.path()).unwrap().next().unwrap().unwrap().path();
    let body = fs::read_to_string(&log).unwrap();
    assert!(body.contains("marker-from-a-tile"), "{body}");
    assert!(body.contains("Full backtrace"), "{body}");
}
