use std::{fs, panic, path::PathBuf};

use silver_common::tracing::initialise_tracing_log;

#[test]
fn panic_reaches_the_log_file() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("panic-log");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    unsafe { std::env::set_var("LOG_PATH", &dir) };

    let guard = initialise_tracing_log("smoke", 1, None, false);
    let caught = panic::catch_unwind(|| panic!("marker-from-a-tile"));
    assert!(caught.is_err());
    drop(guard);

    let log = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    let body = fs::read_to_string(&log).unwrap();
    assert!(body.contains("marker-from-a-tile"), "{body}");
    assert!(body.contains("Full backtrace"), "{body}");
}
