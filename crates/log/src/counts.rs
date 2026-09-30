//! Every `silver_log::warn!`/`error!` callsite has a counter in `counters-log`,
//! labelled by `log-names`. Counting is one atomic add; the message itself
//! stays in the log file.

use std::{fs, io, path::PathBuf, slice, sync::atomic::AtomicU64};

use flux::utils::directories::{local_share_dir, shmem_dir_queues};
use silver_metrics::mmap_counters_file;

pub use self::names::LogName;
use crate::LOG_SITES;

mod names;

const COUNTERS_FILE: &str = "log";

pub fn counters_path(app_name: &str) -> PathBuf {
    shmem_dir_queues(app_name).join(format!("counters-{COUNTERS_FILE}"))
}

pub fn names_path(app_name: &str) -> PathBuf {
    shmem_dir_queues(app_name).join("log-names")
}

/// The names land before the counters, and the counters file is recreated, so
/// every run starts at zero.
pub fn enable(app_name: &str) -> io::Result<()> {
    fs::create_dir_all(shmem_dir_queues(app_name))?;
    LogName::write(&names_path(app_name), &LOG_SITES)?;

    let path = counters_path(app_name);
    match fs::remove_file(&path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let len = LOG_SITES.len();
    let base = mmap_counters_file(
        &local_share_dir(),
        app_name,
        COUNTERS_FILE,
        len * size_of::<AtomicU64>(),
    )?;
    crate::attach(unsafe { slice::from_raw_parts(base.cast_const(), len) });
    Ok(())
}
