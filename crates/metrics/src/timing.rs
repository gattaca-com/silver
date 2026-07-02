//! Runtime on/off switch and the drop guard behind `#[timed]`. Off (the
//! default) allocates nothing — one atomic load per call, so tests running
//! `#[timed]` prod code touch no shmem. Enabled, the guard records a frame
//! open/close into the cross-process flamegraph rings in
//! [`flamegraph_timer`](crate::flamegraph_timer); hardware counters (with the
//! `perf` feature) ride alongside each mark there.

use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

use crate::flamegraph_timer;

/// Process-global `#[timed]` config: whether marks are produced, and the app
/// name used as the parent dir for the shmem rings (`"silver"` until
/// `init_app`).
pub(crate) struct Timing {
    enabled: AtomicBool,
    app: OnceLock<String>,
}

pub(crate) static TIMING: Timing = Timing { enabled: AtomicBool::new(false), app: OnceLock::new() };

impl Timing {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn app(&self) -> &str {
        self.app.get().map(String::as_str).unwrap_or("silver")
    }

    pub(crate) fn set_enabled(&self) {
        self.enabled.store(true, Ordering::Release);
    }
}

/// Publish the app name used by `#[timed]` shmem. Must be called at process
/// startup, before any `#[timed]` function fires. First set wins.
pub fn init_app(app_name: &str) {
    let _ = TIMING.app.set(app_name.to_owned());
}

/// Drop-based timer scope used by the `#[timed]` macro expansion. Records a
/// frame open on construction and a close on every exit path — normal return,
/// `?`, early `return`, panic-unwind.
#[doc(hidden)]
pub struct TimerGuard {
    /// `Some(name)` iff the open was recorded — captured at construction so a
    /// mid-call enable can't make `drop` emit a close with no matching open and
    /// unbalance the flamegraph fold. The close reuses `name`, so its id pairs
    /// with the open's by construction.
    close: Option<&'static str>,
}

impl TimerGuard {
    #[inline]
    pub fn new(name: &'static str) -> Self {
        let close = TIMING.is_enabled().then_some(name);
        if let Some(name) = close {
            flamegraph_timer::record_open(name);
        }
        Self { close }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if let Some(name) = self.close {
            flamegraph_timer::record_close(name);
        }
    }
}

/// Isolates each test process's collection shmem under a per-pid app and
/// unlinks it once the last guarded test in the process exits — normal return
/// or unwinding panic. Without this, every test that produces marks leaks its
/// rings into `/dev/shm` (a crashed swarm filled it and took down other
/// Chromium apps); with tiny `cfg(test)` rings the leak is also bounded.
#[cfg(test)]
pub(crate) mod test_shmem {
    use std::sync::{Mutex, MutexGuard};

    use flux::{communication::cleanup::cleanup_shmem, utils::directories::local_share_dir};

    /// Timing tests drive the process-global mode + reader and share one shmem
    /// dir, so they must run one at a time. nextest isolates per process;
    /// `cargo test` runs them as threads, so serialize here.
    static SERIAL: Mutex<()> = Mutex::new(());

    pub(crate) struct ShmemGuard {
        _serial: MutexGuard<'static, ()>,
    }

    impl ShmemGuard {
        pub(crate) fn new() -> Self {
            let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            super::init_app(&format!("silver_test_{}", std::process::id()));
            ShmemGuard { _serial: serial }
        }
    }

    impl Drop for ShmemGuard {
        fn drop(&mut self) {
            if let Some(app) = super::TIMING.app.get() {
                cleanup_shmem(&local_share_dir().join(app));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_shmem::ShmemGuard;
    use crate::timed;

    #[timed]
    fn timed_default_name(x: u64) -> u64 {
        x * 2
    }

    #[timed("custom_label")]
    fn timed_custom_name(x: u64) -> Result<u64, &'static str> {
        if x == 0 { Err("zero") } else { Ok(x + 1) }
    }

    #[test]
    fn timed_macro_expands_and_runs() {
        let _guard = ShmemGuard::new();

        assert_eq!(timed_default_name(7), 14);
        assert_eq!(timed_custom_name(0), Err("zero"));
        assert_eq!(timed_custom_name(41), Ok(42));
    }
}
