//! Runtime mode and the drop guard behind `#[timed]`. `Off` (the default)
//! allocates nothing; `Live` streams per-function timings to the flux `Timer`
//! queues surfer reads; `Harness` records the cross-process flamegraph
//! call-tree rings in [`flamegraph_timer`](crate::flamegraph_timer).

use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

use flux::{Timer, timing::Instant};

use crate::{
    PerfSample,
    flamegraph_timer::{self, Event},
    perf,
};

/// What `#[timed]` does at runtime. `Off` (the default) allocates nothing — a
/// process that never opts in pays only one atomic load per call, so tests
/// running `#[timed]` prod code touch no shmem. `Live` streams to the
/// per-function flux `Timer` queues surfer reads; `Harness` records the
/// cross-process flamegraph call-tree rings (`flamegraph_timer::enable`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Mode {
    Off = 0,
    Live = 1,
    Harness = 2,
}

/// Process-global timing config: the runtime [`Mode`] and the app name used as
/// the parent dir for `#[timed]` shmem (`"silver"` until `init_app`).
pub(crate) struct Timing {
    mode: AtomicU8,
    app: OnceLock<String>,
}

pub(crate) static TIMING: Timing =
    Timing { mode: AtomicU8::new(Mode::Off as u8), app: OnceLock::new() };

impl Timing {
    pub(crate) fn mode(&self) -> Mode {
        match self.mode.load(Ordering::Acquire) {
            1 => Mode::Live,
            2 => Mode::Harness,
            _ => Mode::Off,
        }
    }

    pub(crate) fn is_harness(&self) -> bool {
        self.mode() == Mode::Harness
    }

    pub(crate) fn app(&self) -> &str {
        self.app.get().map(String::as_str).unwrap_or("silver")
    }

    fn set_live(&self) {
        let _ = self.mode.compare_exchange(
            Mode::Off as u8,
            Mode::Live as u8,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    pub(crate) fn set_harness(&self) {
        self.mode.store(Mode::Harness as u8, Ordering::Release);
    }
}

/// Publish the app name used by `#[timed]` shmem. Must be called at process
/// startup, before any `#[timed]` function fires. First set wins.
pub fn init_app(app_name: &str) {
    let _ = TIMING.app.set(app_name.to_owned());
}

/// Opt into live per-function timing for surfer. Call once at process startup;
/// without it `#[timed]` is inert. No-op once `Harness` mode is active.
pub fn enable_live() {
    TIMING.set_live();
}

fn new_timer(name: &str) -> Timer {
    Timer::new(TIMING.app(), name)
}

thread_local! {
    static TIMERS: RefCell<HashMap<&'static str, Timer>> = RefCell::new(HashMap::new());
}

/// Drop-based timer scope used by the `#[timed]` macro expansion.
/// Records processing time on every exit path — normal return, `?`,
/// early `return`, panic-unwind.
///
/// Built with the `perf` feature it also carries a hardware-counter
/// dimension: in harness (call-tree) mode the counters are captured inside
/// [`flamegraph_timer`]; in live mode this guard reads them itself and streams
/// a [`PerfSample`] onto the `perf-{name}` queue for surfer.
#[doc(hidden)]
pub struct TimerGuard {
    name: &'static str,
    start: Instant,
    /// Captured at construction so entry and exit always agree even if the
    /// process mode flips mid-call — a stray `stack_exit` would unbalance the
    /// flamegraph fold.
    mode: Mode,
    /// Counter snapshot at entry for live-mode streaming. `None` outside
    /// [`Mode::Live`], when this call is not sampled, or when the `perf`
    /// feature/`perf_event_open` is unavailable.
    perf_start: Option<PerfSample>,
}

impl TimerGuard {
    #[inline]
    pub fn new(name: &'static str) -> Self {
        Self::new_sampled(name, true)
    }

    /// As [`new`](Self::new) but `sample = false` skips this call's counter
    /// read/stream (timing is still recorded). Used by `#[timed(sample = N)]`.
    #[inline]
    pub fn new_sampled(name: &'static str, sample: bool) -> Self {
        let start = Instant::now();
        let mode = TIMING.mode();
        if mode == Mode::Harness {
            flamegraph_timer::record(Event::Open(name));
        }
        // Live mode reads counters itself; the harness sink captures them.
        let perf_start = (sample && mode == Mode::Live).then(perf::read).flatten();
        Self { name, start, mode, perf_start }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        match self.mode {
            Mode::Off => {}
            Mode::Harness => flamegraph_timer::record(Event::Close),
            Mode::Live => {
                TIMERS.with(|cell| {
                    let mut map = cell.borrow_mut();
                    let timer = map.entry(self.name).or_insert_with(|| new_timer(self.name));
                    timer.set_start(self.start);
                    timer.record_processing();
                });
                // Stream the call's counter delta for surfer (no-op without `perf`).
                if let (Some(start), Some(end)) = (self.perf_start, perf::read()) {
                    perf::emit(self.name, &end.delta(&start));
                }
            }
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

    #[timed(sample = 4)]
    fn timed_sampled(x: u64) -> u64 {
        x + 1
    }

    #[timed("timed_sampled_label", sample = 1000)]
    fn timed_sampled_named(x: u64) -> Result<u64, &'static str> {
        if x == 0 { Err("zero") } else { Ok(x * 2) }
    }

    /// The hardware-counter dimension is inert without the `perf` feature /
    /// perf access; either way the wrap must be transparent, including the
    /// sampled variants' skip path.
    #[test]
    fn timed_sampled_macro_expands_and_runs() {
        let _guard = ShmemGuard::new();

        // Cross the sampling boundary a few times.
        for i in 0..10 {
            assert_eq!(timed_sampled(i), i + 1);
        }
        assert_eq!(timed_sampled_named(0), Err("zero"));
        assert_eq!(timed_sampled_named(21), Ok(42));
    }
}
