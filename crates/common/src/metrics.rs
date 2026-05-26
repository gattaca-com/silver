//! Shmem-backed atomic counters. Each `declare_counters!` invocation
//! produces an enum + an `mmap(MAP_SHARED)`-backed `[AtomicU64; _Count]`
//! array. Multiple tile processes calling `<Enum>::init(base, app)` with
//! matching arguments share the same atomics; observers `mmap` the file
//! read-only and snapshot u64 values indexed by enum discriminant.
//!
//! # Stability
//! Variants are interpreted by *position*. Append new variants before
//! the `_Count` sentinel; never reorder or remove. Deprecated counters
//! should be renamed `_Reserved_*` to preserve slot indices for
//! external observers.

use std::{
    cell::RefCell,
    fs::OpenOptions,
    io,
    os::fd::AsRawFd,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicPtr, AtomicU64, Ordering},
    },
    thread::LocalKey,
};

use flux::{Timer, timing::Instant};
pub use silver_common_macros::timed;

/// App name used as the parent directory for per-function `Timer`
/// shmem queues. Falls back to `"silver"` if `init_app` is not called.
static APP_NAME: OnceLock<String> = OnceLock::new();

/// Publish the app name used by `#[timed]`-created `Timer`s. Must be
/// called at process startup, before any `#[timed]` function fires.
/// Repeat calls are no-ops (first set wins).
pub fn init_app(app_name: &str) {
    let _ = APP_NAME.set(app_name.to_owned());
}

/// Internal: construct a flux `Timer` under the app namespace published
/// by `init_app`. Used by `TimerGuard` on first hit.
#[doc(hidden)]
pub fn new_timer(name: &str) -> Timer {
    Timer::new(APP_NAME.get().map(String::as_str).unwrap_or("silver"), name)
}

/// Drop-based timer scope used by the `#[timed]` macro expansion.
/// Records processing time on every exit path — normal return, `?`,
/// early `return`, panic-unwind.
#[doc(hidden)]
pub struct TimerGuard {
    key: &'static LocalKey<RefCell<Option<Timer>>>,
    name: &'static str,
    start: Instant,
}

impl TimerGuard {
    #[inline]
    pub fn new(key: &'static LocalKey<RefCell<Option<Timer>>>, name: &'static str) -> Self {
        Self { key, name, start: Instant::now() }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        self.key.with(|cell| {
            let mut opt = cell.borrow_mut();
            let timer = opt.get_or_insert_with(|| new_timer(self.name));
            timer.set_start(self.start);
            timer.record_processing();
        });
    }
}

/// Open / create the counters file, ftruncate to `bytes`, mmap shared,
/// and publish the base pointer to `target`. No-op if `target` is
/// already non-null (idempotent across repeat `init()` calls).
///
/// Counter files land in flux's standard shmem-queues directory —
/// `{base_dir}/{app_name}/shmem/queues/counters-{file_name}` — so a
/// single observer-side scan picks up both flux queues and counter
/// files in one walk.
///
/// Called by macro-generated `init()` functions; not intended for
/// direct use.
pub fn map_counters(
    base_dir: &Path,
    app_name: &str,
    file_name: &str,
    bytes: usize,
    target: &AtomicPtr<AtomicU64>,
) -> io::Result<()> {
    if !target.load(Ordering::Relaxed).is_null() {
        return Ok(());
    }

    let dir = flux::utils::directories::shmem_dir_queues_with_base(base_dir, app_name);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("counters-{file_name}"));

    let file =
        OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
    file.set_len(bytes as u64)?;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    target.store(ptr.cast::<AtomicU64>(), Ordering::Release);
    Ok(())
}

/// Declare a shmem-backed counter enum.
///
/// Each invocation produces a `#[repr(u32)]` enum with a `_Count`
/// sentinel and methods `inc()`, `add(n)`, `dec()`, `get()`, `set(v)`
/// operating on `Relaxed` atomics in an `mmap(MAP_SHARED)` region.
/// `init(base_dir, app_name)` mmaps the backing file (idempotent).
///
/// # Example
/// ```ignore
/// silver_common::declare_counters! {
///     pub GossipCounters => "gossip" {
///         MsgsReceived,
///         MsgsValidated,
///         MsgsInvalid,
///     }
/// }
///
/// // Standard startup — uses `flux::utils::directories::local_share_dir()`.
/// GossipCounters::init("silver")?;
/// GossipCounters::MsgsReceived.inc();
///
/// // Tests / custom deployments override the base.
/// GossipCounters::init_with_base("/tmp/my_test", "silver")?;
/// ```
#[macro_export]
macro_rules! declare_counters {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident => $file:literal {
            $( $variant:ident ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(clippy::manual_non_exhaustive)]
        $vis enum $name {
            $( $variant, )+
            #[doc(hidden)]
            _Count,
        }

        impl $name {
            /// Number of counters (excludes the `_Count` sentinel).
            pub const COUNT: usize = Self::_Count as usize;
            /// Variant names in declaration order.
            pub const NAMES: &'static [&'static str] = &[ $( stringify!($variant), )+ ];

            const BYTES: usize =
                Self::COUNT * ::core::mem::size_of::<::core::sync::atomic::AtomicU64>();

            #[inline]
            fn shmem() -> &'static ::core::sync::atomic::AtomicPtr<::core::sync::atomic::AtomicU64> {
                static SHMEM: ::core::sync::atomic::AtomicPtr<::core::sync::atomic::AtomicU64> =
                    ::core::sync::atomic::AtomicPtr::new(::core::ptr::null_mut());
                &SHMEM
            }

            /// mmap the backing file under flux's default data
            /// directory (`local_share_dir()`). Call once per process
            /// at startup. Idempotent — repeat calls return Ok
            /// immediately.
            pub fn init(app_name: &str) -> ::std::io::Result<()> {
                Self::init_with_base(
                    ::flux::utils::directories::local_share_dir(),
                    app_name,
                )
            }

            /// As `init` but takes an explicit base directory.
            /// Primarily for tests / custom deployments.
            pub fn init_with_base<P: ::core::convert::AsRef<::std::path::Path>>(
                base_dir: P,
                app_name: &str,
            ) -> ::std::io::Result<()> {
                $crate::metrics::map_counters(
                    base_dir.as_ref(),
                    app_name,
                    $file,
                    Self::BYTES,
                    Self::shmem(),
                )
            }

            #[inline]
            fn slot(self) -> &'static ::core::sync::atomic::AtomicU64 {
                let p = Self::shmem().load(::core::sync::atomic::Ordering::Relaxed);
                debug_assert!(!p.is_null(), concat!(stringify!($name), "::init() not called"));
                unsafe { &*p.add(self as usize) }
            }

            #[inline]
            pub fn inc(self) {
                self.slot().fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn add(self, n: u64) {
                self.slot().fetch_add(n, ::core::sync::atomic::Ordering::Relaxed);
            }

            /// Wraps on underflow — use only on gauge-style counters.
            #[inline]
            pub fn dec(self) {
                self.slot().fetch_sub(1, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn get(self) -> u64 {
                self.slot().load(::core::sync::atomic::Ordering::Relaxed)
            }

            #[inline]
            pub fn set(self, v: u64) {
                self.slot().store(v, ::core::sync::atomic::Ordering::Relaxed);
            }
        }
    };
}

#[cfg(test)]
mod tests {
    crate::declare_counters! {
        TestCounters => "test_metrics" {
            Alpha,
            Beta,
            Gamma,
        }
    }

    #[test]
    fn round_trip() {
        let tmp = std::env::temp_dir().join(format!("silver_metrics_test_{}", std::process::id()));
        TestCounters::init_with_base(&tmp, "round_trip").unwrap();

        TestCounters::Alpha.set(0);
        TestCounters::Beta.set(0);
        TestCounters::Gamma.set(0);

        TestCounters::Alpha.inc();
        TestCounters::Alpha.add(5);
        assert_eq!(TestCounters::Alpha.get(), 6);

        TestCounters::Beta.set(100);
        TestCounters::Beta.dec();
        assert_eq!(TestCounters::Beta.get(), 99);

        assert_eq!(TestCounters::NAMES, &["Alpha", "Beta", "Gamma"]);
        assert_eq!(TestCounters::COUNT, 3);

        std::fs::remove_dir_all(&tmp).ok();
    }

    use crate::metrics::timed;

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
        // Sets the app namespace so the per-fn shmem queues land somewhere
        // predictable for the test run.
        super::init_app("silver_test");

        assert_eq!(timed_default_name(7), 14);
        assert_eq!(timed_custom_name(0), Err("zero"));
        assert_eq!(timed_custom_name(41), Ok(42));
    }
}
