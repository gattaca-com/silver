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

extern crate self as silver_metrics;

use std::{
    fs::OpenOptions,
    io,
    os::fd::AsRawFd,
    path::Path,
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
};

pub use silver_common_macros::timed;

pub mod flamegraph_timer;
mod perf;
mod timing;
pub(crate) use perf::Schema;
pub(crate) use timing::TIMING;
#[cfg(test)]
pub(crate) use timing::test_shmem;
pub use timing::{TimerGuard, init_app};

/// Open / create the counters file, ftruncate to `bytes`, mmap shared,
/// and return the base pointer. Counter files land in flux's standard
/// shmem-queues directory —
/// `{base_dir}/{app_name}/shmem/queues/counters-{file_name}` — so a single
/// observer-side scan picks up both flux queues and counter files in one walk.
pub fn mmap_counters_file(
    base_dir: &Path,
    app_name: &str,
    file_name: &str,
    bytes: usize,
) -> io::Result<*mut AtomicU64> {
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

    Ok(ptr.cast::<AtomicU64>())
}

/// As `mmap_counters_file` but publishes the result into a
/// `AtomicPtr` target — used by the static-pointer pattern emitted by
/// `declare_counters!`. No-op if `target` is already non-null.
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
    let ptr = mmap_counters_file(base_dir, app_name, file_name, bytes)?;
    target.store(ptr, Ordering::Release);
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
/// // No init needed for the common path — the first counter op
/// // auto-inits under `local_share_dir() / "silver" / shmem / queues`.
/// GossipCounters::MsgsReceived.inc();
///
/// // Optional: explicit init at startup surfaces mmap errors early.
/// GossipCounters::init()?;
///
/// // Override the app name or base for tests / custom deployments.
/// GossipCounters::init_with_app("custom_app")?;
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

            /// Default app name used by `init()` and auto-init on
            /// first counter access. Override via `init_with_app` /
            /// `init_with_base` if you need a different namespace.
            pub const DEFAULT_APP_NAME: &'static str = "silver";

            /// mmap the backing file under flux's default data
            /// directory (`local_share_dir()`) with app name
            /// `DEFAULT_APP_NAME` (silver). Call at process startup
            /// to surface mmap errors early; otherwise the first
            /// `inc`/`get`/etc. will auto-init the same way (panic
            /// on failure).
            pub fn init() -> ::std::io::Result<()> {
                Self::init_with_app(Self::DEFAULT_APP_NAME)
            }

            /// As `init` but with an explicit app name.
            pub fn init_with_app(app_name: &str) -> ::std::io::Result<()> {
                Self::init_with_base(
                    ::flux::utils::directories::local_share_dir(),
                    app_name,
                )
            }

            /// As `init` but takes an explicit base directory and app
            /// name. Primarily for tests / custom deployments.
            pub fn init_with_base<P: ::core::convert::AsRef<::std::path::Path>>(
                base_dir: P,
                app_name: &str,
            ) -> ::std::io::Result<()> {
                $crate::map_counters(
                    base_dir.as_ref(),
                    app_name,
                    $file,
                    Self::BYTES,
                    Self::shmem(),
                )
            }

            #[inline]
            fn slot(self) -> &'static ::core::sync::atomic::AtomicU64 {
                let mut p = Self::shmem().load(::core::sync::atomic::Ordering::Relaxed);
                if p.is_null() {
                    p = Self::lazy_init();
                }
                unsafe { &*p.add(self as usize) }
            }

            #[cold]
            #[inline(never)]
            fn lazy_init() -> *mut ::core::sync::atomic::AtomicU64 {
                Self::init().unwrap_or_else(|e| {
                    panic!(
                        "{}::init() failed: {e}",
                        ::core::stringify!($name),
                    )
                });
                Self::shmem().load(::core::sync::atomic::Ordering::Relaxed)
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

            /// Wraps on underflow — use only on gauge-style counters.
            #[inline]
            pub fn sub(self, n: u64) {
                self.slot().fetch_sub(n, ::core::sync::atomic::Ordering::Relaxed);
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

/// As `declare_counters!` but each thread gets its own instance: counter
/// ops touch a per-thread `mmap(MAP_SHARED)` region backed by a file named
/// `counters-{thread name}_{file}` (falling back to the thread id when the
/// thread is unnamed). One thread writes each file; the observer reads all of
/// them, so attribution is per-thread without cross-thread atomic contention.
///
/// Mapping is lazy: the first counter op on a thread maps that thread's file.
/// `init` / `init_with_base` force the map early (and let tests redirect the
/// base dir) for the calling thread only.
#[macro_export]
macro_rules! declare_thread_counters {
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
            pub const COUNT: usize = Self::_Count as usize;
            pub const NAMES: &'static [&'static str] = &[ $( stringify!($variant), )+ ];

            const BYTES: usize =
                Self::COUNT * ::core::mem::size_of::<::core::sync::atomic::AtomicI64>();

            pub const DEFAULT_APP_NAME: &'static str = "silver";

            fn map_for_thread(
                base_dir: &::std::path::Path,
                app_name: &str,
            ) -> ::std::io::Result<*mut ::core::sync::atomic::AtomicI64> {
                let thread = ::std::thread::current();
                let file_name = match thread.name() {
                    ::core::option::Option::Some(n) => ::std::format!("{n}_{}", $file),
                    ::core::option::Option::None => ::std::format!("{:?}_{}", thread.id(), $file),
                };
                $crate::mmap_counters_file(base_dir, app_name, &file_name, Self::BYTES)
                    .map(|p| p.cast::<::core::sync::atomic::AtomicI64>())
            }

            /// This thread's base pointer, invoking `map` to map the file on
            /// first use only. `map` is a `&dyn` (not generic) so the single
            /// `BASE` is shared across call sites, and is not evaluated on the
            /// warm path — keeping it allocation-free for use under a global
            /// allocator.
            fn base_with(
                map: &dyn ::core::ops::Fn() -> ::std::io::Result<*mut ::core::sync::atomic::AtomicI64>,
            ) -> ::std::io::Result<*mut ::core::sync::atomic::AtomicI64> {
                ::std::thread_local! {
                    static BASE: ::core::cell::Cell<*mut ::core::sync::atomic::AtomicI64> =
                        const { ::core::cell::Cell::new(::core::ptr::null_mut()) };
                }
                BASE.with(|c| {
                    let p = c.get();
                    if !p.is_null() {
                        return ::core::result::Result::Ok(p);
                    }
                    let ptr = map()?;
                    c.set(ptr);
                    ::core::result::Result::Ok(ptr)
                })
            }

            pub fn init() -> ::std::io::Result<()> {
                Self::init_with_app(Self::DEFAULT_APP_NAME)
            }

            pub fn init_with_app(app_name: &str) -> ::std::io::Result<()> {
                Self::init_with_base(
                    ::flux::utils::directories::local_share_dir(),
                    app_name,
                )
            }

            pub fn init_with_base<P: ::core::convert::AsRef<::std::path::Path>>(
                base_dir: P,
                app_name: &str,
            ) -> ::std::io::Result<()> {
                let base_dir = base_dir.as_ref();
                Self::base_with(&|| Self::map_for_thread(base_dir, app_name)).map(|_| ())
            }

            #[inline]
            fn slot(self) -> &'static ::core::sync::atomic::AtomicI64 {
                let p = Self::base_with(&|| {
                    Self::map_for_thread(
                        ::flux::utils::directories::local_share_dir().as_ref(),
                        Self::DEFAULT_APP_NAME,
                    )
                })
                .unwrap_or_else(|e| {
                    panic!("{}::slot() failed: {e}", ::core::stringify!($name))
                });
                unsafe { &*p.add(self as usize) }
            }

            #[inline]
            pub fn inc(self) {
                self.slot().fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn add(self, n: i64) {
                self.slot().fetch_add(n, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn dec(self) {
                self.slot().fetch_sub(1, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn sub(self, n: i64) {
                self.slot().fetch_sub(n, ::core::sync::atomic::Ordering::Relaxed);
            }

            #[inline]
            pub fn get(self) -> i64 {
                self.slot().load(::core::sync::atomic::Ordering::Relaxed)
            }

            #[inline]
            pub fn set(self, v: i64) {
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

    crate::declare_thread_counters! {
        TestThreadCounters => "test_thread_metrics" {
            Hits,
            Misses,
        }
    }

    #[test]
    fn thread_counters_are_per_thread() {
        let tmp = std::env::temp_dir().join(format!("silver_thread_test_{}", std::process::id()));

        // Each thread maps its own file; counts must not bleed across threads.
        let run = |name: &str, hits: i64| {
            let tmp = tmp.clone();
            let name = name.to_owned();
            std::thread::Builder::new()
                .name(name.clone())
                .spawn(move || {
                    TestThreadCounters::init_with_base(&tmp, "thread_rt").unwrap();
                    TestThreadCounters::Hits.set(0);
                    TestThreadCounters::Misses.set(1);
                    TestThreadCounters::Hits.add(hits);
                    assert_eq!(TestThreadCounters::Hits.get(), hits);
                    // i64 gauge: sub past zero goes negative (not wraparound).
                    TestThreadCounters::Misses.sub(5);
                    assert_eq!(TestThreadCounters::Misses.get(), -4);
                    name
                })
                .unwrap()
                .join()
                .unwrap()
        };

        let a = run("alpha", 3);
        let b = run("beta", 7);

        let dir = flux::utils::directories::shmem_dir_queues_with_base(&tmp, "thread_rt");
        assert!(dir.join(format!("counters-{a}_test_thread_metrics")).exists());
        assert!(dir.join(format!("counters-{b}_test_thread_metrics")).exists());

        assert_eq!(TestThreadCounters::NAMES, &["Hits", "Misses"]);
        assert_eq!(TestThreadCounters::COUNT, 2);

        std::fs::remove_dir_all(&tmp).ok();
    }

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
        // Sets the app namespace so the per-fn shmem queues land somewhere
        // predictable for the test run.
        super::init_app("silver_test");

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
        super::init_app("silver_test");

        // Cross the sampling boundary a few times.
        for i in 0..10 {
            assert_eq!(timed_sampled(i), i + 1);
        }
        assert_eq!(timed_sampled_named(0), Err("zero"));
        assert_eq!(timed_sampled_named(21), Ok(42));
    }
}
