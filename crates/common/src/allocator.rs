#[cfg(feature = "alloc-profile")]
mod profile_impl {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        collections::HashMap,
        sync::{Mutex, OnceLock},
    };

    #[derive(Debug, Clone, Hash, Eq, PartialEq)]
    pub struct CallPoint {
        pub file: String,
        pub line: u32,
        pub function: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct AllocStats {
        pub count: u64,
        pub bytes: u64,
    }

    static ALLOC_STATS: OnceLock<Mutex<HashMap<CallPoint, AllocStats>>> = OnceLock::new();
    static TLS_KEY: OnceLock<libc::pthread_key_t> = OnceLock::new();
    const SYMBOL_ONLY_FILE: &str = "<release symbols>";
    const SILVER_SYMBOL_PREFIXES: &[&str] = &[
        "silver::",
        "silver_beacon_state::",
        "silver_beacon_state_data::",
        "silver_chain_spec::",
        "silver_common::",
        "silver_config::",
        "silver_control::",
        "silver_discovery::",
        "silver_e2e::",
        "silver_engine::",
        "silver_gossip::",
        "silver_metrics::",
        "silver_network::",
        "silver_peer::",
        "silver_ssz::",
        "silver_storage::",
        "silver_surfer::",
    ];

    fn get_stats() -> &'static Mutex<HashMap<CallPoint, AllocStats>> {
        ALLOC_STATS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn get_tls_key() -> libc::pthread_key_t {
        *TLS_KEY.get_or_init(|| {
            let mut key = 0;
            unsafe {
                libc::pthread_key_create(&mut key, None);
            }
            key
        })
    }

    pub fn is_reentrant() -> bool {
        let key = get_tls_key();
        unsafe {
            let ptr = libc::pthread_getspecific(key);
            !ptr.is_null()
        }
    }

    pub fn set_reentrant(val: bool) {
        let key = get_tls_key();
        unsafe {
            if val {
                libc::pthread_setspecific(key, std::ptr::dangling::<libc::c_void>());
            } else {
                libc::pthread_setspecific(key, std::ptr::null());
            }
        }
    }

    fn is_silver_path(path_str: &str) -> bool {
        (path_str.contains("silver/crates/") ||
            path_str.starts_with("crates/") ||
            path_str.contains("/crates/")) &&
            !path_str.contains("allocator.rs") &&
            !path_str.contains(".cargo") &&
            !path_str.contains(".rustup")
    }

    fn is_silver_symbol(function: &str) -> bool {
        let function = function.trim_start_matches('<');
        !function.contains("silver_common::allocator::") &&
            SILVER_SYMBOL_PREFIXES.iter().any(|prefix| function.starts_with(prefix))
    }

    fn call_point_from_symbol(
        filename: Option<&str>,
        line: Option<u32>,
        function: Option<String>,
    ) -> Option<CallPoint> {
        if let Some(path_str) = filename &&
            is_silver_path(path_str)
        {
            return Some(CallPoint {
                file: path_str.to_string(),
                line: line.unwrap_or(0),
                function,
            });
        }

        let function = function?;
        if is_silver_symbol(&function) {
            return Some(CallPoint {
                file: SYMBOL_ONLY_FILE.to_string(),
                line: 0,
                function: Some(function),
            });
        }

        None
    }

    fn record_allocation(size: usize) {
        if is_reentrant() {
            return;
        }
        set_reentrant(true);

        backtrace::trace(|frame| {
            let mut found = false;
            backtrace::resolve_frame(frame, |symbol| {
                let filename = symbol.filename().and_then(|filename| filename.to_str());
                let function = symbol.name().map(|name| format!("{:#}", name));
                if let Some(call_point) =
                    call_point_from_symbol(filename, symbol.lineno(), function)
                {
                    let stats = get_stats();
                    if let Ok(mut map) = stats.lock() {
                        let entry =
                            map.entry(call_point).or_insert(AllocStats { count: 0, bytes: 0 });
                        entry.count += 1;
                        entry.bytes += size as u64;
                    }
                    found = true;
                }
            });
            !found
        });

        set_reentrant(false);
    }

    pub struct ProfilingAllocator;

    unsafe impl GlobalAlloc for ProfilingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                record_allocation(layout.size());
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc_zeroed(layout) };
            if !ptr.is_null() {
                record_allocation(layout.size());
            }
            ptr
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let ptr = unsafe { System.realloc(ptr, layout, new_size) };
            if !ptr.is_null() {
                record_allocation(new_size);
            }
            ptr
        }
    }

    #[global_allocator]
    static ALLOCATOR: ProfilingAllocator = ProfilingAllocator;

    pub fn print_allocations() {
        if is_reentrant() {
            return;
        }
        set_reentrant(true);

        let stats = get_stats();
        if let Ok(map) = stats.lock() {
            if map.is_empty() {
                println!("\n=== Memory Profiler: No allocations recorded in silver code ===");
            } else {
                println!("\n=== Memory Profiler: Allocation Report ===");
                let mut list: Vec<(&CallPoint, &AllocStats)> = map.iter().collect();
                list.sort_by(|a, b| {
                    b.1.bytes.cmp(&a.1.bytes).then_with(|| b.1.count.cmp(&a.1.count))
                });

                println!(
                    "{:<12} | {:<15} | {:<60} ",
                    "Invocations", "Bytes Allocated", "Call Point"
                );
                println!("{}", "-".repeat(95));
                for (cp, stat) in list {
                    let func_name = cp.function.as_deref().unwrap_or("<unknown>");
                    let call_str = if cp.file == SYMBOL_ONLY_FILE {
                        format!("{func_name} ({SYMBOL_ONLY_FILE})")
                    } else {
                        let display_file = if let Some(idx) = cp.file.find("crates/") {
                            &cp.file[idx..]
                        } else {
                            &cp.file
                        };
                        format!("{func_name} ({display_file}:{})", cp.line)
                    };
                    println!("{:<12} | {:<15} | {:<60}", stat.count, stat.bytes, call_str);
                }
                println!("==========================================\n");
            }
        }

        set_reentrant(false);
    }

    pub struct AllocProfileGuard;

    impl Drop for AllocProfileGuard {
        fn drop(&mut self) {
            print_allocations();
        }
    }

    pub fn init_allocator_trace() -> AllocProfileGuard {
        AllocProfileGuard
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_release_symbols_from_workspace_crates() {
            assert!(is_silver_symbol("silver::main"));
            assert!(is_silver_symbol("silver_storage::store::Store::add_block"));
            assert!(is_silver_symbol("<silver_network::P2p as core::fmt::Debug>::fmt"));
        }

        #[test]
        fn rejects_allocator_and_dependency_symbols() {
            assert!(!is_silver_symbol("silver_common::allocator::profile_impl::record_allocation"));
            assert!(!is_silver_symbol("alloc::raw_vec::RawVec<T,A>::grow_one"));
            assert!(!is_silver_symbol("backtrace::backtrace::libunwind::trace"));
        }

        #[test]
        fn call_point_prefers_debug_file_info() {
            let call_point = call_point_from_symbol(
                Some("/home/vlad/repoz/silver/crates/storage/src/store.rs"),
                Some(42),
                Some("silver_storage::store::Store::add_block".to_string()),
            )
            .unwrap();

            assert_eq!(call_point.file, "/home/vlad/repoz/silver/crates/storage/src/store.rs");
            assert_eq!(call_point.line, 42);
        }

        #[test]
        fn call_point_falls_back_to_release_symbols() {
            let call_point = call_point_from_symbol(
                None,
                None,
                Some("silver_storage::store::Store::add_block".to_string()),
            )
            .unwrap();

            assert_eq!(call_point.file, SYMBOL_ONLY_FILE);
            assert_eq!(call_point.line, 0);
        }
    }
}

#[cfg(feature = "alloc-profile")]
pub use profile_impl::{AllocProfileGuard, init_allocator_trace, print_allocations};

#[cfg(not(feature = "alloc-profile"))]
pub fn print_allocations() {
    // No-op
}

silver_metrics::declare_thread_counters! {
    pub AllocationCounters => "allocator" {
        Allocated,
    }
}

// CountingAllocator is the default global allocator; alloc-profile swaps in
// ProfilingAllocator instead (only one #[global_allocator] may exist). The
// AllocationCounters enum above is always compiled so surfer can resolve its
// NAMES regardless of feature set.
#[cfg(not(feature = "alloc-profile"))]
mod count_impl {
    use std::alloc::{GlobalAlloc, Layout, System};

    use super::AllocationCounters;

    pub struct CountingAllocator;

    std::thread_local! {
        // The thread counter's first-touch path mmaps a file, which allocates and
        // would re-enter this allocator. const-init + Copy => no lazy init / no
        // destructor, so the guard itself never allocates. Counter updates made
        // while it is set are skipped.
        static COUNTING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    impl CountingAllocator {
        #[inline]
        fn count(f: impl FnOnce()) {
            if COUNTING.with(|c| c.replace(true)) {
                return;
            }
            f();
            COUNTING.with(|c| c.set(false));
        }
    }

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                Self::count(|| AllocationCounters::Allocated.add(layout.size() as u64));
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            Self::count(|| AllocationCounters::Allocated.sub(layout.size() as u64));
            unsafe { System.dealloc(ptr, layout) };
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc_zeroed(layout) };
            if !ptr.is_null() {
                Self::count(|| AllocationCounters::Allocated.add(layout.size() as u64));
            }
            ptr
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let ptr = unsafe { System.realloc(ptr, layout, new_size) };
            if !ptr.is_null() {
                Self::count(|| {
                    if new_size > layout.size() {
                        AllocationCounters::Allocated.add((new_size - layout.size()) as u64);
                    } else {
                        AllocationCounters::Allocated.sub((layout.size() - new_size) as u64);
                    }
                });
            }
            ptr
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;
}

#[cfg(not(feature = "alloc-profile"))]
pub use count_impl::CountingAllocator;
