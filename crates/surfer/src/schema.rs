//! Compile-time NAMES lookup. Each `declare_counters!` enum exposes
//! `pub const NAMES: &'static [&'static str]`. Adding a new counter
//! enum to silver = one line here. Files without a registered schema
//! fall back to positional `slot_{i}` labels.

/// Map from file suffix (the `{name}` in `counters-{name}`) to the
/// variant name array. Add lines here as silver crates declare counter
/// enums via `silver_common::declare_counters!`.
pub fn lookup(file_name: &str) -> Option<&'static [&'static str]> {
    match file_name {
        "storage" => return Some(silver_storage::StorageCounters::NAMES),
        "network" => return Some(silver_network::NetworkCounters::NAMES),
        "peer" => return Some(silver_peer::PeerCounters::NAMES),
        _ => {}
    }
    // Thread counters write one file per thread, named "{thread}_{group}".
    for (group, names) in THREAD_COUNTERS {
        if let Some(thread) = file_name.strip_suffix(group) &&
            thread.ends_with('_')
        {
            return Some(names);
        }
    }
    None
}

/// `(group, NAMES)` for each `declare_thread_counters!` enum. `group` is the
/// `{file}` literal; matched as the `_{group}` suffix of
/// `counters-{thread}_{group}`.
const THREAD_COUNTERS: &[(&str, &[&str])] =
    &[("allocator", silver_common::allocator::AllocationCounters::NAMES)];

/// Surfer grouping key for a `counters-{file_name}` file. Thread counters
/// (`{thread}_{group}`) collapse into one `{group}` section with `thread` as a
/// per-row prefix; process-wide counters are their own group. Returns
/// `(group, thread)`, `thread` empty for process-wide counters.
pub fn group_of(file_name: &str) -> (&str, &str) {
    for &(group, _) in THREAD_COUNTERS {
        if let Some(thread) = file_name.strip_suffix(group) &&
            let Some(thread) = thread.strip_suffix('_')
        {
            return (group, thread);
        }
    }
    (file_name, "")
}

/// Order files so same-group thread counters are contiguous: by
/// `(group, thread, name)`.
pub fn group_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    group_of(a).cmp(&group_of(b)).then_with(|| a.cmp(b))
}

/// Thread counters are `i64` gauges (`declare_thread_counters!`, e.g. the
/// allocator's add/sub); process-wide `declare_counters!` are `u64`. Drives
/// signed rendering in surfer.
pub fn is_signed(file_name: &str) -> bool {
    !group_of(file_name).1.is_empty()
}

/// `lookup` with a positional fallback. Returns `(names, registered)`
/// — `registered = false` means surfer is displaying positional
/// labels because no schema was wired up for this file.
pub fn names_for(file_name: &str, slot_count: usize) -> (Vec<String>, bool) {
    if let Some(arr) = lookup(file_name) {
        return (arr.iter().map(|s| s.to_string()).collect(), true);
    }
    // TCache files have a fixed semantic layout decoded from slot count.
    if file_name.starts_with("tcache-") && slot_count >= 2 {
        let mut names = vec!["capacity".to_string(), "head_seq".to_string()];
        for i in 0..(slot_count - 2) {
            names.push(format!("tail_{i}"));
        }
        return (names, true);
    }
    ((0..slot_count).map(|i| format!("slot_{i}")).collect(), false)
}
