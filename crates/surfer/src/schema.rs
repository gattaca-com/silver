//! Compile-time NAMES lookup. Each `declare_counters!` enum exposes
//! `pub const NAMES: &'static [&'static str]`. Adding a new counter
//! enum to silver = one line here. Files without a registered schema
//! fall back to positional `slot_{i}` labels.

/// Map from file suffix (the `{name}` in `counters-{name}`) to the
/// variant name array. Add lines here as silver crates declare counter
/// enums via `silver_common::declare_counters!`.
pub fn lookup(file_name: &str) -> Option<&'static [&'static str]> {
    match file_name {
        "data_columns" => Some(data_columns::DataColumnCounters::NAMES),
        "network" => Some(silver_network::NetworkCounters::NAMES),
        _ => None,
    }
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
