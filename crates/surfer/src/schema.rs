//! Compile-time NAMES lookup. Each `declare_counters!` enum exposes
//! `pub const NAMES: &'static [&'static str]`. Adding a new counter
//! enum to silver = one line here. Files without a registered schema
//! fall back to positional `slot_{i}` labels.

/// Map from file suffix (the `{name}` in `counters-{name}`) to the
/// variant name array. Add lines here as silver crates declare counter
/// enums via `silver_common::declare_counters!`.
pub fn lookup(file_name: &str) -> Option<&'static [&'static str]> {
    match file_name {
        "storage" => Some(silver_storage::StorageCounters::NAMES),
        "network" => Some(silver_network::NetworkCounters::NAMES),
        "peer" => Some(silver_peer::PeerCounters::NAMES),
        _ => None,
    }
}

/// Counters-pane ordering: bulky per-topic groups sink below the compact
/// process-wide ones.
pub fn sort_key(file_name: &str) -> (u8, &str) {
    let rank = if file_name == "gossip_topics" { 1 } else { 0 };
    (rank, file_name)
}

/// Groups whose zero-valued slots are hidden in the counters pane —
/// dense pre-allocated layouts where only touched slots are interesting.
pub fn hide_zero(file_name: &str) -> bool {
    file_name == "gossip_topics"
}

/// `lookup` with a positional fallback. Returns `(names, registered)`
/// — `registered = false` means surfer is displaying positional
/// labels because no schema was wired up for this file.
pub fn names_for(file_name: &str, slot_count: usize) -> (Vec<String>, bool) {
    if let Some(arr) = lookup(file_name) {
        return (arr.iter().map(|s| s.to_string()).collect(), true);
    }
    // Gossip topic counters: arithmetic layout shared with
    // `GossipTopic::counter_slot` — (topic slot) x (sent, recv, mesh, subs).
    if file_name == "gossip_topics" {
        let names = (0..slot_count)
            .map(|i| {
                let kind = match i % 4 {
                    0 => "sent",
                    1 => "recv",
                    2 => "mesh",
                    _ => "subs",
                };
                match silver_common::gossip_topic_for_counter_slot(i / 4) {
                    Some(topic) => format!("{topic}_{kind}"),
                    None => format!("slot_{i}"),
                }
            })
            .collect();
        return (names, true);
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
