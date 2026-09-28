use silver_stages::counter_names;

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
    if let Some(arr) = counter_names(file_name) {
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
