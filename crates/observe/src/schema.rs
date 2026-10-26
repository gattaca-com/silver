use silver_common::{GossipTraffic, GossipTrafficBytes};
use silver_stages::counter_names;

fn is_gossip_traffic(file_name: &str) -> bool {
    file_name == GossipTrafficBytes::SENT_FILE || file_name == GossipTrafficBytes::RECV_FILE
}

/// Counters-pane ordering: bulky per-topic groups sink below the compact
/// process-wide ones.
pub fn sort_key(file_name: &str) -> (u8, &str) {
    let rank = if is_gossip_per_topic(file_name) { 1 } else { 0 };
    (rank, file_name)
}

/// Log counts and per-topic gossip counters have their own panes.
pub fn in_counters_pane(file_name: &str) -> bool {
    file_name != "log" && !is_gossip_per_topic(file_name) && !is_gossip_traffic(file_name)
}

fn is_gossip_per_topic(file_name: &str) -> bool {
    matches!(file_name, "gossip_topics" | "gossip_flow")
}

/// `{topic}_{kind}` for slot `i` of a per-topic file of `kinds.len()` slots
/// per `GossipTopic::counter_slot`.
fn per_topic_names(slot_count: usize, kinds: &[&str]) -> Vec<String> {
    (0..slot_count)
        .map(|i| match silver_common::gossip_topic_for_counter_slot(i / kinds.len()) {
            Some(topic) => format!("{topic}_{}", kinds[i % kinds.len()]),
            None => format!("slot_{i}"),
        })
        .collect()
}

/// `lookup` with a positional fallback. Returns `(names, registered)`
/// — `registered = false` means surfer is displaying positional
/// labels because no schema was wired up for this file.
pub fn names_for(file_name: &str, slot_count: usize) -> (Vec<String>, bool) {
    if let Some(arr) = counter_names(file_name) {
        return (arr.iter().map(|s| s.to_string()).collect(), true);
    }
    // Per-topic gossip counters: arithmetic layouts shared with
    // `GossipTopicCounters` and `GossipFlowCounters`.
    if file_name == "gossip_topics" {
        return (per_topic_names(slot_count, &["sent", "recv", "mesh", "subs"]), true);
    }
    if file_name == "gossip_flow" {
        let kinds = ["duplicate", "accepted", "published", "rejected", "iwant_served"];
        return (per_topic_names(slot_count, &kinds), true);
    }
    if is_gossip_traffic(file_name) {
        return ((0..slot_count).map(GossipTraffic::label).collect(), true);
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
