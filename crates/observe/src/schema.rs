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

pub fn slot_name(group: &str, slot: usize) -> String {
    if let Some(name) = counter_names(group).and_then(|names| names.get(slot)) {
        return (*name).to_owned();
    }
    let kinds: &[&str] = match group {
        "gossip_topics" => &["sent", "recv", "mesh", "subs"],
        "gossip_flow" => &["duplicate", "accepted", "published", "rejected", "iwant_served"],
        _ => &[],
    };
    if !kinds.is_empty() &&
        let Some(topic) = silver_common::gossip_topic_for_counter_slot(slot / kinds.len())
    {
        return format!("{topic}_{}", kinds[slot % kinds.len()]);
    }
    if is_gossip_traffic(group) {
        return GossipTraffic::label(slot);
    }
    if group.starts_with("tcache-") {
        return match slot {
            0 => "capacity".to_owned(),
            1 => "head_seq".to_owned(),
            _ => format!("tail_{}", slot - 2),
        };
    }
    format!("slot_{slot}")
}

pub fn names_for(group: &str, slot_count: usize) -> (Vec<String>, bool) {
    if let Some(names) = counter_names(group) {
        return (names.iter().map(|s| s.to_string()).collect(), true);
    }
    if group.starts_with("tcache-") && slot_count < 2 {
        return ((0..slot_count).map(|slot| format!("slot_{slot}")).collect(), false);
    }
    let registered =
        is_gossip_per_topic(group) || is_gossip_traffic(group) || group.starts_with("tcache-");
    ((0..slot_count).map(|slot| slot_name(group, slot)).collect(), registered)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Counter,
    Gauge,
    Untyped,
}

pub fn slot_kind(group: &str, slot: usize) -> SlotKind {
    if group == "gossip_topics" && slot % 4 >= 2 {
        return SlotKind::Gauge;
    }
    if let Some((_, gauges)) = silver_stages::counter_schema(group) &&
        let Some(&gauge) = gauges.get(slot)
    {
        return if gauge { SlotKind::Gauge } else { SlotKind::Counter };
    }
    if is_gossip_per_topic(group) || is_gossip_traffic(group) || group == "log" {
        SlotKind::Counter
    } else {
        SlotKind::Untyped
    }
}
