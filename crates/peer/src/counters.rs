use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use silver_common::{GOSSIP_TOPIC_COUNTER_SLOTS, GossipTopic, metrics::map_counters};

/// Subnet-resolved gossip traffic counters, shmem-backed like
/// `declare_counters!` output but indexed arithmetically:
/// `counter_slot(topic) * 4` is sent, `+ 1` is recv, `+ 2` is the mesh-size
/// gauge, `+ 3` is the subscribed-peers gauge.
pub struct GossipTopicCounters;

pub const PER_TOPIC: usize = 4;

static TOPICS: TopicCounterFile = TopicCounterFile::new("gossip_topics", PER_TOPIC);

impl GossipTopicCounters {
    pub fn sent(topic: GossipTopic) {
        TOPICS.slot(topic.counter_slot(), 0).fetch_add(1, Ordering::Relaxed);
    }

    pub fn recv(topic: GossipTopic) {
        TOPICS.slot(topic.counter_slot(), 1).fetch_add(1, Ordering::Relaxed);
    }

    pub fn mesh(topic: GossipTopic, size: usize) {
        TOPICS.slot(topic.counter_slot(), 2).store(size as u64, Ordering::Relaxed);
    }

    /// `counts` indexed by `GossipTopic::counter_slot`.
    pub fn subscribed(counts: &[u16; GOSSIP_TOPIC_COUNTER_SLOTS]) {
        for (slot, count) in counts.iter().enumerate() {
            TOPICS.slot(slot, 3).store(*count as u64, Ordering::Relaxed);
        }
    }
}

/// Per-topic message outcomes, laid out like `GossipTopicCounters` with
/// `PER_TOPIC_FLOW` slots: duplicate, accepted, published, rejected,
/// iwant_served. Accepted and published count messages, not copies sent.
pub struct GossipFlowCounters;

pub const PER_TOPIC_FLOW: usize = 5;

static FLOW: TopicCounterFile = TopicCounterFile::new("gossip_flow", PER_TOPIC_FLOW);

impl GossipFlowCounters {
    pub fn duplicate(topic: GossipTopic) {
        FLOW.slot(topic.counter_slot(), 0).fetch_add(1, Ordering::Relaxed);
    }

    pub fn accepted(topic: GossipTopic) {
        FLOW.slot(topic.counter_slot(), 1).fetch_add(1, Ordering::Relaxed);
    }

    pub fn published(topic: GossipTopic) {
        FLOW.slot(topic.counter_slot(), 2).fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejected(topic: GossipTopic) {
        FLOW.slot(topic.counter_slot(), 3).fetch_add(1, Ordering::Relaxed);
    }

    /// `topic_slot` is a `GossipTopic::counter_slot`.
    pub fn iwant_served(topic_slot: usize) {
        FLOW.slot(topic_slot, 4).fetch_add(1, Ordering::Relaxed);
    }
}

/// One shmem counter file of `per_topic` slots per topic counter slot,
/// mapped on first use.
struct TopicCounterFile {
    name: &'static str,
    per_topic: usize,
    shmem: AtomicPtr<AtomicU64>,
}

impl TopicCounterFile {
    const fn new(name: &'static str, per_topic: usize) -> Self {
        Self { name, per_topic, shmem: AtomicPtr::new(std::ptr::null_mut()) }
    }

    fn slot(&self, topic_slot: usize, kind: usize) -> &AtomicU64 {
        debug_assert!(topic_slot < GOSSIP_TOPIC_COUNTER_SLOTS && kind < self.per_topic);
        let mut p = self.shmem.load(Ordering::Relaxed);
        if p.is_null() {
            p = self.lazy_init();
        }
        unsafe { &*p.add(topic_slot * self.per_topic + kind) }
    }

    #[cold]
    #[inline(never)]
    fn lazy_init(&self) -> *mut AtomicU64 {
        let bytes = GOSSIP_TOPIC_COUNTER_SLOTS * self.per_topic * size_of::<AtomicU64>();
        map_counters(
            flux::utils::directories::local_share_dir().as_ref(),
            "silver",
            self.name,
            bytes,
            &self.shmem,
        )
        .unwrap_or_else(|e| panic!("{} counters init failed: {e}", self.name));
        self.shmem.load(Ordering::Relaxed)
    }
}
