use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use silver_common::{GOSSIP_TOPIC_COUNTER_SLOTS, GossipTopic, metrics::map_counters};

/// Subnet-resolved gossip traffic counters, shmem-backed like
/// `declare_counters!` output but indexed arithmetically:
/// `counter_slot(topic) * 4` is sent, `+ 1` is recv, `+ 2` is the mesh-size
/// gauge, `+ 3` is the subscribed-peers gauge.
pub struct GossipTopicCounters;

pub const PER_TOPIC: usize = 4;

const COUNT: usize = GOSSIP_TOPIC_COUNTER_SLOTS * PER_TOPIC;
const BYTES: usize = COUNT * size_of::<AtomicU64>();

impl GossipTopicCounters {
    pub fn sent(topic: GossipTopic) {
        Self::slot(topic.counter_slot() * PER_TOPIC).fetch_add(1, Ordering::Relaxed);
    }

    pub fn recv(topic: GossipTopic) {
        Self::slot(topic.counter_slot() * PER_TOPIC + 1).fetch_add(1, Ordering::Relaxed);
    }

    pub fn mesh(topic: GossipTopic, size: usize) {
        Self::slot(topic.counter_slot() * PER_TOPIC + 2).store(size as u64, Ordering::Relaxed);
    }

    /// `counts` indexed by `GossipTopic::counter_slot`.
    pub fn subscribed(counts: &[u16; GOSSIP_TOPIC_COUNTER_SLOTS]) {
        for (slot, count) in counts.iter().enumerate() {
            Self::slot(slot * PER_TOPIC + 3).store(*count as u64, Ordering::Relaxed);
        }
    }

    fn shmem() -> &'static AtomicPtr<AtomicU64> {
        static SHMEM: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());
        &SHMEM
    }

    fn slot(i: usize) -> &'static AtomicU64 {
        let mut p = Self::shmem().load(Ordering::Relaxed);
        if p.is_null() {
            p = Self::lazy_init();
        }
        unsafe { &*p.add(i) }
    }

    #[cold]
    #[inline(never)]
    fn lazy_init() -> *mut AtomicU64 {
        map_counters(
            flux::utils::directories::local_share_dir().as_ref(),
            "silver",
            "gossip_topics",
            BYTES,
            Self::shmem(),
        )
        .unwrap_or_else(|e| panic!("GossipTopicCounters init failed: {e}"));
        Self::shmem().load(Ordering::Relaxed)
    }
}
