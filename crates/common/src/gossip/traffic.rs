use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use flux::utils::directories::local_share_dir;

use super::{GOSSIP_TOPIC_COUNTER_SLOTS, GossipTopic, gossip_topic_for_counter_slot};
use crate::metrics::map_counters;

/// Where a gossip frame's bytes are counted: the counter slot of the topic
/// whose payload it carries, IHAVE, IWANT or IDONTWANT, or control for the
/// rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipTraffic(u16);

impl GossipTraffic {
    pub const CONTROL: Self = Self(GOSSIP_TOPIC_COUNTER_SLOTS as u16);
    pub const IHAVE: Self = Self(GOSSIP_TOPIC_COUNTER_SLOTS as u16 + 1);
    pub const IWANT: Self = Self(GOSSIP_TOPIC_COUNTER_SLOTS as u16 + 2);
    pub const IDONTWANT: Self = Self(GOSSIP_TOPIC_COUNTER_SLOTS as u16 + 3);
    pub const SLOTS: usize = GOSSIP_TOPIC_COUNTER_SLOTS + 4;

    pub fn of(topic: GossipTopic) -> Self {
        Self(topic.counter_slot() as u16)
    }

    /// Observer-side label of counter `slot`.
    pub fn label(slot: usize) -> String {
        match slot {
            s if s == Self::CONTROL.0 as usize => return "control".to_string(),
            s if s == Self::IHAVE.0 as usize => return "ihave".to_string(),
            s if s == Self::IWANT.0 as usize => return "iwant".to_string(),
            s if s == Self::IDONTWANT.0 as usize => return "idontwant".to_string(),
            _ => {}
        }
        gossip_topic_for_counter_slot(slot)
            .map_or_else(|| format!("slot_{slot}"), |topic| topic.to_string())
    }
}

/// Gossip bytes per `GossipTraffic` slot. Each direction has one writing
/// tile and its own file, so the two never share a cache line.
#[derive(Clone, Copy, Debug)]
pub enum GossipTrafficBytes {
    /// Frame bytes as the network tile writes them.
    Sent,
    /// Compressed payload per published message, and the encoded IHAVE,
    /// IWANT and IDONTWANT entries; the rest of each frame goes to control.
    Recv,
}

impl GossipTrafficBytes {
    pub const SENT_FILE: &str = "gossip_bytes_sent";
    pub const RECV_FILE: &str = "gossip_bytes_recv";
    const BYTES: usize = GossipTraffic::SLOTS * size_of::<AtomicU64>();

    #[inline]
    pub fn add(self, traffic: GossipTraffic, bytes: usize) {
        let mut base = self.shmem().load(Ordering::Relaxed);
        if base.is_null() {
            base = self.lazy_init();
        }
        unsafe { &*base.add(traffic.0 as usize) }.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn get(self, traffic: GossipTraffic) -> u64 {
        let mut base = self.shmem().load(Ordering::Relaxed);
        if base.is_null() {
            base = self.lazy_init();
        }
        unsafe { &*base.add(traffic.0 as usize) }.load(Ordering::Relaxed)
    }

    fn shmem(self) -> &'static AtomicPtr<AtomicU64> {
        static SENT: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());
        static RECV: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());
        match self {
            Self::Sent => &SENT,
            Self::Recv => &RECV,
        }
    }

    #[cold]
    #[inline(never)]
    fn lazy_init(self) -> *mut AtomicU64 {
        let file = match self {
            Self::Sent => Self::SENT_FILE,
            Self::Recv => Self::RECV_FILE,
        };
        map_counters(local_share_dir().as_ref(), "silver", file, Self::BYTES, self.shmem())
            .unwrap_or_else(|e| panic!("GossipTrafficBytes {file} init failed: {e}"));
        self.shmem().load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_follows_every_topic_slot() {
        assert_eq!(GossipTraffic::label(GossipTraffic::CONTROL.0 as usize), "control");
        assert_eq!(GossipTraffic::label(GossipTraffic::IHAVE.0 as usize), "ihave");
        assert_eq!(GossipTraffic::label(GossipTraffic::IWANT.0 as usize), "iwant");
        assert_eq!(GossipTraffic::label(GossipTraffic::IDONTWANT.0 as usize), "idontwant");
        assert_eq!(GossipTraffic::IDONTWANT.0 as usize, GossipTraffic::SLOTS - 1);
        let topic = GossipTopic::DataColumnSidecar(127);
        assert!(GossipTraffic::of(topic).0 < GossipTraffic::CONTROL.0);
        assert_eq!(GossipTraffic::label(GossipTraffic::of(topic).0 as usize), topic.to_string());
    }
}
