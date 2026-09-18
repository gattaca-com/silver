use fxhash::FxHashMap;
use silver_common::GossipDomain;
use silver_gossip::ColumnGroupKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct HeaderKey {
    peer: usize,
    domain: GossipDomain,
    root: [u8; 32],
}

#[derive(Clone, Copy)]
enum HeaderState {
    Sent,
    Known,
}

pub(super) struct HeaderTracker {
    entries: FxHashMap<HeaderKey, HeaderState>,
    capacity: usize,
}

impl HeaderTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            capacity,
        }
    }

    fn key(peer: usize, group: ColumnGroupKey) -> HeaderKey {
        HeaderKey { peer, domain: group.domain, root: group.block_root }
    }

    pub fn needed(&self, peer: usize, group: ColumnGroupKey) -> bool {
        !self.entries.contains_key(&Self::key(peer, group))
    }

    pub fn sent(&mut self, peer: usize, group: ColumnGroupKey) {
        let key = Self::key(peer, group);
        if self.entries.len() < self.capacity || self.entries.contains_key(&key) {
            self.entries.entry(key).or_insert(HeaderState::Sent);
        }
    }

    pub fn known(&mut self, peer: usize, group: ColumnGroupKey) {
        let key = Self::key(peer, group);
        if self.entries.len() < self.capacity || self.entries.contains_key(&key) {
            self.entries.insert(key, HeaderState::Known);
        }
    }

    pub fn forget_sent(&mut self, peer: usize, group: ColumnGroupKey) {
        let key = Self::key(peer, group);
        if matches!(self.entries.get(&key), Some(HeaderState::Sent)) {
            self.entries.remove(&key);
        }
    }

    pub fn retry_peer(&mut self, peer: usize) {
        self.entries.retain(|key, state| key.peer != peer || matches!(state, HeaderState::Known));
    }

    pub fn remove_peer(&mut self, peer: usize) {
        self.entries.retain(|key, _| key.peer != peer);
    }

    pub fn remove_root(&mut self, root: &[u8; 32]) {
        self.entries.retain(|key, _| &key.root != root);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
