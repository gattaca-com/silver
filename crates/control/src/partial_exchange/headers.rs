use fxhash::FxHashMap;
use silver_common::{GossipDomain, P2pStreamId};
use silver_gossip::ColumnGroupKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct HeaderKey {
    peer: usize,
    domain: GossipDomain,
    root: [u8; 32],
}

#[derive(Clone, Copy)]
enum HeaderState {
    Queued(u64),
    Written(P2pStreamId),
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

    pub fn queued(&mut self, peer: usize, group: ColumnGroupKey, seq: u64) {
        let key = Self::key(peer, group);
        if self.entries.len() < self.capacity || self.entries.contains_key(&key) {
            self.entries.insert(key, HeaderState::Queued(seq));
        }
    }

    pub fn known(&mut self, peer: usize, group: ColumnGroupKey) {
        let key = Self::key(peer, group);
        if self.entries.len() < self.capacity || self.entries.contains_key(&key) {
            self.entries.insert(key, HeaderState::Known);
        }
    }

    pub fn complete(
        &mut self,
        peer: usize,
        group: ColumnGroupKey,
        seq: u64,
        stream: Option<P2pStreamId>,
    ) {
        let key = Self::key(peer, group);
        if matches!(self.entries.get(&key), Some(HeaderState::Queued(pending)) if *pending == seq) {
            if let Some(stream) = stream {
                self.entries.insert(key, HeaderState::Written(stream));
            } else {
                self.entries.remove(&key);
            }
        }
    }

    pub fn reset_stream(&mut self, stream: P2pStreamId) {
        self.entries
            .retain(|_, state| !matches!(state, HeaderState::Written(sent) if *sent == stream));
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
