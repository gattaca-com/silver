// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// This basis of this file has been taken from the rust-libp2p codebase:
// https://github.com/libp2p/rust-libp2p

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use flux::utils::ArrayVec;
use silver_common::NodeId;
use uint::construct_uint;

construct_uint! {
    struct U256(4);
}

/// A node's position in the Kademlia keyspace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Key {
    preimage: NodeId,
    hash: U256,
}

impl Key {
    pub fn preimage(&self) -> &NodeId {
        &self.preimage
    }

    /// XOR distance between two keys.
    pub fn distance(&self, other: &Key) -> Distance {
        Distance(self.hash ^ other.hash)
    }
}

impl From<NodeId> for Key {
    fn from(node_id: NodeId) -> Self {
        Key { preimage: node_id, hash: U256::from_big_endian(&node_id.raw()) }
    }
}

impl AsRef<Key> for Key {
    fn as_ref(&self) -> &Key {
        self
    }
}

/// XOR distance between two `Key`s.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug)]
pub struct Distance(U256);

#[cfg(test)]
impl Distance {
    /// log2 distance (FindNode bucket index, 1..=256); 0 for identical keys.
    pub fn log2(&self) -> u64 {
        NUM_BUCKETS as u64 - self.0.leading_zeros() as u64
    }
}

pub const MAX_NODES_PER_BUCKET: usize = 64;

/// A node in a k-bucket.
#[derive(Debug, Clone, Copy)]
pub struct Node<T: Copy> {
    pub key: Key,
    pub value: T,
    /// Timestamp of the last received message from this node.
    pub last_seen: Instant,
}

#[derive(Clone, Copy)]
struct PendingNode<T: Copy> {
    node: Node<T>,
    replace: Instant,
}

/// A k-bucket holding at most `MAX_NODES_PER_BUCKET` nodes, ordered by
/// `last_seen` ascending — index 0 is the LRU and eviction candidate.
#[derive(Clone)]
struct KBucket<T: Copy> {
    nodes: ArrayVec<Node<T>, MAX_NODES_PER_BUCKET>,
    pending: Option<PendingNode<T>>,
    pending_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult {
    Inserted,
    Updated,
    /// Bucket full; `oldest` is the current LRU that will be evicted after
    /// `pending_timeout` unless it sends a message first.
    Pending {
        oldest: Key,
    },
    Failed(FailureReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    BucketFull,
    SelfUpdate,
}

pub struct AppliedPending<T: Copy> {
    pub inserted: Key,
    pub evicted: Option<Node<T>>,
}

impl<T: Copy> KBucket<T> {
    fn new(pending_timeout: Duration) -> Self {
        KBucket { nodes: ArrayVec::new(), pending: None, pending_timeout }
    }

    fn iter(&self) -> impl Iterator<Item = &Node<T>> {
        self.nodes.iter()
    }

    fn position(&self, key: &Key) -> Option<usize> {
        self.nodes.iter().position(|n| &n.key == key)
    }

    /// Insert or update a node.
    ///
    /// - Existing node in nodes: update value + `last_seen`, move to tail.
    /// - Existing node in pending slot: update value + `last_seen` in place.
    /// - Bucket not full: insert at tail.
    /// - Bucket full, no pending: record as pending, return `Pending{oldest}`
    /// - Bucket full, pending occupied: `Failed(BucketFull)`.
    fn insert_or_update(&mut self, key: &Key, value: T, now: Instant) -> InsertResult {
        if let Some(pos) = self.position(key) {
            // Copy out, shift left to close the gap, then re-push at tail.
            let mut node = self.nodes[pos];
            let len = self.nodes.len();
            self.nodes.copy_within(pos + 1..len, pos);
            self.nodes.truncate(len - 1);
            node.value = value;
            node.last_seen = now;
            self.nodes.push(node);
            return InsertResult::Updated;
        }

        if let Some(ref mut p) = self.pending {
            if &p.node.key == key {
                p.node.value = value;
                p.node.last_seen = now;
                return InsertResult::Updated;
            }
        }

        if self.nodes.is_full() {
            if self.pending.is_some() {
                return InsertResult::Failed(FailureReason::BucketFull);
            }
            let oldest = self.nodes[0].key;
            self.pending = Some(PendingNode {
                node: Node { key: *key, value, last_seen: now },
                replace: now + self.pending_timeout,
            });
            return InsertResult::Pending { oldest };
        }

        self.nodes.push(Node { key: *key, value, last_seen: now });
        InsertResult::Inserted
    }

    /// Like `insert_or_update`, but always commits the node: a full bucket
    /// evicts its LRU entry immediately instead of parking the node as pending.
    /// Used on session establishment, where the peer must be routable because
    /// we will connect to it on the p2p layer. Returns the evicted LRU node.
    fn insert_or_update_evicting(&mut self, key: &Key, value: T, now: Instant) -> Option<Node<T>> {
        if let Some(pos) = self.position(key) {
            let mut node = self.nodes[pos];
            let len = self.nodes.len();
            self.nodes.copy_within(pos + 1..len, pos);
            self.nodes.truncate(len - 1);
            node.value = value;
            node.last_seen = now;
            self.nodes.push(node);
            return None;
        }

        // A pending copy is stale once we commit the node directly.
        if self.pending.as_ref().is_some_and(|p| &p.node.key == key) {
            self.pending = None;
        }

        let evicted = if self.nodes.is_full() {
            let node = self.nodes[0];
            let len = self.nodes.len();
            self.nodes.copy_within(1..len, 0);
            self.nodes.truncate(len - 1);
            Some(node)
        } else {
            None
        };
        self.nodes.push(Node { key: *key, value, last_seen: now });
        evicted
    }

    /// Remove `key` from the committed slots or the pending slot. Returns
    /// whether anything was removed.
    fn remove(&mut self, key: &Key) -> bool {
        if let Some(pos) = self.position(key) {
            let len = self.nodes.len();
            self.nodes.copy_within(pos + 1..len, pos);
            self.nodes.truncate(len - 1);
            return true;
        }
        if self.pending.as_ref().is_some_and(|p| &p.node.key == key) {
            self.pending = None;
            return true;
        }
        false
    }

    /// Promote the pending node if its timeout has elapsed, evicting the
    /// current LRU.
    fn apply_pending(&mut self) -> Option<AppliedPending<T>> {
        let pending = self.pending.take()?;
        if pending.replace > Instant::now() {
            self.pending = Some(pending);
            return None;
        }
        let inserted = pending.node.key;
        let evicted = if self.nodes.is_full() {
            let node = self.nodes[0];
            let len = self.nodes.len();
            self.nodes.copy_within(1..len, 0);
            self.nodes.truncate(len - 1);
            Some(node)
        } else {
            None
        };
        self.nodes.push(pending.node);
        Some(AppliedPending { inserted, evicted })
    }
}

const NUM_BUCKETS: usize = 256;

/// A Kademlia routing table keyed by `NodeId`.
pub struct KBucketsTable<T: Copy> {
    local_key: Key,
    buckets: Vec<KBucket<T>>,
    applied_pending: VecDeque<AppliedPending<T>>,
}

impl<T: Copy> KBucketsTable<T> {
    pub fn new(local_key: Key, pending_timeout: Duration) -> Self {
        KBucketsTable {
            local_key,
            buckets: (0..NUM_BUCKETS).map(|_| KBucket::new(pending_timeout)).collect(),
            applied_pending: VecDeque::new(),
        }
    }

    /// Insert or update a node. `now` is the message receive timestamp.
    pub fn insert_or_update(&mut self, key: &Key, value: T, now: Instant) -> InsertResult {
        let Some(i) = BucketIndex::new(&self.local_key.distance(key)) else {
            return InsertResult::Failed(FailureReason::SelfUpdate);
        };
        let bucket = &mut self.buckets[i.get()];
        if let Some(applied) = bucket.apply_pending() {
            self.applied_pending.push_back(applied);
        }
        bucket.insert_or_update(key, value, now)
    }

    /// Force-commit a node, evicting the bucket LRU if full.
    pub fn insert_or_update_evicting(
        &mut self,
        key: &Key,
        value: T,
        now: Instant,
    ) -> Result<Option<Node<T>>, FailureReason> {
        let Some(i) = BucketIndex::new(&self.local_key.distance(key)) else {
            return Err(FailureReason::SelfUpdate);
        };
        let bucket = &mut self.buckets[i.get()];
        if let Some(applied) = bucket.apply_pending() {
            self.applied_pending.push_back(applied);
        }
        Ok(bucket.insert_or_update_evicting(key, value, now))
    }

    /// Iterate all nodes (no pending promotion triggered).
    pub fn iter_ref(&self) -> impl Iterator<Item = &Node<T>> {
        self.buckets.iter().flat_map(|b| b.iter())
    }

    /// Consume the next pending-eviction event, if any.
    pub fn take_applied_pending(&mut self) -> Option<AppliedPending<T>> {
        self.applied_pending.pop_front()
    }

    /// Return up to `max_nodes` node IDs from buckets at the given log2
    /// distances (1–256). Applies pending promotions on traversed buckets.
    pub fn nodes_by_distances(
        &mut self,
        log2_distances: &[u64],
        max_nodes: usize,
    ) -> ArrayVec<NodeId, MAX_NODES_PER_BUCKET> {
        // Apply pending promotions first, then collect.
        for &d in log2_distances {
            if d > 0 && d <= NUM_BUCKETS as u64 {
                let bucket = &mut self.buckets[(d - 1) as usize];
                if let Some(applied) = bucket.apply_pending() {
                    self.applied_pending.push_back(applied);
                }
            }
        }

        let mut out: ArrayVec<NodeId, MAX_NODES_PER_BUCKET> = ArrayVec::new();
        for &d in log2_distances {
            if d == 0 || d > NUM_BUCKETS as u64 {
                continue;
            }
            for node in self.buckets[(d - 1) as usize].iter() {
                if out.is_full() || out.len() >= max_nodes {
                    return out;
                }
                out.push(*node.key.preimage());
            }
        }
        out
    }

    /// Lookup by key. Does not trigger pending promotion.
    pub fn get(&self, key: &Key) -> Option<&Node<T>> {
        let i = BucketIndex::new(&self.local_key.distance(key))?;
        let pos = self.buckets[i.get()].position(key)?;
        Some(&self.buckets[i.get()].nodes[pos])
    }

    /// Evict a node from the routing table (committed or pending slot).
    /// Returns whether it was present.
    pub fn remove(&mut self, key: &Key) -> bool {
        match BucketIndex::new(&self.local_key.distance(key)) {
            Some(i) => self.buckets[i.get()].remove(key),
            None => false,
        }
    }

    /// `(bucket_index, committed_node_count)` for every non-empty bucket.
    /// Diagnostics only; pending entries are not counted.
    pub fn bucket_sizes(&self) -> Vec<(usize, usize)> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.nodes.is_empty())
            .map(|(i, b)| (i, b.nodes.len()))
            .collect()
    }
}

#[derive(Copy, Clone)]
struct BucketIndex(usize);

impl BucketIndex {
    fn new(d: &Distance) -> Option<BucketIndex> {
        (NUM_BUCKETS - d.0.leading_zeros() as usize).checked_sub(1).map(BucketIndex)
    }

    fn get(self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use silver_common::NodeId;

    use super::*;

    #[test]
    fn insert_local_fails() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local_key, Duration::from_secs(5));
        assert!(matches!(
            table.insert_or_update(&local_key, (), Instant::now()),
            InsertResult::Failed(FailureReason::SelfUpdate)
        ));
    }

    // Random peers do NOT spread evenly across the 256 buckets. Bucket index is
    // 255 - leading_zeros(xor_distance), so the probability of landing in the
    // top bucket is 1/2, the next 1/4, and so on — a geometric distribution
    // concentrated in the few high-distance buckets.
    #[test]
    fn random_ids_distribute_geometrically_by_distance() {
        let local = Key::from(NodeId::random());
        let n = 100_000usize;
        let mut counts = [0usize; NUM_BUCKETS];
        for _ in 0..n {
            let k = Key::from(NodeId::random());
            let idx = BucketIndex::new(&local.distance(&k)).expect("distinct key").get();
            counts[idx] += 1;
        }

        // Top bucket ~1/2, next ~1/4, next ~1/8 (10% relative slack).
        assert!((counts[255] as f64 - n as f64 / 2.0).abs() < n as f64 * 0.05);
        assert!((counts[254] as f64 - n as f64 / 4.0).abs() < n as f64 * 0.05);
        assert!((counts[253] as f64 - n as f64 / 8.0).abs() < n as f64 * 0.05);

        // The top 16 buckets hold essentially everything; lower buckets are
        // effectively unreachable for uniformly-random peer ids.
        let top16: usize = counts[NUM_BUCKETS - 16..].iter().sum();
        assert!(top16 > n * 999 / 1000, "top16={top16}");
    }

    // Consequence of the geometric distribution: offering many random peers
    // saturates the high buckets at MAX_NODES_PER_BUCKET and rejects the rest,
    // so the committed table holds far fewer nodes than peers offered.
    #[test]
    fn high_buckets_saturate_and_reject() {
        let local = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local, Duration::from_secs(60));
        let now = Instant::now();

        let offered = 4096usize;
        let mut not_committed = 0usize;
        for _ in 0..offered {
            match table.insert_or_update(&Key::from(NodeId::random()), (), now) {
                InsertResult::Inserted | InsertResult::Updated => {}
                InsertResult::Pending { .. } | InsertResult::Failed(_) => not_committed += 1,
            }
        }

        for b in &table.buckets {
            assert!(b.nodes.len() <= MAX_NODES_PER_BUCKET);
        }

        // Top buckets are full; the table commits only a small fraction.
        assert_eq!(table.buckets[255].nodes.len(), MAX_NODES_PER_BUCKET);
        assert_eq!(table.buckets[254].nodes.len(), MAX_NODES_PER_BUCKET);
        let committed: usize = table.buckets.iter().map(|b| b.nodes.len()).sum();
        assert!(committed < offered / 4, "committed={committed}");
        assert!(not_committed > offered * 3 / 4, "not_committed={not_committed}");
    }

    #[test]
    fn evicting_insert_replaces_lru_when_full() {
        let now = Instant::now();
        let mut b = KBucket::<u32>::new(Duration::from_secs(60));
        let keys: Vec<Key> =
            (0..MAX_NODES_PER_BUCKET).map(|_| Key::from(NodeId::random())).collect();
        for (i, k) in keys.iter().enumerate() {
            assert!(matches!(b.insert_or_update(k, i as u32, now), InsertResult::Inserted));
        }
        assert!(b.nodes.is_full());

        let newcomer = Key::from(NodeId::random());
        let evicted = b.insert_or_update_evicting(&newcomer, 999, now).expect("LRU evicted");
        assert_eq!(evicted.key, keys[0]); // index 0 is the LRU
        assert_eq!(b.nodes.len(), MAX_NODES_PER_BUCKET);
        assert!(b.position(&newcomer).is_some());
        assert!(b.position(&keys[0]).is_none());
    }

    #[test]
    fn evicting_insert_updates_in_place_without_eviction() {
        let now = Instant::now();
        let mut b = KBucket::<u32>::new(Duration::from_secs(60));
        let k = Key::from(NodeId::random());
        b.insert_or_update(&k, 1, now);
        b.insert_or_update(&Key::from(NodeId::random()), 2, now);

        assert!(b.insert_or_update_evicting(&k, 7, now).is_none());
        assert_eq!(b.nodes.len(), 2);
        let pos = b.position(&k).expect("still present");
        assert_eq!(b.nodes[pos].value, 7);
        assert_eq!(pos, b.nodes.len() - 1); // refreshed -> moved to tail (MRU)
    }

    #[test]
    fn evicting_insert_commits_pending_node() {
        let now = Instant::now();
        let mut b = KBucket::<u32>::new(Duration::from_secs(60));
        for i in 0..MAX_NODES_PER_BUCKET {
            b.insert_or_update(&Key::from(NodeId::random()), i as u32, now);
        }
        let pend = Key::from(NodeId::random());
        assert!(matches!(b.insert_or_update(&pend, 100, now), InsertResult::Pending { .. }));
        assert!(b.pending.is_some());

        let evicted = b.insert_or_update_evicting(&pend, 100, now).expect("LRU evicted");
        assert!(b.pending.is_none());
        assert!(b.position(&pend).is_some());
        assert_ne!(evicted.key, pend);
    }

    #[test]
    fn evicting_insert_rejects_local() {
        let local = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local, Duration::from_secs(5));
        assert!(matches!(
            table.insert_or_update_evicting(&local, (), Instant::now()),
            Err(FailureReason::SelfUpdate)
        ));
    }
}
