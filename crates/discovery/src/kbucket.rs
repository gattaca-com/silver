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

    /// Integer log-2 of the XOR distance. Returns `None` if keys are identical.
    /// Range: 1–256.
    pub fn log2_distance(&self, other: &Key) -> Option<u64> {
        let xor = self.distance(other);
        let log = u64::from(256 - xor.0.leading_zeros());
        if log == 0 { None } else { Some(log) }
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

pub const MAX_NODES_PER_BUCKET: usize = 16;

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
    #[allow(dead_code)]
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
                out.push(*node.key.preimage());
                if out.len() >= max_nodes {
                    return out;
                }
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

    /// Iterator over keys closest to `target`, ordered by increasing XOR
    /// distance.
    pub fn closest_keys(&mut self, target: &Key) -> impl Iterator<Item = Key> + '_ {
        let distance = self.local_key.distance(target);
        ClosestIter {
            target: *target,
            iter: None,
            table: self,
            buckets_iter: ClosestBucketsIter::new(distance),
            fmap: |b: &KBucket<T>| -> ArrayVec<_, MAX_NODES_PER_BUCKET> {
                b.iter().map(|n| n.key).collect()
            },
        }
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

struct ClosestIter<'a, T: Copy, TMap, TOut: Copy> {
    target: Key,
    table: &'a mut KBucketsTable<T>,
    buckets_iter: ClosestBucketsIter,
    iter: Option<<ArrayVec<TOut, MAX_NODES_PER_BUCKET> as IntoIterator>::IntoIter>,
    fmap: TMap,
}

struct ClosestBucketsIter {
    distance: Distance,
    state: ClosestBucketsIterState,
}

enum ClosestBucketsIterState {
    Start(BucketIndex),
    ZoomIn(BucketIndex),
    ZoomOut(BucketIndex),
    Done,
}

impl ClosestBucketsIter {
    fn new(distance: Distance) -> Self {
        let state = match BucketIndex::new(&distance) {
            Some(i) => ClosestBucketsIterState::Start(i),
            None => ClosestBucketsIterState::Start(BucketIndex(0)),
        };
        Self { distance, state }
    }

    fn next_in(&self, i: BucketIndex) -> Option<BucketIndex> {
        (0..i.get())
            .rev()
            .find_map(|i| if self.distance.0.bit(i) { Some(BucketIndex(i)) } else { None })
    }

    fn next_out(&self, i: BucketIndex) -> Option<BucketIndex> {
        (i.get() + 1..NUM_BUCKETS)
            .find_map(|i| if !self.distance.0.bit(i) { Some(BucketIndex(i)) } else { None })
    }
}

impl Iterator for ClosestBucketsIter {
    type Item = BucketIndex;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            ClosestBucketsIterState::Start(i) => {
                self.state = ClosestBucketsIterState::ZoomIn(i);
                Some(i)
            }
            ClosestBucketsIterState::ZoomIn(i) => {
                if let Some(i) = self.next_in(i) {
                    self.state = ClosestBucketsIterState::ZoomIn(i);
                    Some(i)
                } else {
                    let i = BucketIndex(0);
                    self.state = ClosestBucketsIterState::ZoomOut(i);
                    Some(i)
                }
            }
            ClosestBucketsIterState::ZoomOut(i) => {
                if let Some(i) = self.next_out(i) {
                    self.state = ClosestBucketsIterState::ZoomOut(i);
                    Some(i)
                } else {
                    self.state = ClosestBucketsIterState::Done;
                    None
                }
            }
            ClosestBucketsIterState::Done => None,
        }
    }
}

impl<T: Copy, TMap, TOut: Copy> Iterator for ClosestIter<'_, T, TMap, TOut>
where
    TMap: Fn(&KBucket<T>) -> ArrayVec<TOut, MAX_NODES_PER_BUCKET>,
    TOut: AsRef<Key>,
{
    type Item = TOut;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.iter {
                Some(iter) => match iter.next() {
                    Some(k) => return Some(k),
                    None => self.iter = None,
                },
                None => {
                    if let Some(i) = self.buckets_iter.next() {
                        let bucket = &mut self.table.buckets[i.get()];
                        if let Some(applied) = bucket.apply_pending() {
                            self.table.applied_pending.push_back(applied);
                        }
                        let mut v = (self.fmap)(bucket);
                        let target = self.target;
                        v.sort_by(|a, b| {
                            target.distance(a.as_ref()).cmp(&target.distance(b.as_ref()))
                        });
                        self.iter = Some(v.into_iter());
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use silver_common::NodeId;

    use super::*;

    #[test]
    fn basic_closest() {
        let local_key = Key::from(NodeId::random());
        let other_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local_key, Duration::from_secs(5));
        assert!(matches!(
            table.insert_or_update(&other_key, (), Instant::now()),
            InsertResult::Inserted
        ));
        let res: Vec<_> = table.closest_keys(&other_key).collect();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], other_key);
    }

    #[test]
    fn insert_local_fails() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local_key, Duration::from_secs(5));
        assert!(matches!(
            table.insert_or_update(&local_key, (), Instant::now()),
            InsertResult::Failed(FailureReason::SelfUpdate)
        ));
    }

    #[test]
    fn closest_sorted() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local_key, Duration::from_secs(5));
        let now = Instant::now();
        let mut count = 0;
        while count < 100 {
            let key = Key::from(NodeId::random());
            if matches!(table.insert_or_update(&key, (), now), InsertResult::Inserted) {
                count += 1;
            }
        }
        let mut expected: Vec<Key> =
            table.buckets.iter().flat_map(|b| b.iter().map(|n| n.key)).collect();
        for _ in 0..10 {
            let target = Key::from(NodeId::random());
            let keys: Vec<_> = table.closest_keys(&target).collect();
            expected.sort_by_key(|k| k.distance(&target));
            assert_eq!(keys, expected);
        }
    }

    #[test]
    fn closest_local() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<()>::new(local_key, Duration::from_secs(5));
        let now = Instant::now();
        let mut count = 0;
        while count < 100 {
            let key = Key::from(NodeId::random());
            if matches!(table.insert_or_update(&key, (), now), InsertResult::Inserted) {
                count += 1;
            }
        }
        assert_eq!(table.closest_keys(&local_key).count(), count);
    }
}
