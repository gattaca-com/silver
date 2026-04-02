// Copyright 2019 Parity Technologies (UK) Ltd.
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
    collections::btree_map::{BTreeMap, Entry},
    time::{Duration, Instant},
};

use rustc_hash::FxHashMap;
use silver_common::NodeId;

use crate::{
    config::DiscoveryConfig,
    kbucket::{Distance, Key, MAX_NODES_PER_BUCKET},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryState {
    /// Waiting; `Some(peer)` is the next peer to contact.
    Waiting(Option<NodeId>),
    WaitingAtCapacity,
    Finished,
}

pub struct FindNodeQuery {
    target_key: Key,
    progress: QueryProgress,
    /// Closest peers seen so far, ordered by XOR distance to target.
    closest_peers: BTreeMap<Distance, QueryPeer>,
    num_waiting: usize,
    config: FindNodeQueryConfig,
}

#[derive(Debug, Clone)]
pub struct FindNodeQueryConfig {
    /// α: max parallel in-flight requests.
    pub parallelism: usize,
    /// k: number of successful results needed to terminate.
    pub num_results: usize,
    /// Per-peer timeout before marking unresponsive.
    pub peer_timeout: Duration,
}

impl FindNodeQueryConfig {
    pub fn new_from_config(config: &DiscoveryConfig) -> Self {
        Self {
            parallelism: config.query_parallelism,
            num_results: MAX_NODES_PER_BUCKET,
            peer_timeout: config.query_peer_timeout(),
        }
    }
}

impl FindNodeQuery {
    pub fn with_config(
        config: FindNodeQueryConfig,
        target_key: Key,
        known_closest_peers: impl IntoIterator<Item = Key>,
    ) -> Self {
        let closest_peers = known_closest_peers
            .into_iter()
            .map(|key| {
                let distance = key.distance(&target_key);
                (distance, QueryPeer::new(key, QueryPeerState::NotContacted))
            })
            .take(config.num_results)
            .collect();
        FindNodeQuery {
            config,
            target_key,
            progress: QueryProgress::Iterating { no_progress: 0 },
            closest_peers,
            num_waiting: 0,
        }
    }

    pub fn on_success(&mut self, node_id: &NodeId, closer_peers: impl IntoIterator<Item = NodeId>) {
        if let QueryProgress::Finished = self.progress {
            return;
        }

        let key = Key::from(*node_id);
        let distance = key.distance(&self.target_key);

        match self.closest_peers.entry(distance) {
            Entry::Vacant(..) => return,
            Entry::Occupied(mut e) => match e.get().state {
                QueryPeerState::Waiting(..) => {
                    debug_assert!(self.num_waiting > 0);
                    self.num_waiting -= 1;
                    e.get_mut().state = QueryPeerState::Succeeded;
                }
                QueryPeerState::Unresponsive => {
                    e.get_mut().state = QueryPeerState::Succeeded;
                }
                QueryPeerState::NotContacted |
                QueryPeerState::Failed |
                QueryPeerState::Succeeded => return,
            },
        }

        let mut progress = false;
        let num_closest = self.closest_peers.len();

        for peer_id in closer_peers {
            let key = Key::from(peer_id);
            let distance = self.target_key.distance(&key);
            let peer = QueryPeer::new(key, QueryPeerState::NotContacted);
            self.closest_peers.entry(distance).or_insert(peer);
            progress |= self.closest_peers.keys().next() == Some(&distance) ||
                num_closest < self.config.num_results;
        }

        // Bound the map: evict furthest NotContacted entries beyond 3 * num_results.
        // In-flight / completed entries are never evicted.
        // todo @nina: necessary?
        let cap = self.config.num_results * 3;
        while self.closest_peers.len() > cap {
            let last = match self.closest_peers.keys().next_back() {
                Some(&d) => d,
                None => break,
            };
            if matches!(self.closest_peers[&last].state, QueryPeerState::NotContacted) {
                self.closest_peers.remove(&last);
            } else {
                break;
            }
        }

        self.progress = match self.progress {
            QueryProgress::Iterating { no_progress } => {
                let no_progress = if progress { 0 } else { no_progress + 1 };
                if no_progress >= self.config.parallelism {
                    QueryProgress::Stalled
                } else {
                    QueryProgress::Iterating { no_progress }
                }
            }
            QueryProgress::Stalled => {
                if progress {
                    QueryProgress::Iterating { no_progress: 0 }
                } else {
                    QueryProgress::Stalled
                }
            }
            QueryProgress::Finished => QueryProgress::Finished,
        };
    }

    pub fn on_failure(&mut self, peer: &NodeId) {
        if let QueryProgress::Finished = self.progress {
            return;
        }

        let key = Key::from(*peer);
        let distance = key.distance(&self.target_key);

        match self.closest_peers.entry(distance) {
            Entry::Vacant(_) => {}
            Entry::Occupied(mut e) => match e.get().state {
                QueryPeerState::Waiting(..) => {
                    debug_assert!(self.num_waiting > 0);
                    self.num_waiting -= 1;
                    e.get_mut().state = QueryPeerState::Failed;
                }
                QueryPeerState::Unresponsive => e.get_mut().state = QueryPeerState::Failed,
                _ => {}
            },
        }
    }

    pub fn next(&mut self, now: Instant) -> QueryState {
        if let QueryProgress::Finished = self.progress {
            return QueryState::Finished;
        }

        let mut result_counter = Some(0);
        let at_capacity = self.at_capacity();

        for peer in self.closest_peers.values_mut() {
            match peer.state {
                QueryPeerState::NotContacted => {
                    if !at_capacity {
                        let timeout = now + self.config.peer_timeout;
                        peer.state = QueryPeerState::Waiting(timeout);
                        self.num_waiting += 1;
                        return QueryState::Waiting(Some(*peer.key.preimage()));
                    } else {
                        return QueryState::WaitingAtCapacity;
                    }
                }
                QueryPeerState::Waiting(timeout) => {
                    if now >= timeout {
                        debug_assert!(self.num_waiting > 0);
                        self.num_waiting -= 1;
                        peer.state = QueryPeerState::Unresponsive;
                    } else if at_capacity {
                        return QueryState::WaitingAtCapacity;
                    } else {
                        result_counter = None;
                    }
                }
                QueryPeerState::Succeeded => {
                    if let Some(ref mut cnt) = result_counter {
                        *cnt += 1;
                        if *cnt >= self.config.num_results {
                            self.progress = QueryProgress::Finished;
                            return QueryState::Finished;
                        }
                    }
                }
                QueryPeerState::Failed | QueryPeerState::Unresponsive => {}
            }
        }

        if self.num_waiting > 0 {
            QueryState::Waiting(None)
        } else {
            self.progress = QueryProgress::Finished;
            QueryState::Finished
        }
    }

    pub fn into_result(self) -> impl Iterator<Item = NodeId> {
        let num_results = self.config.num_results;
        self.closest_peers
            .into_values()
            .filter(|p| matches!(p.state, QueryPeerState::Succeeded))
            .take(num_results)
            .map(|p| *p.key.preimage())
    }

    pub fn is_waiting_for(&self, peer: &NodeId) -> bool {
        let key = Key::from(*peer);
        let distance = key.distance(&self.target_key);
        matches!(
            self.closest_peers.get(&distance).map(|p| &p.state),
            Some(QueryPeerState::Waiting(_) | QueryPeerState::Unresponsive)
        )
    }

    fn at_capacity(&self) -> bool {
        match self.progress {
            QueryProgress::Stalled => self.num_waiting >= self.config.num_results,
            QueryProgress::Iterating { .. } => self.num_waiting >= self.config.parallelism,
            QueryProgress::Finished => true,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum QueryProgress {
    Iterating { no_progress: usize },
    Stalled,
    Finished,
}

#[derive(Debug, Clone)]
struct QueryPeer {
    key: Key,
    state: QueryPeerState,
}

impl QueryPeer {
    fn new(key: Key, state: QueryPeerState) -> Self {
        QueryPeer { key, state }
    }
}

#[derive(Debug, Copy, Clone)]
enum QueryPeerState {
    NotContacted,
    Waiting(Instant),
    Unresponsive,
    Failed,
    Succeeded,
}

/// Pool of active iterative FINDNODE queries.
pub struct QueryPool {
    next_id: usize,
    query_timeout: Duration,
    queries: FxHashMap<QueryId, Query>,
}

pub enum QueryPoolState<'a> {
    Idle,
    /// `Some` carries the next peer to contact.
    Waiting(Option<(&'a mut Query, NodeId)>),
    Finished(Query),
    #[allow(dead_code)]
    Timeout(Query),
}

impl QueryPool {
    pub fn new(query_timeout: Duration) -> Self {
        QueryPool { next_id: 0, query_timeout, queries: Default::default() }
    }

    pub fn add_findnode_query(
        &mut self,
        config: FindNodeQueryConfig,
        target_key: Key,
        peers: impl IntoIterator<Item = Key>,
    ) -> QueryId {
        let inner = FindNodeQuery::with_config(config, target_key, peers);
        let id = QueryId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.queries.insert(id, Query { id, inner, started: None });
        id
    }

    pub fn get_mut(&mut self, id: QueryId) -> Option<&mut Query> {
        self.queries.get_mut(&id)
    }

    /// Find the query that sent a request to `peer` and is awaiting a response.
    pub fn find_query_for_peer(&mut self, peer: &NodeId) -> Option<&mut Query> {
        self.queries.values_mut().find(|q| q.inner.is_waiting_for(peer))
    }

    pub fn poll(&mut self) -> QueryPoolState<'_> {
        let now = Instant::now();
        let mut waiting = None;
        let mut finished = None;
        let mut timeout = None;

        for (&id, query) in self.queries.iter_mut() {
            query.started = query.started.or(Some(now));
            match query.inner.next(now) {
                QueryState::Finished => {
                    finished = Some(id);
                    break;
                }
                QueryState::Waiting(Some(peer)) => {
                    waiting = Some((id, peer));
                    break;
                }
                QueryState::Waiting(None) | QueryState::WaitingAtCapacity => {
                    let elapsed = now - query.started.unwrap_or(now);
                    if elapsed >= self.query_timeout {
                        timeout = Some(id);
                        break;
                    }
                }
            }
        }

        if let Some((id, peer)) = waiting {
            return QueryPoolState::Waiting(Some((self.queries.get_mut(&id).unwrap(), peer)));
        }
        if let Some(id) = finished {
            return QueryPoolState::Finished(self.queries.remove(&id).unwrap());
        }
        if let Some(id) = timeout {
            return QueryPoolState::Timeout(self.queries.remove(&id).unwrap());
        }
        if self.queries.is_empty() { QueryPoolState::Idle } else { QueryPoolState::Waiting(None) }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(pub usize);

pub struct Query {
    id: QueryId,
    inner: FindNodeQuery,
    started: Option<Instant>,
}

impl Query {
    pub fn id(&self) -> QueryId {
        self.id
    }

    pub fn on_failure(&mut self, peer: &NodeId) {
        self.inner.on_failure(peer);
    }

    pub fn on_success(&mut self, peer: &NodeId, new_peers: impl IntoIterator<Item = NodeId>) {
        self.inner.on_success(peer, new_peers);
    }

    /// Consume the query, returning the closest peers that responded
    /// successfully.
    pub fn into_result(self) -> impl Iterator<Item = NodeId> {
        self.inner.into_result()
    }
}
