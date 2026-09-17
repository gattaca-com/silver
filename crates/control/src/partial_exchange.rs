use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{
    ForkName, GossipFrameOutcome, GossipFrameResult, GossipTopic, P2pSend, PeerEvent, TProducer,
    cell_store::{CellStoreConfig, ColumnAvailability},
};
use silver_gossip::{ColumnGroupKey, PartialMetadataReceived, PartsMetadata};
use silver_peer::PeerManager;

use self::{
    headers::HeaderTracker,
    peer_column::{ExchangeKey, PeerColumnExchange},
    response::PartialResponse,
};
use crate::{ControlCounters, cell_ingress::CellIngress};

mod headers;
mod peer_column;
mod response;
#[cfg(test)]
mod tests;

const WORK_PER_SPIN: usize = 64;
const MAX_PENDING: usize = 128;
const MAX_FRAMES_PER_GROUP: u8 = 32;
const HEARTBEAT: Duration = Duration::from_millis(500);
const RETRY: Duration = Duration::from_millis(100);

struct PendingPartialSend {
    key: ExchangeKey,
    rows: u128,
    available: u128,
    header: bool,
}

pub(crate) struct PartialExchange {
    exchanges: FxHashMap<ExchangeKey, PeerColumnExchange>,
    peer_counts: FxHashMap<usize, usize>,
    pending: FxHashMap<(usize, u64), PendingPartialSend>,
    headers: HeaderTracker,
    ready: VecDeque<ExchangeKey>,
    capacity: usize,
    peer_capacity: usize,
    max_rows: usize,
    columns: u128,
    slot: u64,
    next_heartbeat: Instant,
}

impl PartialExchange {
    pub fn new(config: &CellStoreConfig, slot: u64, now: Instant) -> Self {
        let peer_capacity = config.column_capacity().max(16);
        let capacity = (peer_capacity * 32).min(8192);
        Self {
            exchanges: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            peer_counts: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            pending: FxHashMap::with_capacity_and_hasher(MAX_PENDING, Default::default()),
            headers: HeaderTracker::new(capacity),
            ready: VecDeque::with_capacity(capacity),
            capacity,
            peer_capacity,
            max_rows: config.max_blobs(),
            columns: config.columns(),
            slot,
            next_heartbeat: now,
        }
    }

    fn admit(
        &mut self,
        key: ExchangeKey,
        slot: u64,
        rows: usize,
        expires: Instant,
        now: Instant,
    ) -> bool {
        if self.exchanges.contains_key(&key) {
            return true;
        }
        let count = self.peer_counts.get(&key.peer).copied().unwrap_or(0);
        if self.exchanges.len() >= self.capacity || count >= self.peer_capacity {
            ControlCounters::PartialStateLimited.inc();
            return false;
        }
        self.exchanges.insert(key, PeerColumnExchange::new(slot, rows, expires, now));
        self.peer_counts.insert(key.peer, count + 1);
        true
    }

    fn schedule(&mut self, key: ExchangeKey) {
        if let Some(exchange) = self.exchanges.get_mut(&key) &&
            !exchange.scheduled
        {
            exchange.scheduled = true;
            self.ready.push_back(key);
        }
    }

    pub fn available(
        &mut self,
        column: ColumnAvailability,
        peers: &PeerManager,
        now: Instant,
        lazy: bool,
    ) {
        if now >= column.expires || column.slot != self.slot {
            return;
        }
        let group = ColumnGroupKey::from(column);
        let topic = GossipTopic::DataColumnSidecar(group.column);
        let mut lazy_remaining = if lazy { peers.lazy_gossip_limit() } else { 0 };
        for peer in peers.partial_peers(topic, group.domain.digest()) {
            let key = ExchangeKey { peer: peer.connection, group };
            if !peer.meshed && !self.exchanges.contains_key(&key) {
                if lazy_remaining == 0 {
                    continue;
                }
                lazy_remaining -= 1;
            }
            if !self.admit(key, column.slot, column.blob_count, column.expires, now) {
                continue;
            }
            let exchange = self.exchanges.get_mut(&key).unwrap();
            exchange.slot = column.slot;
            exchange.n_rows = column.blob_count;
            exchange.expires = column.expires;
            if exchange.remote.is_some_and(|remote| remote.n_rows != column.blob_count) ||
                exchange.remote_slot.is_some_and(|slot| slot != column.slot)
            {
                exchange.remote = None;
                exchange.remote_slot = None;
                ControlCounters::PartialMetadataIgnored.inc();
            }
            if exchange.remote.is_some() && group.domain.format() == ForkName::Fulu {
                self.headers.known(key.peer, group);
            }
            self.schedule(key);
        }
    }

    pub fn metadata(
        &mut self,
        message: PartialMetadataReceived,
        ingress: &CellIngress,
        peers: &PeerManager,
        now: Instant,
    ) {
        ControlCounters::PartialMetadataReceived.inc();
        let group = message.group;
        let (slot, expires) = ingress.slot_window();
        if group.column >= 128 ||
            self.columns & (1u128 << group.column) == 0 ||
            message.metadata.n_rows == 0 ||
            message.metadata.n_rows > self.max_rows ||
            message.slot.is_some_and(|s| s != slot) ||
            peers
                .partial_peer(
                    message.stream_id.peer(),
                    GossipTopic::DataColumnSidecar(group.column),
                    group.domain.digest(),
                )
                .is_none()
        {
            ControlCounters::PartialMetadataIgnored.inc();
            return;
        }
        let column = ingress.availability(&group.block_root, group.column as usize, now);
        if column.is_some_and(|c| {
            c.domain != group.domain ||
                c.blob_count != message.metadata.n_rows ||
                message.slot.is_some_and(|s| s != c.slot)
        }) {
            ControlCounters::PartialMetadataIgnored.inc();
            return;
        }
        let key = ExchangeKey { peer: message.stream_id.peer(), group };
        if !self.admit(key, slot, message.metadata.n_rows, expires, now) {
            return;
        }
        let exchange = self.exchanges.get_mut(&key).unwrap();
        if exchange.remote.is_some() {
            ControlCounters::PartialMetadataReplaced.inc();
        }
        exchange.replace(message.metadata, message.slot);
        if column.is_some() && group.domain.format() == ForkName::Fulu {
            self.headers.known(key.peer, group);
        }
        self.schedule(key);
    }

    pub fn peer_event(&mut self, event: &PeerEvent, now: Instant) {
        match *event {
            PeerEvent::SegmentedGossipResult(result) => self.completed(result, now),
            PeerEvent::P2pDisconnect { p2p_peer, .. } |
            PeerEvent::P2pGossipExtensions { p2p_peer, .. } => self.remove_peer(p2p_peer),
            PeerEvent::P2pNewConnection { p2p_peer_id, .. } => self.remove_peer(p2p_peer_id),
            PeerEvent::P2pGossipTopicUnsubscribe {
                p2p_peer,
                topic: GossipTopic::DataColumnSidecar(column),
                digest,
            } |
            PeerEvent::P2pGossipPartialCaps { p2p_peer, subnet: column, digest, .. } => {
                self.remove_where(|key| {
                    key.peer == p2p_peer &&
                        key.group.column == column &&
                        key.group.domain.digest() == digest
                });
            }
            PeerEvent::P2pStreamClosed { stream_id } if stream_id.protocol().is_gossip() => {
                self.headers.reset_stream(stream_id);
                self.remove_peer(stream_id.peer());
            }
            _ => {}
        }
    }

    fn completed(&mut self, result: GossipFrameResult, now: Instant) {
        let Some(pending) = self.pending.remove(&(result.p2p_peer, result.frame_seq)) else {
            return
        };
        let written = match result.outcome {
            GossipFrameOutcome::Written { stream_id } => Some(stream_id),
            GossipFrameOutcome::Dropped => None,
        };
        if pending.header {
            self.headers.complete(result.p2p_peer, pending.key.group, result.frame_seq, written);
        }
        if let Some(exchange) = self.exchanges.get_mut(&pending.key) {
            exchange.pending = false;
            if written.is_some() {
                exchange.sent |= pending.rows;
                exchange.advertised = Some(pending.available);
                ControlCounters::PartialFramesWritten.inc();
                if pending.rows != 0 {
                    ControlCounters::PartialResponsesSent.inc();
                    ControlCounters::PartialCellsServed.add(pending.rows.count_ones() as u64);
                }
            } else {
                exchange.retry_at = now + RETRY;
                ControlCounters::PartialFramesDropped.inc();
            }
            self.schedule(pending.key);
        }
    }

    fn remove_where(&mut self, mut predicate: impl FnMut(&ExchangeKey) -> bool) {
        self.exchanges.retain(|key, _| {
            if !predicate(key) {
                return true;
            }
            let count = self.peer_counts.get_mut(&key.peer).unwrap();
            *count -= 1;
            if *count == 0 {
                self.peer_counts.remove(&key.peer);
            }
            false
        });
        self.pending.retain(|&(peer, seq), pending| {
            if self.exchanges.contains_key(&pending.key) {
                return true;
            }
            if pending.header {
                self.headers.complete(peer, pending.key.group, seq, None);
            }
            false
        });
        self.ready.retain(|key| self.exchanges.contains_key(key));
    }

    fn remove_peer(&mut self, peer: usize) {
        self.remove_where(|key| key.peer == peer);
        self.headers.remove_peer(peer);
    }

    pub fn reject(&mut self, root: &[u8; 32]) {
        self.remove_where(|key| &key.group.block_root == root);
        self.headers.remove_root(root);
    }

    pub fn validated_sender(&mut self, peer: usize, column: ColumnAvailability) {
        if column.domain.format() == ForkName::Fulu {
            self.headers.known(peer, column.into());
        }
    }

    pub fn spin(
        &mut self,
        ingress: &CellIngress,
        peers: &PeerManager,
        producer: &mut TProducer,
        now: Instant,
        emit: &mut impl FnMut(P2pSend),
    ) -> bool {
        self.advance_slot(ingress, peers, producer, now, emit);
        if now >= self.next_heartbeat {
            self.next_heartbeat = now + HEARTBEAT;
            self.remove_where(|key| {
                peers
                    .partial_peer(
                        key.peer,
                        GossipTopic::DataColumnSidecar(key.group.column),
                        key.group.domain.digest(),
                    )
                    .is_none()
            });
            for column in ingress.columns(now) {
                self.available(column, peers, now, true);
            }
        }
        let mut did_work = false;
        for _ in 0..self.ready.len().min(WORK_PER_SPIN) {
            if self.pending.len() >= MAX_PENDING {
                break;
            }
            let key = self.ready.pop_front().unwrap();
            let exchange = self.exchanges.get_mut(&key).unwrap();
            exchange.scheduled = false;
            if exchange.pending ||
                now < exchange.retry_at ||
                now >= exchange.expires ||
                exchange.frames_sent >= MAX_FRAMES_PER_GROUP
            {
                continue;
            }
            let Some(peer) = peers.partial_peer(
                key.peer,
                GossipTopic::DataColumnSidecar(key.group.column),
                key.group.domain.digest(),
            ) else {
                continue;
            };
            let Some(column) = ingress
                .availability(&key.group.block_root, key.group.column as usize, now)
                .filter(|c| c.domain == key.group.domain)
            else {
                continue;
            };
            if exchange.remote.is_some_and(|r| r.n_rows != column.blob_count) ||
                exchange.remote_slot.is_some_and(|s| s != column.slot)
            {
                continue;
            }
            let rows = if peer.requests { exchange.requested(column.available) } else { 0 };
            let header = peer.requests &&
                key.group.domain.format() == ForkName::Fulu &&
                column.header.is_some() &&
                self.headers.needed(key.peer, key.group);
            if rows == 0 && !header && exchange.advertised == Some(column.available) {
                continue;
            }
            let response = PartialResponse {
                group: key.group,
                slot: column.slot,
                metadata: PartsMetadata {
                    available: column.available,
                    requests: 0,
                    n_rows: column.blob_count,
                },
                column: Some(column),
                rows,
                header,
            };
            let frame = match response.write(producer, column.expires) {
                Ok(frame) => frame,
                Err(_) => {
                    exchange.retry_at = now + RETRY;
                    ControlCounters::PartialFramesDropped.inc();
                    continue;
                }
            };
            let seq = frame.read().seq();
            exchange.pending = true;
            exchange.frames_sent += 1;
            self.pending.insert((key.peer, seq), PendingPartialSend {
                key,
                rows,
                available: column.available,
                header,
            });
            if header {
                self.headers.queued(key.peer, key.group, seq);
            }
            ControlCounters::PartialFramesQueued.inc();
            emit(P2pSend::SegmentedGossip { peer_id: key.peer, frame });
            did_work = true;
        }
        ControlCounters::PartialExchanges.set(self.exchanges.len() as u64);
        ControlCounters::PartialPendingFrames.set(self.pending.len() as u64);
        did_work
    }

    pub fn advance_slot(
        &mut self,
        ingress: &CellIngress,
        peers: &PeerManager,
        producer: &mut TProducer,
        now: Instant,
        emit: &mut impl FnMut(P2pSend),
    ) {
        let (slot, _) = ingress.slot_window();
        if slot != self.slot {
            self.expire(slot, peers, producer, now, emit);
        }
    }

    fn expire(
        &mut self,
        slot: u64,
        peers: &PeerManager,
        producer: &mut TProducer,
        now: Instant,
        emit: &mut impl FnMut(P2pSend),
    ) {
        for (key, exchange) in self
            .exchanges
            .iter()
            .filter(|(_, e)| e.advertised.is_some_and(|a| a != 0))
            .take(WORK_PER_SPIN)
        {
            if peers
                .partial_peer(
                    key.peer,
                    GossipTopic::DataColumnSidecar(key.group.column),
                    key.group.domain.digest(),
                )
                .is_none()
            {
                continue;
            }
            let response = PartialResponse {
                group: key.group,
                slot: exchange.slot,
                metadata: PartsMetadata { available: 0, requests: 0, n_rows: exchange.n_rows },
                column: None,
                rows: 0,
                header: false,
            };
            if let Ok(frame) = response.write(producer, now + RETRY) {
                emit(P2pSend::SegmentedGossip { peer_id: key.peer, frame });
                ControlCounters::PartialWithdrawals.inc();
            }
        }
        self.exchanges.clear();
        self.peer_counts.clear();
        self.pending.clear();
        self.headers.clear();
        self.ready.clear();
        self.slot = slot;
        self.next_heartbeat = now;
    }
}
