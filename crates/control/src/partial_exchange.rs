use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{
    ForkName, GossipTopic, P2pSend, PeerEvent, TProducer,
    cell_store::{CellStoreConfig, ColumnAvailability},
};
use silver_gossip::{ColumnGroupKey, PartialMetadataReceived, PartsMetadata};
use silver_peer::PeerManager;

use self::{
    headers::HeaderTracker,
    peer_column::{ExchangeKey, PeerColumnExchange},
    peer_exchange::PeerExchange,
    response::PartialResponse,
};
use crate::{ControlCounters, cell_ingress::CellIngress};

mod headers;
mod peer_column;
mod peer_exchange;
mod response;
#[cfg(test)]
mod tests;

const WORK_PER_SPIN: usize = 64;
const MAX_FRAMES_PER_GROUP: u8 = 32;
const HEARTBEAT: Duration = Duration::from_millis(500);
const RETRY: Duration = Duration::from_millis(100);

pub(crate) struct PartialExchange {
    exchanges: FxHashMap<ExchangeKey, PeerColumnExchange>,
    peer_exchanges: FxHashMap<usize, PeerExchange>,
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
            peer_exchanges: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
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
        let peer = self.peer_exchanges.get(&key.peer);
        if self.exchanges.len() >= self.capacity ||
            peer.is_some_and(|p| p.columns >= self.peer_capacity) ||
            (peer.is_none() && self.peer_exchanges.len() >= self.capacity)
        {
            ControlCounters::PartialStateLimited.inc();
            return false;
        }
        self.exchanges.insert(key, PeerColumnExchange::new(slot, rows, expires, now));
        self.peer_exchanges.entry(key.peer).or_default().columns += 1;
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
            message.slot.is_some_and(|s| s != slot)
        {
            ControlCounters::PartialMetadataIgnored.inc();
            return;
        }
        let Some(peer) = peers.partial_peer(
            message.stream_id.peer(),
            GossipTopic::DataColumnSidecar(group.column),
            group.domain.digest(),
        ) else {
            ControlCounters::PartialMetadataIgnored.inc();
            return;
        };
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
        let requested = exchange.replace(message.metadata, message.slot);
        if peer.requests && requested != 0 {
            ControlCounters::PartialCellsRequested.add(requested as u64);
        }
        if column.is_some() && group.domain.format() == ForkName::Fulu {
            self.headers.known(key.peer, group);
        }
        self.schedule(key);
    }

    pub fn peer_event(&mut self, event: &PeerEvent, now: Instant) {
        match *event {
            PeerEvent::P2pOutboundMessageDropped {
                msg: P2pSend::SegmentedGossip { peer_id, frame, partial_cells },
                ..
            } => {
                if partial_cells.is_some() {
                    ControlCounters::PartialFramesDropped.inc();
                }
                // Only inspect the descriptor's sequence: its TCache bytes may
                // already have expired. One failure resets this peer's batch.
                if self
                    .peer_exchanges
                    .get_mut(&peer_id)
                    .is_some_and(|peer| peer.dropped(frame.read().seq()))
                {
                    self.retry_peer(peer_id, now);
                }
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => self.remove_peer(p2p_peer),
            PeerEvent::P2pGossipExtensions { p2p_peer, .. } => {
                self.remove_where(|key| key.peer == p2p_peer);
                self.headers.remove_peer(p2p_peer);
            }
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
                self.retry_peer(stream_id.peer(), now);
            }
            _ => {}
        }
    }

    fn retry_peer(&mut self, peer: usize, now: Instant) {
        self.headers.retry_peer(peer);
        if let Some(exchange) = self.peer_exchanges.get_mut(&peer) {
            exchange.reset_sends();
        }
        for (key, exchange) in &mut self.exchanges {
            if key.peer != peer {
                continue;
            }
            // Preserve the latest remote requests, but no longer assume our
            // availability, cells or headers reached this peer. No quota refund.
            exchange.sent = 0;
            exchange.advertised = None;
            exchange.retry_at = now + RETRY;
            if !exchange.scheduled {
                exchange.scheduled = true;
                self.ready.push_back(*key);
            }
        }
    }

    fn remove_where(&mut self, mut predicate: impl FnMut(&ExchangeKey) -> bool) {
        self.exchanges.retain(|key, _| {
            if !predicate(key) {
                return true;
            }
            // Keep the spent per-peer budget until the next heartbeat, even
            // when unsubscribing removes the peer's last column exchange.
            self.peer_exchanges.get_mut(&key.peer).unwrap().columns -= 1;
            self.headers.forget_sent(key.peer, key.group);
            false
        });
        self.ready.retain(|key| self.exchanges.contains_key(key));
    }

    fn remove_peer(&mut self, peer: usize) {
        self.remove_where(|key| key.peer == peer);
        self.headers.remove_peer(peer);
        self.peer_exchanges.remove(&peer);
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
        let mut did_work = false;
        for _ in 0..self.ready.len().min(WORK_PER_SPIN) {
            let key = self.ready.pop_front().unwrap();
            let exchange = self.exchanges.get_mut(&key).unwrap();
            exchange.scheduled = false;
            if now < exchange.retry_at {
                exchange.scheduled = true;
                self.ready.push_back(key);
                continue;
            }
            if now >= exchange.expires || exchange.frames_sent >= MAX_FRAMES_PER_GROUP {
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
            let budget = self.peer_exchanges.get_mut(&key.peer).unwrap();
            let (frame, bytes) =
                match response.write(producer, column.expires, budget.remaining_bytes()) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        ControlCounters::PartialRateLimited.inc();
                        continue;
                    }
                    Err(_) => {
                        exchange.retry_at = now + RETRY;
                        ControlCounters::PartialFramesDropped.inc();
                        continue;
                    }
                };
            let seq = frame.read().seq();
            budget.record(seq, bytes);
            exchange.sent |= rows;
            exchange.advertised = Some(column.available);
            exchange.frames_sent += 1;
            if header {
                self.headers.sent(key.peer, key.group);
            }
            ControlCounters::PartialFramesQueued.inc();
            emit(P2pSend::SegmentedGossip {
                peer_id: key.peer,
                frame,
                partial_cells: Some(rows.count_ones() as u8),
            });
            did_work = true;
        }
        ControlCounters::PartialExchanges.set(self.exchanges.len() as u64);
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
        let heartbeat = now >= self.next_heartbeat;
        if heartbeat {
            self.next_heartbeat = now + HEARTBEAT;
            self.peer_exchanges.retain(|_, peer| {
                peer.heartbeat();
                peer.columns != 0
            });
        }
        let (slot, _) = ingress.slot_window();
        if slot != self.slot {
            self.expire(slot, peers, producer, now, emit);
        }
        if heartbeat {
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
            let budget = self.peer_exchanges.get_mut(&key.peer).unwrap();
            if let Ok(Some((frame, bytes))) =
                response.write(producer, now + RETRY, budget.remaining_bytes())
            {
                budget.record(frame.read().seq(), bytes);
                emit(P2pSend::SegmentedGossip { peer_id: key.peer, frame, partial_cells: None });
                ControlCounters::PartialWithdrawals.inc();
            }
        }
        self.exchanges.clear();
        for peer in self.peer_exchanges.values_mut() {
            peer.columns = 0;
            peer.reset_sends();
        }
        self.headers.clear();
        self.ready.clear();
        self.slot = slot;
    }
}
