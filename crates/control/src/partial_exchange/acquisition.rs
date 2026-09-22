use std::{
    collections::hash_map::Entry,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{
    DataColumnsEvent, GossipDomain, GossipTopic, SyncNeed,
    cell_store::{AssemblyRequest, CellStoreConfig, ColumnGroupKey},
    column_util::columns_of,
};
use silver_peer::PeerManager;

use super::peer_column::{ExchangeKey, PeerColumnExchange};
use crate::{ControlCounters, cell_ingress::CellIngress};

const POLL: Duration = Duration::from_millis(20);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const ACQUISITION_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_ATTEMPTS: u8 = 2;

#[derive(Clone, Copy)]
struct Request {
    peer: Option<usize>,
    rows: u128,
    deadline: Instant,
    attempts: u8,
    offered: bool,
}

impl Request {
    fn new(now: Instant) -> Self {
        Self { peer: None, rows: 0, deadline: now, attempts: 0, offered: false }
    }

    fn refresh(
        &mut self,
        missing: u128,
        group: ColumnGroupKey,
        peers: &PeerManager,
        exchanges: &FxHashMap<ExchangeKey, PeerColumnExchange>,
        now: Instant,
    ) {
        self.rows &= missing;
        if self.rows == 0 {
            return;
        }
        let failed = self.peer.is_some_and(|peer| {
            peers
                .partial_peer(
                    peer,
                    GossipTopic::DataColumnSidecar(group.column),
                    group.domain.digest(),
                )
                .is_none() ||
                (self.offered &&
                    exchanges
                        .get(&ExchangeKey { peer, group })
                        .and_then(|exchange| exchange.remote)
                        .is_some_and(|remote| remote.available & self.rows == 0))
        });
        if now >= self.deadline || failed {
            self.cancel();
            ControlCounters::PartialRequestsTimedOut.inc();
        }
    }

    fn can_retry(&self) -> bool {
        self.rows == 0 && self.attempts < MAX_ATTEMPTS
    }

    fn exhausted(&self) -> bool {
        self.rows == 0 && self.attempts >= MAX_ATTEMPTS
    }

    fn assign(&mut self, peer: usize, missing: u128, offered: u128, now: Instant) {
        self.peer = Some(peer);
        self.rows = if offered == 0 { missing } else { offered };
        self.offered = offered != 0;
        self.deadline = now + REQUEST_TIMEOUT;
        self.attempts += 1;
    }

    fn cancel(&mut self) -> Option<usize> {
        if self.rows == 0 {
            return None;
        }
        self.rows = 0;
        // Keep the last peer and attempt count so a retry chooses a different peer.
        self.peer
    }
}

struct BlockAcquisition {
    domain: GossipDomain,
    slot: u64,
    n_rows: usize,
    columns: u128,
    deadline: Instant,
    requests: [Request; 128],
    recovering: bool,
}

impl BlockAcquisition {
    fn new(request: AssemblyRequest, columns: u128, expires: Instant, now: Instant) -> Self {
        Self {
            domain: request.domain,
            slot: request.context.slot,
            n_rows: request.context.blob_count,
            columns,
            deadline: expires.min(now + ACQUISITION_TIMEOUT),
            requests: [Request::new(now); 128],
            recovering: false,
        }
    }

    fn cancel_requests(&mut self, root: [u8; 32], columns: u128, changed: &mut Vec<ExchangeKey>) {
        for column in columns_of(columns) {
            if let Some(peer) = self.requests[column as usize].cancel() {
                changed.push(ExchangeKey {
                    peer,
                    group: ColumnGroupKey { domain: self.domain, block_root: root, column },
                });
            }
        }
    }

    fn recover(&mut self, root: [u8; 32]) -> Option<SyncNeed> {
        if self.recovering || self.columns == 0 {
            return None;
        }
        self.recovering = true;
        ControlCounters::PartialFullFallbacks.inc();
        Some(SyncNeed::missing_columns(root, self.slot, self.columns))
    }
}

pub(super) struct Acquisition {
    blocks: FxHashMap<[u8; 32], BlockAcquisition>,
    completed: FxHashMap<[u8; 32], u128>,
    changed: Vec<ExchangeKey>,
    peer_load: FxHashMap<usize, usize>,
    capacity: usize,
    completion_capacity: usize,
    columns: u128,
    slot: u64,
    next_poll: Instant,
}

impl Acquisition {
    pub fn new(config: &CellStoreConfig, slot: u64, now: Instant) -> Self {
        let capacity = config.live_blocks();
        Self {
            blocks: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            completed: FxHashMap::with_capacity_and_hasher(
                config.block_capacity(),
                Default::default(),
            ),
            changed: Vec::with_capacity(capacity * config.columns().count_ones() as usize * 3),
            peer_load: FxHashMap::with_capacity_and_hasher(
                capacity * config.columns().count_ones() as usize,
                Default::default(),
            ),
            capacity,
            completion_capacity: config.block_capacity(),
            columns: config.columns(),
            slot,
            next_poll: now,
        }
    }

    // Only the validated context handoff may create demand. Optimistic assemblies
    // and peer metadata never authorize requests.
    pub fn context(&mut self, request: AssemblyRequest, expires: Instant, now: Instant) {
        let context = request.context;
        if context.slot != self.slot || now >= expires || !(1..=128).contains(&context.blob_count) {
            return;
        }
        let full = self.blocks.len() >= self.capacity;
        if let Entry::Vacant(entry) = self.blocks.entry(context.block_root) {
            if full {
                ControlCounters::PartialStateLimited.inc();
                return;
            }
            let columns = request.columns &
                self.columns &
                !self.completed.get(&context.block_root).copied().unwrap_or(0);
            entry.insert(BlockAcquisition::new(request, columns, expires, now));
        }
        self.wake(now);
    }

    pub fn validated(&mut self, event: DataColumnsEvent, now: Instant) {
        if let DataColumnsEvent::Validated { block_root, column_index, slot, .. } |
        DataColumnsEvent::Persist { block_root, column_index, slot, .. } = event &&
            slot == self.slot &&
            column_index < 128
        {
            self.complete(block_root, 1 << column_index);
            self.wake(now);
        }
    }

    fn complete(&mut self, root: [u8; 32], columns: u128) {
        if self.completed.len() < self.completion_capacity || self.completed.contains_key(&root) {
            *self.completed.entry(root).or_default() |= columns;
        }
        if let Some(block) = self.blocks.get_mut(&root) {
            block.columns &= !columns;
        }
    }

    pub fn reject(&mut self, root: &[u8; 32]) {
        self.blocks.remove(root);
        self.complete(*root, self.columns);
    }

    pub fn wake(&mut self, now: Instant) {
        self.next_poll = now;
    }

    pub fn pop_changed(&mut self) -> Option<ExchangeKey> {
        self.changed.pop()
    }

    pub fn requests(&self, key: ExchangeKey) -> u128 {
        self.blocks
            .get(&key.group.block_root)
            .filter(|block| block.domain == key.group.domain)
            .and_then(|block| block.requests.get(key.group.column as usize))
            .filter(|request| request.peer == Some(key.peer))
            .map_or(0, |request| request.rows)
    }

    pub fn advance_slot(&mut self, slot: u64, now: Instant, recover: &mut impl FnMut(SyncNeed)) {
        if slot != self.slot {
            for (root, block) in &mut self.blocks {
                if let Some(need) = block.recover(*root) {
                    recover(need);
                }
            }
            self.blocks.clear();
            self.completed.clear();
            self.changed.clear();
            self.slot = slot;
            self.next_poll = now;
        }
    }

    pub fn drive(
        &mut self,
        ingress: &CellIngress,
        peers: &PeerManager,
        exchanges: &FxHashMap<ExchangeKey, PeerColumnExchange>,
        now: Instant,
        recover: &mut impl FnMut(SyncNeed),
    ) {
        if now < self.next_poll {
            return;
        }
        self.next_poll = now + POLL;
        self.peer_load.clear();
        for (&root, block) in &mut self.blocks {
            if block.recovering {
                continue;
            }
            let mut fallback = false;
            let all = u128::MAX.checked_shr(128 - block.n_rows as u32).unwrap_or(0);
            for column in columns_of(self.columns) {
                let group = ColumnGroupKey { domain: block.domain, block_root: root, column };
                let request = &mut block.requests[column as usize];
                if block.columns & (1 << column) == 0 && request.rows == 0 {
                    continue;
                }
                let previous = *request;
                let available =
                    ingress.availability(&root, column as usize, now).filter(|column| {
                        column.domain == block.domain && column.blob_count == block.n_rows
                    });
                let missing = all & !available.map_or(0, |column| column.available);
                if missing == 0 {
                    block.columns &= !(1 << column);
                }
                if fallback || block.columns & (1 << column) == 0 {
                    request.cancel();
                } else {
                    request.refresh(missing, group, peers, exchanges, now);
                    if request.can_retry() && available.is_some() && now < block.deadline {
                        let candidate = peers
                            .partial_peers(
                                GossipTopic::DataColumnSidecar(column),
                                group.domain.digest(),
                            )
                            .filter(|peer| request.peer != Some(peer.connection))
                            .filter_map(|peer| {
                                let exchange =
                                    exchanges.get(&ExchangeKey { peer: peer.connection, group });
                                if exchange.is_some_and(|exchange| {
                                    !exchange.remote_matches(block.slot, block.n_rows)
                                }) {
                                    return None;
                                }
                                let offered = exchange
                                    .and_then(|exchange| exchange.remote)
                                    .map_or(0, |remote| remote.available & missing);
                                Some((peer, offered))
                            })
                            .max_by_key(|(peer, offered)| {
                                (
                                    offered.count_ones(),
                                    usize::MAX -
                                        self.peer_load
                                            .get(&peer.connection)
                                            .copied()
                                            .unwrap_or(0),
                                    peer.meshed,
                                    usize::MAX - peer.connection,
                                )
                            });
                        if let Some((peer, offered)) = candidate {
                            request.assign(peer.connection, missing, offered, now);
                        }
                    }
                    if now >= block.deadline || request.exhausted() {
                        fallback = true;
                    }
                }
                if previous.peer != request.peer || previous.rows != request.rows {
                    if let Some(peer) = previous.peer {
                        self.changed.push(ExchangeKey { peer, group });
                    }
                    if let Some(peer) = request.peer &&
                        previous.peer != request.peer
                    {
                        self.changed.push(ExchangeKey { peer, group });
                    }
                }
                if request.rows != 0 &&
                    let Some(peer) = request.peer
                {
                    *self.peer_load.entry(peer).or_default() += 1;
                }
            }
            if fallback {
                block.cancel_requests(root, self.columns, &mut self.changed);
                if let Some(need) = block.recover(root) {
                    recover(need);
                }
            }
        }
    }
}
