use std::{io::Write, time::Instant};

use flux::spine::SpineProducers;
use fxhash::FxHashMap;
use silver_common::{
    ForkName, GossipTopic, PeerEvent, SilverSpineProducers, TCacheProducer, TProducer,
    cell_store::{
        CellKey, CellOrigin, CellStoreConfig, CellStoreEvent, CellValidationRequest,
        CommitmentContext, DataColumnCounters, HeaderValidationRequest, MAX_CONTEXT_BYTES,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        partial_column::{
            PartialDataColumnHeaderView, PartialDataColumnSidecarFuluView,
            PartialDataColumnSidecarGloasView,
        },
    },
};
use silver_gossip::{ColumnIngress, PartialInbound};

use super::CellIngress;

#[derive(Default)]
struct PeerBudget {
    cells: usize,
    headers: usize,
}

pub(super) struct PartialBudget {
    peers: FxHashMap<usize, PeerBudget>,
    cells: usize,
    headers: usize,
    max_cells: usize,
    per_peer: usize,
}

impl PartialBudget {
    pub(super) fn new(config: &CellStoreConfig) -> Self {
        Self {
            peers: FxHashMap::with_capacity_and_hasher(256, Default::default()),
            cells: 0,
            headers: 0,
            max_cells: 2 * config.cell_capacity(),
            per_peer: 2 * config.max_blobs() * config.column_indices().len(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.peers.clear();
        self.cells = 0;
        self.headers = 0;
    }

    fn admit_peer(&mut self, peer: usize) -> bool {
        if self.peers.len() >= 256 && !self.peers.contains_key(&peer) {
            return false;
        }
        self.peers.entry(peer).or_default();
        true
    }

    fn header(&mut self, peer: usize) -> bool {
        let Some(budget) = self.peers.get_mut(&peer) else { return false };
        if self.headers >= 128 || budget.headers >= 8 {
            return false;
        }
        self.headers += 1;
        budget.headers += 1;
        true
    }

    fn cell(&mut self, peer: usize) -> bool {
        let Some(budget) = self.peers.get_mut(&peer) else { return false };
        if self.cells >= self.max_cells || budget.cells >= self.per_peer {
            return false;
        }
        self.cells += 1;
        budget.cells += 1;
        true
    }
}

impl ColumnIngress for CellIngress {
    fn producer_mut(&mut self) -> &mut TProducer {
        self.producer_mut()
    }

    fn receive_partial(&mut self, message: PartialInbound<'_>, producers: &SilverSpineProducers) {
        let now = Instant::now();
        self.spin(now, producers);
        let peer = message.stream_id.peer();
        let group = message.group;
        let (wall_slot, deadline) = self.slot_window();
        if group.column >= 128 ||
            !self.allocator.handles_column(group.column as usize) ||
            !self.partial_budget.admit_peer(peer)
        {
            return;
        }
        let parsed = match group.domain.format() {
            ForkName::Fulu => PartialDataColumnSidecarFuluView::parse(message.payload),
            ForkName::Gloas => PartialDataColumnSidecarGloasView::parse(message.payload),
            _ => return,
        };
        let Some(parsed) = parsed else {
            producers.produce(PeerEvent::ColumnVerdict {
                p2p_peer: peer,
                block_root: group.block_root,
                column: group.column,
                recv_ts: message.received,
                accepted: false,
            });
            return;
        };
        let mut slot = message.slot.unwrap_or(wall_slot);
        let mut count = parsed.n_rows;
        if let Some(header) = parsed.header {
            if header.len() > MAX_CONTEXT_BYTES {
                return;
            }
            let signed = PartialDataColumnHeaderView::signed_block_header(header);
            let Ok(slot_bytes) = signed[..8].try_into() else { return };
            slot = u64::from_le_bytes(slot_bytes);
            let header_count = PartialDataColumnHeaderView::kzg_commitments(header).len() /
                BYTES_PER_KZG_COMMITMENT;
            if parsed.rows == 0 {
                count = header_count;
            } else if header_count != count {
                producers.produce(PeerEvent::ColumnVerdict {
                    p2p_peer: peer,
                    block_root: group.block_root,
                    column: group.column,
                    recv_ts: message.received,
                    accepted: false,
                });
                return;
            }
        }
        if slot != wall_slot || slot < self.min_slot {
            return;
        }
        if count == 0 ||
            count > self.allocator.max_blobs_at(slot) ||
            self.allocator
                .trusted_context(&group.block_root)
                .is_some_and(|context| context.blob_count != count || context.slot != slot)
        {
            producers.produce(PeerEvent::ColumnVerdict {
                p2p_peer: peer,
                block_root: group.block_root,
                column: group.column,
                recv_ts: message.received,
                accepted: false,
            });
            return;
        }
        let origin = CellOrigin::Gossip {
            stream_id: message.stream_id,
            topic: GossipTopic::DataColumnSidecar(group.column),
            received: message.received,
        };
        let header = if let Some(bytes) = parsed.header {
            if !self.partial_budget.header(peer) {
                return;
            }
            let Some(mut write) = self.producer_mut().reserve(bytes.len(), false) else { return };
            if write.write_all(bytes).and_then(|_| write.flush()).is_err() {
                return;
            }
            let read = write.read();
            DataColumnCounters::PartialHeadersQueued.inc();
            producers.produce(CellStoreEvent::Header(HeaderValidationRequest {
                block_root: group.block_root,
                ssz: read,
                domain: group.domain,
                origin,
                deadline,
            }));
            Some(read)
        } else {
            None
        };
        let context = CommitmentContext {
            block_root: group.block_root,
            slot,
            format: group.domain.format(),
            blob_count: count,
        };
        if self.allocator.optimistic(context, group.domain, header, peer).is_err() {
            return;
        }
        let mut rows = parsed.rows;
        for (cell, proof) in parsed
            .cells
            .chunks_exact(BYTES_PER_CELL)
            .zip(parsed.proofs.chunks_exact(BYTES_PER_KZG_PROOF))
        {
            let row = rows.trailing_zeros() as usize;
            rows &= rows - 1;
            let (Ok(cell), Ok(proof)) = (cell.try_into(), proof.try_into()) else { return };
            let key = CellKey { block_root: group.block_root, column: group.column as usize, row };
            if let Ok(Some(pending)) = self.stage_cell(key, cell, proof, now) {
                if !self.partial_budget.cell(peer) {
                    self.cancel(pending, now);
                    return;
                }
                producers.produce(CellStoreEvent::Validate(CellValidationRequest {
                    pending,
                    slot,
                    origin,
                    domain: group.domain,
                    deadline,
                }));
                DataColumnCounters::PartialCellsQueued.inc();
            }
        }
    }
}
