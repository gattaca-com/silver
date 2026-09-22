use std::{io::Write, time::Instant};

use flux::spine::SpineProducers;
use fxhash::FxHashMap;
use silver_common::{
    ForkName, GossipTopic, PeerEvent, SilverSpineProducers, TCacheProducer, TCacheRead, TProducer,
    cell_store::{
        CellKey, CellOrigin, CellStoreConfig, CellStoreEvent, CellValidationRequest,
        CommitmentContext, DataColumnCounters, HeaderValidationRequest, MAX_CONTEXT_BYTES,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        partial_column::{
            PartialColumnView, PartialDataColumnHeaderView, PartialDataColumnSidecarFuluView,
            PartialDataColumnSidecarGloasView,
        },
    },
};
use silver_gossip::{ColumnGroupKey, ColumnIngress, PartialInbound};

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
        if !self.admits(peer, group) {
            return;
        }
        let Some(parsed) = parse(group.domain.format(), message.payload) else {
            reject(&message, producers);
            return;
        };

        let (wall_slot, deadline) = self.slot_window();
        let Some((slot, count)) = header_slot_and_count(&parsed, message.slot.unwrap_or(wall_slot))
        else {
            reject(&message, producers);
            return;
        };
        if slot != wall_slot || slot < self.min_slot {
            return;
        }
        if !self.count_matches_context(&group.block_root, slot, count) {
            reject(&message, producers);
            return;
        }

        let origin = CellOrigin::Gossip {
            stream_id: message.stream_id,
            topic: GossipTopic::DataColumnSidecar(group.column),
            received: message.received,
        };
        let header = match parsed.header {
            Some(bytes) => {
                let Some(read) = self.queue_header(peer, bytes, group, origin, deadline, producers)
                else {
                    return;
                };
                Some(read)
            }
            None => None,
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
        self.stage_cells(&parsed, group, slot, peer, origin, deadline, now, producers);
    }
}

impl CellIngress {
    fn admits(&mut self, peer: usize, group: ColumnGroupKey) -> bool {
        matches!(group.domain.format(), ForkName::Fulu | ForkName::Gloas) &&
            group.column < 128 &&
            self.allocator.handles_column(group.column as usize) &&
            self.partial_budget.admit_peer(peer)
    }

    fn count_matches_context(&self, root: &[u8; 32], slot: u64, count: usize) -> bool {
        count != 0 &&
            count <= self.allocator.max_blobs_at(slot) &&
            self.allocator
                .trusted_context(root)
                .is_none_or(|context| context.blob_count == count && context.slot == slot)
    }

    fn queue_header(
        &mut self,
        peer: usize,
        bytes: &[u8],
        group: ColumnGroupKey,
        origin: CellOrigin,
        deadline: Instant,
        producers: &SilverSpineProducers,
    ) -> Option<TCacheRead> {
        if !self.partial_budget.header(peer) {
            return None;
        }
        let mut write = self.producer_mut().reserve(bytes.len(), false)?;
        write.write_all(bytes).and_then(|_| write.flush()).ok()?;
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
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_cells(
        &mut self,
        parsed: &PartialColumnView<'_>,
        group: ColumnGroupKey,
        slot: u64,
        peer: usize,
        origin: CellOrigin,
        deadline: Instant,
        now: Instant,
        producers: &SilverSpineProducers,
    ) {
        let mut rows = parsed.rows;
        for (cell, proof) in parsed
            .cells
            .chunks_exact(BYTES_PER_CELL)
            .zip(parsed.proofs.chunks_exact(BYTES_PER_KZG_PROOF))
        {
            let row = rows.trailing_zeros() as usize;
            rows &= rows - 1;
            let (cell, proof) =
                (cell.try_into().expect("exact chunk"), proof.try_into().expect("exact chunk"));
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

fn parse(format: ForkName, payload: &[u8]) -> Option<PartialColumnView<'_>> {
    match format {
        ForkName::Fulu => PartialDataColumnSidecarFuluView::parse(payload),
        ForkName::Gloas => PartialDataColumnSidecarGloasView::parse(payload),
        _ => None,
    }
}

/// `None` when the header exceeds the context cap or its commitment count
/// disagrees with the bitmap; both are the peer's fault.
fn header_slot_and_count(
    parsed: &PartialColumnView<'_>,
    default_slot: u64,
) -> Option<(u64, usize)> {
    let Some(header) = parsed.header else { return Some((default_slot, parsed.n_rows)) };
    if header.len() > MAX_CONTEXT_BYTES {
        return None;
    }
    let signed = PartialDataColumnHeaderView::signed_block_header(header);
    let slot = u64::from_le_bytes(signed[..8].try_into().expect("fixed header"));
    let header_count =
        PartialDataColumnHeaderView::kzg_commitments(header).len() / BYTES_PER_KZG_COMMITMENT;
    if parsed.rows == 0 {
        return Some((slot, header_count));
    }
    (header_count == parsed.n_rows).then_some((slot, header_count))
}

fn reject(message: &PartialInbound<'_>, producers: &SilverSpineProducers) {
    producers.produce(PeerEvent::ColumnVerdict {
        p2p_peer: message.stream_id.peer(),
        block_root: message.group.block_root,
        column: message.group.column,
        recv_ts: message.received,
        accepted: false,
    });
}
