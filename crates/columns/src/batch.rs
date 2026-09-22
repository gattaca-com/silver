use silver_common::{
    GossipDomain, IngestionTime, MessageId, P2pStreamId, PeerEvent, SszCache, SubValidation,
    TCacheRead, TRead,
    cell_store::CellValidationRequest,
    column_util::KzgBatchEntry,
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView, DataColumnSidecarGloasView,
        NUMBER_OF_COLUMNS,
    },
};

use crate::{
    BlockRoot, availability::ColumnTracker, cell_store::CellStore, validate::ColumnValidator,
};

pub(crate) struct PendingCellKzg {
    pub request: CellValidationRequest,
    pub validation: SubValidation,
}

impl PendingCellKzg {
    pub fn entry<'a>(&'a self, store: &'a CellStore) -> Option<KzgBatchEntry<'a>> {
        let key = self.request.pending.key;
        let (_, data) = store.context(&key.block_root)?;
        let commitments = data
            .commitments()
            .get(key.row * BYTES_PER_KZG_COMMITMENT..(key.row + 1) * BYTES_PER_KZG_COMMITMENT)?;
        let [column, proofs] = self.validation.buffers();
        Some(KzgBatchEntry { column, commitments, proofs, index: key.column as u64 })
    }
}

pub(crate) type PreparedCells = [Option<PendingCellKzg>; 128];

/// The gossip frame a sidecar arrived in, kept until KZG passes so the mesh
/// receives that exact frame, on the fork domain it came from, and never an
/// unverified one.
pub(crate) struct GossipSidecarFrame {
    pub domain: GossipDomain,
    pub msg_hash: MessageId,
    pub protobuf: TCacheRead,
}

/// A sidecar that passed every per-sidecar check and awaits the end-of-pass
/// KZG batch. Holds its `TRead` so the buffer stays acquired until flush.
pub(crate) struct PendingKzg {
    pub sidecar: TRead,
    pub ssz_cache: SszCache,
    pub domain: Option<GossipDomain>,
    pub context_eligible: bool,
    pub stream_id: P2pStreamId,
    pub recv_ts: IngestionTime,
    pub block_root: BlockRoot,
    pub column_index: u64,
    pub slot: u64,
    pub is_gloas: bool,
    pub frame: Option<GossipSidecarFrame>,
}

impl From<&PendingKzg> for PeerEvent {
    fn from(p: &PendingKzg) -> Self {
        PeerEvent::ColumnVerdict {
            p2p_peer: p.stream_id.peer(),
            block_root: p.block_root,
            column: p.column_index,
            recv_ts: p.recv_ts.into(),
            accepted: true,
        }
    }
}

/// Columns collected within one `loop_body` pass for a single combined
/// `verify_cell_kzg_proof_batch` call — one pairing check per pass instead
/// of one per sidecar.
pub(crate) struct KzgBatch {
    pub pending: Vec<PendingKzg>,
}

impl KzgBatch {
    pub fn new() -> Self {
        Self { pending: Vec::with_capacity(NUMBER_OF_COLUMNS) }
    }

    /// False = a copy of this column is already queued this pass. `validated`
    /// only records at flush, so a gossip and an RPC copy arriving in the same
    /// pass would otherwise both verify; the queue drained by that flush is
    /// itself the memo, so the pass cannot leave a stale one behind.
    pub fn push(&mut self, entry: PendingKzg) -> bool {
        let queued = self
            .pending
            .iter()
            .any(|p| p.column_index == entry.column_index && p.block_root == entry.block_root);
        if queued {
            return false;
        }
        self.pending.push(entry);
        true
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Queued sidecars through the one that makes the first block available;
    /// all of them when none does.
    pub fn columns_until_available(&self, tracker: &ColumnTracker) -> usize {
        let root = self.pending[0].block_root;
        let mut held = 0;
        for (i, p) in self.pending.iter().enumerate() {
            if p.block_root == root {
                held |= 1u128 << p.column_index;
            }
            if tracker.becomes_available(&root, held) {
                return i + 1;
            }
        }
        self.pending.len()
    }
}

/// KZG inputs of one pending sidecar. `None` means the buffer can't be read
/// or (gloas) the bid commitments aged out — our failure, not the peer's.
pub(crate) fn kzg_entry<'a>(
    p: &'a PendingKzg,
    validator: &'a ColumnValidator,
) -> Option<KzgBatchEntry<'a>> {
    let (buf, _) = p.sidecar.buffer().ok()?;
    Some(if p.is_gloas {
        KzgBatchEntry {
            column: DataColumnSidecarGloasView::column(buf),
            commitments: validator.gloas_commitments(&p.block_root)?,
            proofs: DataColumnSidecarGloasView::kzg_proofs(buf),
            index: p.column_index,
        }
    } else {
        KzgBatchEntry {
            column: DataColumnSidecarFuluView::column(buf),
            commitments: DataColumnSidecarFuluView::kzg_commitments(buf),
            proofs: DataColumnSidecarFuluView::kzg_proofs(buf),
            index: p.column_index,
        }
    })
}
