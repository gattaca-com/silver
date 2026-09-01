use silver_common::{
    GossipTopic, IngestionTime, MessageId, Nanos, P2pStreamId, TCacheRead, TRead,
    column_util::KzgBatchEntry,
    ssz_view::{DataColumnSidecarFuluView, DataColumnSidecarGloasView, NUMBER_OF_COLUMNS},
};

use crate::{BlockRoot, validate::ColumnValidator};

/// Relay owed to the network once a batched sidecar verifies: forwarding for
/// gossip-origin sidecars, publish for RPC-fetched ones. Deferred with the
/// KZG check so nothing unverified is ever relayed.
pub(crate) enum RelayMeta {
    None,
    Gossip { topic: GossipTopic, msg_hash: MessageId, recv_ts: Nanos, protobuf: TCacheRead },
    Rpc { ssz: TCacheRead },
}

/// A sidecar that passed every per-sidecar check and awaits the end-of-pass
/// KZG batch. Holds its `TRead` so the buffer stays acquired until flush.
pub(crate) struct PendingKzg {
    pub sidecar: TRead,
    pub stream_id: P2pStreamId,
    pub recv_ts: IngestionTime,
    pub block_root: BlockRoot,
    pub column_index: u64,
    pub bitmask: u128,
    pub slot: u64,
    pub is_gloas: bool,
    pub relay: RelayMeta,
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
            .any(|p| p.bitmask == entry.bitmask && p.block_root == entry.block_root);
        if queued {
            return false;
        }
        self.pending.push(entry);
        true
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
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
