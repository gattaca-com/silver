use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    GossipDomain, IngestionTime, P2pStreamId, SszCache, TRead, Wheel, column_util as util,
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView, DataColumnSidecarGloasView,
        NUMBER_OF_COLUMNS, SidecarLayout, SignedBeaconBlockView,
    },
    ticker::{MAXIMUM_GOSSIP_CLOCK_DISPARITY, SlotTicker},
};

use crate::{BlockRoot, availability::ColumnTracker, sync::SyncStatus};

const COMMITMENT_EPOCHS: usize = 4;
const MAX_COMMITMENT_ROOTS: usize = 2 * COMMITMENT_EPOCHS * SLOTS_PER_EPOCH as usize;

mod fulu_header;
mod partial;
use fulu_header::{FuluHeader, ProposerCheck, SignatureError};
pub(crate) use partial::HeaderOutcome;

/// A sidecar with the provenance its validation needs. Carrying `recv_ts` is
/// what lets a column buffered before its block still report its own receive
/// time rather than the drain's.
pub(crate) struct PendingColumn {
    pub(crate) stream_id: P2pStreamId,
    pub(crate) sidecar: TRead,
    /// Which cache `sidecar` lives in, for the persist consumer.
    pub(crate) ssz_cache: SszCache,
    pub(crate) domain: Option<GossipDomain>,
    pub(crate) gossip_subnet: Option<u64>,
    pub(crate) recv_ts: IngestionTime,
}

pub(crate) enum ColumnOutcome {
    Skip,
    AlreadyHeld {
        block_root: BlockRoot,
        slot: u64,
    },
    Reject {
        block_root: BlockRoot,
        slot: u64,
        column: Option<u64>,
    },
    Buffer {
        block_root: BlockRoot,
    },
    AwaitParent {
        parent_root: BlockRoot,
    },
    /// `relay_eligible` is false when a check the gossip rules require could
    /// not be completed — the sidecar is still imported, but it must not enter
    /// the mesh on our authority.
    Record {
        block_root: BlockRoot,
        column_index: u64,
        slot: u64,
        relay_eligible: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum ParentCheck {
    Seen,
    Unseen,
    NotExtending { parent_slot: u64 },
}

impl ParentCheck {
    /// Fulu requires a sidecar to be proposed strictly after its parent block.
    fn extending(slot: u64, parent_slot: u64) -> Self {
        if slot > parent_slot { Self::Seen } else { Self::NotExtending { parent_slot } }
    }
}

struct GloasBlockCommitments {
    slot: u64,
    commitments: Box<[u8]>,
}

/// Per-sidecar validation, i.e. everything except the KZG cell proofs —
/// those are deferred to the end-of-pass batch, so `Record` means "passed
/// every check but KZG". Owns the caches only validation consults.
pub(crate) struct ColumnValidator {
    beacon_state: BeaconStateReader,
    spec: Arc<SpecConfig>,
    ticker: SlotTicker,
    // Gloas sidecars carry no commitments, so column KZG verifies against these.
    gloas_commitments: Wheel<BlockRoot, GloasBlockCommitments, COMMITMENT_EPOCHS>,
    // Blocks past validation (imported, or staged on their columns) and the
    // slot each sits at — parent-seen and parent-slot checks beyond the head
    // fork.
    validated_block_roots: Wheel<BlockRoot, u64, 16>,
    partial_parents: partial::PartialParents,
}

impl ColumnValidator {
    pub fn new(
        beacon_state: BeaconStateReader,
        spec: Arc<SpecConfig>,
        epoch_duration: Duration,
        ticker: SlotTicker,
    ) -> Self {
        Self {
            beacon_state,
            spec,
            ticker,
            gloas_commitments: Wheel::new(epoch_duration),
            validated_block_roots: Wheel::new(epoch_duration),
            partial_parents: partial::PartialParents::new(epoch_duration * 2),
        }
    }

    /// EIP-7892 `blob_schedule` entry active at `slot`'s epoch.
    fn max_blobs_at(&self, slot: u64) -> usize {
        self.spec.blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block as usize
    }

    pub fn note_validated(&mut self, block_root: BlockRoot, slot: u64) {
        if !self.validated_block_roots.contains(&block_root) {
            self.validated_block_roots.insert(block_root, slot);
        }
    }

    /// A block the beacon state dropped no longer vouches for its children.
    pub fn note_rejected(&mut self, block_root: &BlockRoot) {
        self.validated_block_roots.remove(block_root);
        self.gloas_commitments.remove(block_root);
        self.partial_parents.remember(*block_root, None);
    }

    pub fn cache_parent_state_root(&mut self, block_root: BlockRoot, buffer: &[u8]) {
        self.partial_parents.remember(block_root, Some(*SignedBeaconBlockView::state_root(buffer)));
    }

    pub fn is_validated(&self, block_root: &BlockRoot) -> bool {
        self.validated_block_roots.contains(block_root)
    }

    pub fn gloas_commitments(&self, block_root: &BlockRoot) -> Option<&[u8]> {
        if !self.validated_block_roots.contains(block_root) {
            return None;
        }
        self.gloas_commitments.get(block_root).map(|c| c.commitments.as_ref())
    }

    pub fn domain_at(&self, slot: u64) -> Option<GossipDomain> {
        self.beacon_state.read(|v| {
            GossipDomain::new(
                self.spec.fork_digest_at(slot / SLOTS_PER_EPOCH, &v.imm.genesis_validators_root),
                self.spec.fork_at_slot(slot),
            )
        })
    }

    pub fn cache_gloas_commitments(&mut self, block_root: BlockRoot, buffer: &[u8]) {
        if self.gloas_commitments.contains(&block_root) ||
            self.gloas_commitments.len() >= MAX_COMMITMENT_ROOTS
        {
            return;
        }
        let commitments = SignedBeaconBlockView::gloas_block_commitments(buffer);
        if !commitments.is_empty() &&
            commitments.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT) &&
            commitments.len() / BYTES_PER_KZG_COMMITMENT <=
                self.max_blobs_at(SignedBeaconBlockView::slot(buffer))
        {
            self.gloas_commitments.insert(block_root, GloasBlockCommitments {
                slot: SignedBeaconBlockView::slot(buffer),
                commitments: commitments.to_vec().into_boxed_slice(),
            });
        }
    }

    /// Spec `is_future_slot` for a synced node; during sync every sidecar is
    /// behind the wall clock and the gate must stay out of the way.
    fn is_future(&self, slot: u64, sync_state: &SyncStatus) -> bool {
        sync_state.is_synced() && self.ticker.is_future_slot(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY)
    }

    #[cfg(feature = "ef_tests")]
    pub(crate) fn ef_tick(&mut self, since_genesis_ms: u64) {
        self.ticker.set_since_genesis_ms(since_genesis_ms);
    }

    pub fn rotate(&mut self, now: Instant) {
        self.partial_parents.prune(now);
        self.gloas_commitments.maybe_rotate(now);
        self.validated_block_roots.maybe_rotate(now);
    }

    pub fn validate(
        &mut self,
        column: &PendingColumn,
        buffer: &[u8],
        sync_state: &SyncStatus,
        tracker: &mut ColumnTracker,
        verify_held: bool,
    ) -> Option<(ColumnOutcome, bool)> {
        match SidecarLayout::of(buffer)? {
            SidecarLayout::Gloas => {
                Some((self.validate_gloas(column, buffer, sync_state, tracker, verify_held), true))
            }
            SidecarLayout::Fulu => {
                Some((self.validate_fulu(column, buffer, sync_state, tracker, verify_held), false))
            }
        }
    }

    #[timed]
    pub fn validate_fulu(
        &mut self,
        column: &PendingColumn,
        buffer: &[u8],
        sync_state: &SyncStatus,
        tracker: &mut ColumnTracker,
        verify_held: bool,
    ) -> ColumnOutcome {
        let PendingColumn { stream_id, gossip_subnet, recv_ts, .. } = *column;
        let parent_root = DataColumnSidecarFuluView::parent_root(buffer);
        let slot = DataColumnSidecarFuluView::slot(buffer);

        if slot <= sync_state.data_availability_floor() {
            return ColumnOutcome::Skip;
        }

        if gossip_subnet.is_some() {
            let elapsed_ms = recv_ts.internal().elapsed().as_millis_u64();
            tracing::info!(
                slot,
                parent_root = hex::encode(parent_root),
                ?gossip_subnet,
                elapsed_ms,
                "data column recv"
            );
        }

        if self.is_future(slot, sync_state) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = self.ticker.current_slot(),
                "future sidecar"
            );
            return ColumnOutcome::Skip;
        }

        let header = FuluHeader::new(
            DataColumnSidecarFuluView::block_header(buffer),
            DataColumnSidecarFuluView::block_signature(buffer),
        );
        let block_root = header.root;
        let column_index = DataColumnSidecarFuluView::index(buffer);
        if column_index >= NUMBER_OF_COLUMNS as u64 {
            tracing::warn!(?stream_id, column_index, "sidecar column index out of range");
            return ColumnOutcome::Reject { block_root, slot, column: None };
        }

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        if self.spec.is_gloas_at_slot(slot) {
            tracing::warn!(?stream_id, slot, "Fulu sidecar at or after Gloas activation");
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        if !verify_held && tracker.holds(&block_root, column_index) {
            return ColumnOutcome::AlreadyHeld { block_root, slot };
        }

        if !util::verify_data_column_sidecar_fulu(buffer, self.max_blobs_at(slot)) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        if !header.verify_commitments(
            DataColumnSidecarFuluView::kzg_commitments(buffer),
            DataColumnSidecarFuluView::inclusion_proof(buffer),
        ) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        // State-driven validations: pull every input in one seqlock pass.
        // BLS verify runs OUTSIDE the closure (slow; would hold the
        // notional read lock too long otherwise).
        let validated_parent_slot = self.validated_block_roots.get(parent_root).copied();
        let checks = self.beacon_state.read(|v| {
            let parent = match validated_parent_slot {
                Some(parent_slot) => ParentCheck::extending(slot, parent_slot),
                None if parent_root == sync_state.head_root() => ParentCheck::Seen,
                None => match v.block_roots.slot_of(parent_root, v.slot.slot_number()) {
                    Some(parent_slot) => ParentCheck::extending(slot, parent_slot),
                    None => ParentCheck::Unseen,
                },
            };
            (
                header.read_state(&v),
                parent,
                v.epoch.fork().current_version, // TODO for backfill
            )
        });
        // No snapshot yet (pre-bootstrap): nothing can be validated.
        let Some((state, parent, fork_version)) = checks else {
            tracing::warn!(?stream_id, "sidecar before first beacon state snapshot");
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        };

        if slot <= state.finalized_slot() {
            tracing::warn!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return ColumnOutcome::Skip;
        }
        match parent {
            ParentCheck::Seen => {}
            ParentCheck::Unseen => {
                tracing::warn!(
                    ?stream_id,
                    slot,
                    parent_root = hex::encode(parent_root),
                    "sidecar parent_root not yet validated — ignoring (not penalized)"
                );
                return ColumnOutcome::AwaitParent { parent_root: *parent_root };
            }
            ParentCheck::NotExtending { parent_slot } => {
                tracing::warn!(?stream_id, slot, parent_slot, "sidecar does not extend its parent");
                return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
            }
        }
        let relay_eligible = match state.proposer {
            ProposerCheck::Matches => true,
            ProposerCheck::Mismatch => {
                tracing::warn!(?stream_id, "sidecar proposer_index mismatch");
                return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
            }
            // Spec answer is IGNORE.
            ProposerCheck::Unresolvable => {
                tracing::debug!(?stream_id, slot, "sidecar proposer unresolvable — not relayed");
                false
            }
        };

        match header.verify_signature(&state, fork_version, tracker) {
            Ok(()) => {}
            Err(SignatureError::UnknownProposer) => {
                tracing::warn!(?stream_id, "sidecar proposer_index out of range");
                return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
            }
            Err(SignatureError::InvalidSignature) => {
                tracing::warn!(?stream_id, "sidecar proposer signature invalid");
                return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
            }
        }

        ColumnOutcome::Record { block_root, column_index, slot, relay_eligible }
    }

    #[timed]
    pub fn validate_gloas(
        &self,
        column: &PendingColumn,
        buffer: &[u8],
        sync_state: &SyncStatus,
        tracker: &ColumnTracker,
        verify_held: bool,
    ) -> ColumnOutcome {
        let PendingColumn { stream_id, gossip_subnet, .. } = *column;
        let slot = DataColumnSidecarGloasView::slot(buffer);

        if self.is_future(slot, sync_state) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = self.ticker.current_slot(),
                "future sidecar"
            );
            return ColumnOutcome::Skip;
        }
        if slot <= sync_state.data_availability_floor() {
            return ColumnOutcome::Skip;
        }

        let block_root = *DataColumnSidecarGloasView::beacon_block_root(buffer);
        let column_index = DataColumnSidecarGloasView::index(buffer);
        if column_index >= NUMBER_OF_COLUMNS as u64 {
            tracing::warn!(?stream_id, column_index, "sidecar column index out of range");
            return ColumnOutcome::Reject { block_root, slot, column: None };
        }

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        if !verify_held && tracker.holds(&block_root, column_index) {
            return ColumnOutcome::AlreadyHeld { block_root, slot };
        }

        let Some(block) = self
            .gloas_commitments
            .get(&block_root)
            .filter(|_| self.validated_block_roots.contains(&block_root))
        else {
            return ColumnOutcome::Buffer { block_root };
        };
        if block.slot != slot {
            tracing::warn!(
                ?stream_id,
                slot,
                block_slot = block.slot,
                "sidecar slot is not its block's"
            );
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        if !util::verify_data_column_sidecar_gloas(
            buffer,
            &block.commitments,
            self.max_blobs_at(slot),
        ) {
            tracing::warn!(?stream_id, "badly formed gloas data column sidecar");
            return ColumnOutcome::Reject { block_root, slot, column: Some(column_index) };
        }

        ColumnOutcome::Record { block_root, column_index, slot, relay_eligible: true }
    }
}
