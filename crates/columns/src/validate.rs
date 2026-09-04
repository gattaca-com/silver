use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    IngestionTime, P2pStreamId, TRead, Wheel, column_util as util,
    ssz_view::{
        DataColumnSidecarFuluView, DataColumnSidecarGloasView, NUMBER_OF_COLUMNS, SidecarLayout,
        SignedBeaconBlockView,
    },
};

use crate::{BlockRoot, availability::ColumnTracker, sync::SyncStatus};

/// A sidecar with the provenance its validation needs. Carrying `recv_ts` is
/// what lets a column buffered before its block still report its own receive
/// time rather than the drain's.
pub(crate) struct PendingColumn {
    pub(crate) stream_id: P2pStreamId,
    pub(crate) sidecar: TRead,
    pub(crate) gossip_subnet: Option<u64>,
    pub(crate) recv_ts: IngestionTime,
}

pub(crate) enum ColumnOutcome {
    Skip,
    AlreadyHeld {
        block_root: BlockRoot,
        column_index: u64,
        slot: u64,
    },
    Reject {
        block_root: BlockRoot,
        slot: u64,
        bitmask: u128,
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
        bitmask: u128,
        slot: u64,
        relay_eligible: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum ProposerCheck {
    Matches,
    Mismatch,
    Unresolvable,
}

#[derive(Debug, PartialEq, Eq)]
enum ParentCheck {
    Seen,
    Unseen,
    NotExtending { parent_slot: u64 },
}

/// Per-sidecar validation, i.e. everything except the KZG cell proofs —
/// those are deferred to the end-of-pass batch, so `Record` means "passed
/// every check but KZG". Owns the caches only validation consults.
pub(crate) struct ColumnValidator {
    beacon_state: BeaconStateReader,
    spec: Arc<SpecConfig>,
    // Gloas sidecars carry no commitments, so column KZG verifies against these.
    gloas_commitments: Wheel<BlockRoot, Box<[u8]>, 4>,
    // Persisted blocks and the slot each sits at — parent-seen and
    // parent-slot checks beyond the head fork.
    persisted_block_roots: Wheel<BlockRoot, u64, 16>,
}

impl ColumnValidator {
    pub fn new(
        beacon_state: BeaconStateReader,
        spec: Arc<SpecConfig>,
        epoch_duration: Duration,
    ) -> Self {
        Self {
            beacon_state,
            spec,
            gloas_commitments: Wheel::new(epoch_duration),
            persisted_block_roots: Wheel::new(epoch_duration),
        }
    }

    /// EIP-7892 `blob_schedule` entry active at `slot`'s epoch.
    fn max_blobs_at(&self, slot: u64) -> usize {
        self.spec.blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block as usize
    }

    pub fn note_persisted(&mut self, block_root: BlockRoot, slot: u64) {
        self.persisted_block_roots.insert(block_root, slot);
    }

    /// Fulu requires a sidecar to be proposed strictly after its parent block.
    fn check_parent(&self, parent_root: &BlockRoot, slot: u64, in_head_fork: bool) -> ParentCheck {
        match self.persisted_block_roots.get(parent_root) {
            Some(&parent_slot) if slot <= parent_slot => ParentCheck::NotExtending { parent_slot },
            Some(_) => ParentCheck::Seen,
            None if in_head_fork => ParentCheck::Seen,
            None => ParentCheck::Unseen,
        }
    }

    pub fn gloas_commitments(&self, block_root: &BlockRoot) -> Option<&[u8]> {
        self.gloas_commitments.get(block_root).map(|c| c.as_ref())
    }

    pub fn cache_gloas_commitments(&mut self, block_root: BlockRoot, buffer: &[u8]) {
        if self.gloas_commitments.contains(&block_root) {
            return;
        }
        let commitments = SignedBeaconBlockView::gloas_block_commitments(buffer);
        if !commitments.is_empty() {
            self.gloas_commitments.insert(block_root, commitments.to_vec().into_boxed_slice());
        }
    }

    pub fn rotate(&mut self, now: Instant) {
        self.gloas_commitments.maybe_rotate(now);
        self.persisted_block_roots.maybe_rotate(now);
    }

    pub fn validate(
        &mut self,
        column: &PendingColumn,
        buffer: &[u8],
        sync_state: &SyncStatus,
        tracker: &mut ColumnTracker,
    ) -> Option<(ColumnOutcome, bool)> {
        match SidecarLayout::of(buffer)? {
            SidecarLayout::Gloas => {
                Some((self.validate_gloas(column, buffer, sync_state, tracker), true))
            }
            SidecarLayout::Fulu => {
                Some((self.validate_fulu(column, buffer, sync_state, tracker), false))
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

        if sync_state.is_synced() && sync_state.is_future_slot(slot, self.spec.slot_duration_ms()) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = sync_state.wall_slot(),
                "post-wall sidecar"
            );
            return ColumnOutcome::Skip;
        }

        let block_root = util::block_root_from_sidecar(buffer);
        let column_index = DataColumnSidecarFuluView::index(buffer);
        if column_index >= NUMBER_OF_COLUMNS as u64 {
            tracing::warn!(?stream_id, column_index, "sidecar column index out of range");
            return ColumnOutcome::Reject { block_root, slot, bitmask: 0 };
        }
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        }

        if tracker.has_any(&block_root, column_bitmask) {
            return ColumnOutcome::AlreadyHeld { block_root, column_index, slot };
        }

        if !util::verify_data_column_sidecar_fulu(buffer, self.max_blobs_at(slot)) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        }

        // Inclusion proof binds the sidecar's `kzg_commitments` to the
        // block's `body_root` — neither input is pinned by block_root, so
        // it must run on every sidecar.
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        }

        // State-driven validations: pull every input in one seqlock pass.
        // BLS verify runs OUTSIDE the closure (slow; would hold the
        // notional read lock too long otherwise).
        let claimed_proposer_index = DataColumnSidecarFuluView::proposer_index(buffer);
        let checks = self.beacon_state.read(&|v| {
            let state_epoch = v.slot.current_epoch();
            // proposer_lookahead is anchored to `state_epoch` and covers
            // current+next epochs (PROPOSER_LOOKAHEAD_SIZE = 64).
            let lookahead_idx = slot.wrapping_sub(state_epoch * SLOTS_PER_EPOCH) as usize;
            let proposer = match v.epoch.proposer_at(lookahead_idx) {
                Some(expected) if expected == claimed_proposer_index => ProposerCheck::Matches,
                Some(_) => ProposerCheck::Mismatch,
                None => ProposerCheck::Unresolvable,
            };
            let parent_in_head_fork = parent_root == sync_state.head_root() ||
                v.block_roots.contains(parent_root, v.slot.slot_number());
            let is_above_finalized =
                util::is_above_finalized(buffer, v.epoch.state().finalized_checkpoint.epoch);

            let idx = claimed_proposer_index as usize;
            let pubkey =
                (idx < v.validators.count()).then(|| *v.validators.pubkey_decompressed(idx));

            (
                is_above_finalized,
                parent_in_head_fork,
                proposer,
                pubkey,
                v.epoch.fork().current_version, // TODO for backfill
                v.imm.genesis_validators_root,
            )
        });
        // No snapshot yet (pre-bootstrap): nothing can be validated.
        let Some((above_finalized, parent_in_head_fork, proposer, pubkey, fork_version, gvr)) =
            checks
        else {
            tracing::warn!(?stream_id, "sidecar before first beacon state snapshot");
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        };

        if !above_finalized {
            tracing::warn!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return ColumnOutcome::Skip;
        }
        match self.check_parent(parent_root, slot, parent_in_head_fork) {
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
                return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
            }
        }
        let relay_eligible = match proposer {
            ProposerCheck::Matches => true,
            ProposerCheck::Mismatch => {
                tracing::warn!(?stream_id, "sidecar proposer_index mismatch");
                return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
            }
            // Spec answer is IGNORE.
            ProposerCheck::Unresolvable => {
                tracing::debug!(?stream_id, slot, "sidecar proposer unresolvable — not relayed");
                false
            }
        };

        // BLS verify cache: skip the ~1 ms verify iff the sidecar's
        // signature bytes match a previously-validated signature for
        // this block_root. block_root does not pin the signature, so
        // bytes-equality is required.
        let sig_bytes = *DataColumnSidecarFuluView::block_signature(buffer);
        if !tracker.signature_verified(&block_root, &sig_bytes) {
            let Some(pubkey) = pubkey else {
                tracing::warn!(?stream_id, "sidecar proposer_index out of range");
                return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
            };
            if !util::verify_proposer_signature(buffer, &pubkey, fork_version, &gvr) {
                tracing::warn!(?stream_id, "sidecar proposer signature invalid");
                return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
            }
            tracker.set_signature(block_root, sig_bytes);
        }

        ColumnOutcome::Record {
            block_root,
            column_index,
            bitmask: column_bitmask,
            slot,
            relay_eligible,
        }
    }

    #[timed]
    pub fn validate_gloas(
        &self,
        column: &PendingColumn,
        buffer: &[u8],
        sync_state: &SyncStatus,
        tracker: &ColumnTracker,
    ) -> ColumnOutcome {
        let PendingColumn { stream_id, gossip_subnet, .. } = *column;
        let slot = DataColumnSidecarGloasView::slot(buffer);

        if sync_state.is_synced() && sync_state.is_future_slot(slot, self.spec.slot_duration_ms()) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = sync_state.wall_slot(),
                "post-wall sidecar"
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
            return ColumnOutcome::Reject { block_root, slot, bitmask: 0 };
        }
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        }

        if tracker.has_any(&block_root, column_bitmask) {
            return ColumnOutcome::AlreadyHeld { block_root, column_index, slot };
        }

        let Some(commitments) = self.gloas_commitments.get(&block_root) else {
            return ColumnOutcome::Buffer { block_root };
        };

        if !util::verify_data_column_sidecar_gloas(buffer, commitments, self.max_blobs_at(slot)) {
            tracing::warn!(?stream_id, "badly formed gloas data column sidecar");
            return ColumnOutcome::Reject { block_root, slot, bitmask: column_bitmask };
        }

        ColumnOutcome::Record {
            block_root,
            column_index,
            bitmask: column_bitmask,
            slot,
            relay_eligible: true,
        }
    }
}
