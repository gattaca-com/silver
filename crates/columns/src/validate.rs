use std::time::{Duration, Instant};

use flux_profiler::timed;
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH};
use silver_common::{
    Nanos, P2pStreamId, StreamProtocol, Wheel, column_util as util,
    ssz_view::{DataColumnSidecarFuluView, DataColumnSidecarGloasView, SignedBeaconBlockView},
};

use crate::{BlockRoot, sync::SyncStatus};

pub(crate) enum ColumnOutcome {
    Skip,
    Reject { block_root: BlockRoot, bitmask: u128 },
    Buffer { block_root: BlockRoot },
    AwaitParent { parent_root: BlockRoot },
    Record { block_root: BlockRoot, column_index: u64, bitmask: u128, slot: u64 },
}

/// Per-sidecar validation, i.e. everything except the KZG cell proofs —
/// those are deferred to the end-of-pass batch, so `Record` means "passed
/// every check but KZG". Owns the caches only validation consults.
pub(crate) struct ColumnValidator {
    beacon_state: BeaconStateReader,
    // BLS verify memo: block_root → previously-validated 96-byte
    // proposer signature. On a subsequent sidecar with the same
    // block_root AND matching signature bytes we skip the ~1 ms BLS
    // verify; with a different signature we re-verify. block_root
    // alone is not safe to cache by — it does not cover the
    // signature, kzg_commitments, or inclusion proof, all of which
    // remain verified on every sidecar. Time-bounded: 4 buckets × 1
    // epoch ⇒ entries age out after 3–4 epochs.
    validated_blocks: Wheel<BlockRoot, [u8; 96], 4>,
    // Gloas sidecars carry no commitments, so column KZG verifies against these.
    gloas_commitments: Wheel<BlockRoot, Box<[u8]>, 4>,
    // Roots of persisted blocks — parent-seen checks beyond the head fork.
    persisted_block_roots: Wheel<BlockRoot, (), 16>,
}

impl ColumnValidator {
    pub fn new(beacon_state: BeaconStateReader, epoch_duration: Duration) -> Self {
        Self {
            beacon_state,
            validated_blocks: Wheel::new(epoch_duration),
            gloas_commitments: Wheel::new(epoch_duration),
            persisted_block_roots: Wheel::new(epoch_duration),
        }
    }

    pub fn note_persisted(&mut self, block_root: BlockRoot) {
        self.persisted_block_roots.insert(block_root, ());
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
        self.validated_blocks.maybe_rotate(now, &mut |_, _| true);
        self.gloas_commitments.maybe_rotate(now, &mut |_, _| true);
        self.persisted_block_roots.maybe_rotate(now, &mut |_, _| true);
    }

    #[timed]
    pub fn validate_fulu(
        &mut self,
        stream_id: P2pStreamId,
        buffer: &[u8],
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
        sync_state: &SyncStatus,
        validated_columns: &Wheel<BlockRoot, u128, 4>,
    ) -> ColumnOutcome {
        let parent_root = DataColumnSidecarFuluView::parent_root(buffer);
        let slot = DataColumnSidecarFuluView::slot(buffer);

        if slot < sync_state.head_slot() {
            tracing::info!(slot, "skip old data column");
            return ColumnOutcome::Skip;
        }

        if gossip_subnet.is_some() {
            let elapsed_ms = recv_ts.map(|r| r.elapsed().as_millis_u64());
            tracing::info!(
                slot,
                parent_root = hex::encode(parent_root),
                ?gossip_subnet,
                ?elapsed_ms,
                "data column recv"
            );
        }

        if sync_state.is_synced() && slot > sync_state.wall_slot().saturating_add(1) {
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
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        let do_parent_checks = stream_id.protocol() == StreamProtocol::GossipSub;

        if validated_columns.get(&block_root).map(|c| c & column_bitmask != 0).unwrap_or_default() {
            return ColumnOutcome::Skip;
        }

        if !util::verify_data_column_sidecar_fulu(buffer) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // Inclusion proof binds the sidecar's `kzg_commitments` to the
        // block's `body_root` — neither input is pinned by block_root, so
        // it must run on every sidecar.
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // State-driven validations: pull every input in one seqlock pass.
        // BLS verify runs OUTSIDE the closure (slow; would hold the
        // notional read lock too long otherwise).
        let claimed_proposer_index = DataColumnSidecarFuluView::proposer_index(buffer);
        let checks = self.beacon_state.read(&|v| {
            let state_epoch = v.slot.current_epoch();

            let (proposer_matches, parent_validated, is_above_finalized) = if do_parent_checks {
                // proposer_lookahead is anchored to `state_epoch` and covers
                // current+next epochs (PROPOSER_LOOKAHEAD_SIZE = 64). Slots
                // outside that window we cannot resolve here.
                let lookahead_idx = slot.wrapping_sub(state_epoch * SLOTS_PER_EPOCH) as usize;
                let expected_proposer = v.epoch.proposer_at(lookahead_idx);
                let parent_validated = parent_root == sync_state.head_root() ||
                    v.block_roots.contains(parent_root, v.slot.slot_number());
                let is_above_finalized =
                    util::is_above_finalized(buffer, v.epoch.state().finalized_checkpoint.epoch);
                (
                    expected_proposer == Some(claimed_proposer_index),
                    parent_validated,
                    is_above_finalized,
                )
            } else {
                // Sync / RPC blocks cannot validate proposer shuffling.
                (true, true, true)
            };

            let idx = claimed_proposer_index as usize;
            let pubkey =
                (idx < v.validators.count()).then(|| *v.validators.pubkey_decompressed(idx));

            (
                is_above_finalized,
                parent_validated,
                proposer_matches,
                pubkey,
                v.epoch.fork().current_version, // TODO for backfill
                v.imm.genesis_validators_root,
            )
        });
        // No snapshot yet (pre-bootstrap): nothing can be validated.
        let Some((above_finalized, parent_validated, proposer_matches, pubkey, fork_version, gvr)) =
            checks
        else {
            tracing::warn!(?stream_id, "sidecar before first beacon state snapshot");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        };

        if !above_finalized {
            tracing::warn!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return ColumnOutcome::Skip;
        }
        // The state view sees only the head fork's chain; the store holds
        // every BS-accepted block (all forks, incl. validated children of the
        // head that aren't head yet).
        let parent_validated = parent_validated || self.persisted_block_roots.contains(parent_root);
        if !parent_validated {
            tracing::warn!(
                ?stream_id,
                slot,
                parent_root = hex::encode(parent_root),
                "sidecar parent_root not yet validated — ignoring (not penalized)"
            );
            return ColumnOutcome::AwaitParent { parent_root: *parent_root };
        }
        if !proposer_matches {
            tracing::warn!(?stream_id, "sidecar proposer_index mismatch");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // BLS verify cache: skip the ~1 ms verify iff the sidecar's
        // signature bytes match a previously-validated signature for
        // this block_root. block_root does not pin the signature, so
        // bytes-equality is required.
        let sig_bytes = *DataColumnSidecarFuluView::block_signature(buffer);
        if self.validated_blocks.get(&block_root) != Some(&sig_bytes) {
            let Some(pubkey) = pubkey else {
                tracing::warn!(?stream_id, "sidecar proposer_index out of range");
                return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
            };
            if !util::verify_proposer_signature(buffer, &pubkey, fork_version, &gvr) {
                tracing::warn!(?stream_id, "sidecar proposer signature invalid");
                return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
            }
            self.validated_blocks.insert(block_root, sig_bytes);
        }

        ColumnOutcome::Record { block_root, column_index, bitmask: column_bitmask, slot }
    }

    #[timed]
    pub fn validate_gloas(
        &self,
        stream_id: P2pStreamId,
        buffer: &[u8],
        gossip_subnet: Option<u64>,
        sync_state: &SyncStatus,
        validated_columns: &Wheel<BlockRoot, u128, 4>,
    ) -> ColumnOutcome {
        let slot = DataColumnSidecarGloasView::slot(buffer);

        if sync_state.is_synced() && slot > sync_state.wall_slot().saturating_add(1) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = sync_state.wall_slot(),
                "post-wall sidecar"
            );
            return ColumnOutcome::Skip;
        }
        if slot <= sync_state.finalized_slot() {
            return ColumnOutcome::Skip;
        }

        let block_root = *DataColumnSidecarGloasView::beacon_block_root(buffer);
        let column_index = DataColumnSidecarGloasView::index(buffer);
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        if validated_columns.get(&block_root).map(|c| c & column_bitmask != 0).unwrap_or_default() {
            return ColumnOutcome::Skip;
        }

        let Some(commitments) = self.gloas_commitments.get(&block_root) else {
            return ColumnOutcome::Buffer { block_root };
        };

        if !util::verify_data_column_sidecar_gloas(buffer, commitments) {
            tracing::warn!(?stream_id, "badly formed gloas data column sidecar");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        ColumnOutcome::Record { block_root, column_index, bitmask: column_bitmask, slot }
    }
}
