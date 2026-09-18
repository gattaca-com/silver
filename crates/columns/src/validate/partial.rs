use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use silver_common::{
    ForkName, GossipDomain, SLOTS_PER_EPOCH,
    cell_store::{CommitmentContext, ContextData},
    column_util,
    merkle::{merkleize, uint64_chunk},
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, BeaconBlockHeaderView,
        partial_column::PartialDataColumnHeaderView,
    },
};

use super::ColumnValidator;
use crate::{BlockRoot, sync::SyncStatus};

pub(super) struct PartialParents {
    entries: FxHashMap<BlockRoot, ParentInfo>,
    next_prune: Instant,
    retention: Duration,
}

struct ParentInfo {
    state_root: Option<BlockRoot>,
    expires: Instant,
}

impl PartialParents {
    pub(super) fn new(retention: Duration) -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(256, Default::default()),
            next_prune: Instant::now(),
            retention,
        }
    }

    pub(super) fn remember(&mut self, root: BlockRoot, state_root: Option<BlockRoot>) {
        if state_root.is_some() &&
            self.entries.get(&root).is_some_and(|info| info.state_root.is_none())
        {
            return;
        }
        if self.entries.len() < 256 || self.entries.contains_key(&root) {
            self.entries
                .insert(root, ParentInfo { state_root, expires: Instant::now() + self.retention });
        }
    }

    pub(super) fn prune(&mut self, now: Instant) {
        if now >= self.next_prune {
            self.entries.retain(|_, info| now < info.expires);
            self.next_prune = now + Duration::from_secs(1);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderOutcome {
    Valid(CommitmentContext),
    Ignore,
    Reject,
    AwaitParent { root: BlockRoot, slot: u64 },
}

impl ColumnValidator {
    pub(crate) fn validate_partial_header(
        &self,
        root: BlockRoot,
        domain: GossipDomain,
        bytes: &[u8],
        sync: &SyncStatus,
    ) -> HeaderOutcome {
        if domain.format() != ForkName::Fulu || !PartialDataColumnHeaderView::check_size(bytes) {
            return HeaderOutcome::Reject;
        }
        let Some(ContextData::Fulu { signed_header, inclusion_proof, commitments }) =
            ContextData::from_encoded(bytes, ForkName::Fulu)
        else {
            return HeaderOutcome::Reject;
        };
        let (Ok(header), Ok(signature)) =
            (signed_header[..112].try_into(), signed_header[112..].try_into())
        else {
            return HeaderOutcome::Reject;
        };
        let slot = BeaconBlockHeaderView::slot(header);
        let index = BeaconBlockHeaderView::proposer_index(header);
        let parent = BeaconBlockHeaderView::parent_root(header);
        let body = BeaconBlockHeaderView::body_root(header);
        let computed_root = merkleize(&[
            uint64_chunk(slot),
            uint64_chunk(index),
            *parent,
            *BeaconBlockHeaderView::state_root(header),
            *body,
        ]);
        if root != computed_root ||
            commitments.is_empty() ||
            commitments.len() / BYTES_PER_KZG_COMMITMENT > self.max_blobs_at(slot)
        {
            return HeaderOutcome::Reject;
        }
        if slot <= sync.data_availability_floor() || self.is_future(slot, sync) {
            return HeaderOutcome::Ignore;
        }
        if self.partial_parents.entries.get(parent).is_some_and(|info| info.state_root.is_none()) {
            return HeaderOutcome::Reject;
        }
        let checks = self.beacon_state.read(|view| {
            let finalized = view.epoch.state().finalized_checkpoint;
            let state_slot = view.slot.slot_number();
            let latest = view.slot.state().latest_block_header;
            // A post-block snapshot leaves state_root zero until the next slot.
            // Only a positively validated block may supply the missing root.
            let state_root = if latest.state_root != [0; 32] {
                Some(latest.state_root)
            } else {
                self.partial_parents
                    .entries
                    .get(parent)
                    .filter(|_| self.validated_block_roots.contains(parent))
                    .and_then(|info| info.state_root)
            };
            let is_head = state_root.is_some_and(|state_root| {
                *parent ==
                    merkleize(&[
                        uint64_chunk(latest.slot),
                        uint64_chunk(latest.proposer_index),
                        latest.parent_root,
                        state_root,
                        latest.body_root,
                    ])
            });
            let parent_slot = if is_head {
                Some(latest.slot)
            } else {
                view.block_roots.slot_of(parent, state_slot.saturating_sub(1))
            };
            let expected = parent_slot
                .filter(|&parent_slot| slot / SLOTS_PER_EPOCH <= parent_slot / SLOTS_PER_EPOCH + 1)
                .and_then(|_| {
                    slot.checked_sub(view.slot.current_epoch() * SLOTS_PER_EPOCH)
                        .and_then(|offset| view.epoch.proposer_at(offset as usize))
                });
            let pubkey = usize::try_from(index)
                .ok()
                .filter(|&index| index < view.validators.count())
                .map(|index| *view.validators.pubkey_decompressed(index));
            let domain = GossipDomain::new(
                self.spec.fork_digest_at(slot / SLOTS_PER_EPOCH, &view.imm.genesis_validators_root),
                self.spec.fork_at_slot(slot),
            );
            (finalized, parent_slot, expected, pubkey, view.imm.genesis_validators_root, domain)
        });
        let Some((finalized, parent_slot, expected, pubkey, gvr, expected_domain)) = checks else {
            return HeaderOutcome::Ignore
        };
        if slot <= finalized.epoch * SLOTS_PER_EPOCH {
            return HeaderOutcome::Ignore;
        }
        if domain != expected_domain {
            return HeaderOutcome::Reject;
        }
        // The published snapshot vouches for its own ancestry and proposer lookahead,
        // not another fork's. Wait rather than rejecting an unresolved parent fork.
        let Some(parent_slot) = parent_slot else {
            if self.validated_block_roots.contains(parent) {
                return HeaderOutcome::Ignore;
            }
            return HeaderOutcome::AwaitParent { root: *parent, slot: slot.saturating_sub(1) };
        };
        if parent_slot >= slot ||
            parent_slot < finalized.epoch * SLOTS_PER_EPOCH && parent != &finalized.root
        {
            return HeaderOutcome::Reject;
        }
        let Some(pubkey) = pubkey else { return HeaderOutcome::Reject };
        let Some(expected) = expected else { return HeaderOutcome::Ignore };
        if !column_util::verify_header_signature(
            &root,
            signature,
            &pubkey,
            self.spec.fork_version_at(slot / SLOTS_PER_EPOCH),
            &gvr,
        ) || !column_util::verify_commitments_inclusion_proof(commitments, inclusion_proof, body)
        {
            return HeaderOutcome::Reject;
        }
        if expected != index {
            return HeaderOutcome::Reject;
        }
        HeaderOutcome::Valid(CommitmentContext {
            block_root: root,
            slot,
            format: ForkName::Fulu,
            blob_count: commitments.len() / BYTES_PER_KZG_COMMITMENT,
        })
    }
}
