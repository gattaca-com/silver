use std::collections::hash_map::Entry;

use flux::spine::SpineProducer;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::StateReadView;
use silver_common::{
    BeaconStateEvent, PoolChange,
    ssz_view::{
        MAX_BLS_TO_EXECUTION_CHANGES, SIGNED_BLS_CHANGE_SIZE, SignedBlsToExecutionChangeView,
    },
};

use crate::{tile::Producers, validate};

/// Gossip-verified BLS to execution changes, one per validator: the first
/// valid change wins, as on gossip, and a block holds at most one change per
/// validator.
///
/// The signature is checked once, at admission: its domain is fork-agnostic
/// and its signer is the message's own `from_bls_pubkey`. Only the credentials
/// it must match can differ between forks, so `select` re-checks those.
#[derive(Default)]
pub(super) struct BlsChangePool {
    changes: FxHashMap<u32, [u8; SIGNED_BLS_CHANGE_SIZE]>,
    producer: Option<SpineProducer<BeaconStateEvent>>,
}

impl BlsChangePool {
    pub(super) fn with_producer(&mut self, producers: &Producers) {
        self.producer.replace(producers.beacon_events);
    }

    pub(super) fn insert(&mut self, ssz: &[u8; SIGNED_BLS_CHANGE_SIZE]) {
        let vi = SignedBlsToExecutionChangeView::validator_index(ssz) as u32;
        if let Entry::Vacant(slot) = self.changes.entry(vi) {
            slot.insert(*ssz);
            if let Some(producer) = &mut self.producer {
                producer.produce(
                    &BeaconStateEvent::PoolChange(PoolChange::BlsChangeAdded(*ssz)).into(),
                );
            }
        }
    }

    /// Appends to `out`, in validator order, up to
    /// `MAX_BLS_TO_EXECUTION_CHANGES` changes that
    /// `process_bls_to_execution_change` accepts on `pre_state`.
    /// Checks lazily in index order, so a large pool costs one pubkey hash
    /// per candidate up to the limit, not one per entry.
    pub(super) fn select(&self, pre_state: &StateReadView, out: &mut Vec<u8>) {
        let mut indices: Vec<_> = self.changes.keys().copied().collect();
        indices.sort_unstable();
        let includable = indices
            .iter()
            .map(|vi| (*vi, &self.changes[vi]))
            .filter(|&(vi, ssz)| applies(pre_state, vi, ssz))
            .take(MAX_BLS_TO_EXECUTION_CHANGES);
        for (_, ssz) in includable {
            out.extend_from_slice(ssz);
        }
    }

    /// Drops changes `finalized` rules out for good: the credentials already
    /// changed, or the finalized validator at the index is not the signer's.
    /// Changes for validators past the finalized registry stay.
    pub(super) fn prune(&mut self, finalized: &StateReadView) {
        let count = finalized.validators.count();
        self.changes.retain(|&vi, ssz| {
            let keep = vi as usize >= count || applies(finalized, vi, ssz);
            if !keep && let Some(producer) = &mut self.producer {
                producer.produce(
                    &BeaconStateEvent::PoolChange(PoolChange::BlsChangeRemoved {
                        validator_index: vi,
                    })
                    .into(),
                );
            }
            keep
        });
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.changes.len()
    }
}

fn applies(state: &StateReadView, vi: u32, ssz: &[u8; SIGNED_BLS_CHANGE_SIZE]) -> bool {
    let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(ssz);
    validate::validate_bls_to_execution_change(&state.validators, vi, from_pubkey).is_ok()
}
