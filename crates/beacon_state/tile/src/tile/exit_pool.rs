use std::collections::hash_map::Entry;

use flux::spine::SpineProducer;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{SpecConfig, StateReadView};
use silver_common::{
    BeaconStateEvent, PoolChange,
    ssz_view::{MAX_VOLUNTARY_EXITS, SIGNED_VOLUNTARY_EXIT_SIZE, SignedVoluntaryExitView},
};

use crate::{stf, tile::Producers, validate};

/// Gossip-verified voluntary exits, one per validator: the first valid exit
/// wins, as on gossip, and a block holds at most one exit per validator.
///
/// The signature is checked once, at admission. Its domain is pinned to
/// Capella (EIP-7044) and the signer's index is finalized in practice (active
/// for `SHARD_COMMITTEE_PERIOD`), so it holds on every fork built on.
#[derive(Default)]
pub(super) struct ExitPool {
    exits: FxHashMap<u32, [u8; SIGNED_VOLUNTARY_EXIT_SIZE]>,
    producer: Option<SpineProducer<BeaconStateEvent>>,
}

impl ExitPool {
    pub(super) fn with_producer(&mut self, producers: &Producers) {
        self.producer.replace(producers.beacon_events);
    }

    pub(super) fn insert(&mut self, ssz: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE]) {
        let vi = SignedVoluntaryExitView::validator_index(ssz) as u32;
        if let Entry::Vacant(slot) = self.exits.entry(vi) {
            slot.insert(*ssz);
            if let Some(producer) = &mut self.producer {
                producer.produce(&BeaconStateEvent::PoolChange(PoolChange::ExitAdded(*ssz)).into());
            }
        }
    }

    /// Appends to `out`, in validator order, up to `MAX_VOLUNTARY_EXITS` exits
    /// that `process_voluntary_exit` accepts on `pre_state`, the proposal's
    /// parent advanced into its epoch. Excludes `slashed`, the validators
    /// slashed earlier in the same block: slashing initiates their exit, which
    /// would fail the block.
    pub(super) fn select(
        &self,
        spec: &SpecConfig,
        pre_state: &StateReadView,
        slashed: &[usize],
        out: &mut Vec<u8>,
    ) {
        let current_epoch = pre_state.slot.current_epoch();
        let mut indices: Vec<_> = self.exits.keys().copied().collect();
        indices.sort_unstable();
        let includable = indices
            .iter()
            .map(|vi| (*vi, &self.exits[vi]))
            .filter(|&(vi, ssz)| {
                !slashed.contains(&(vi as usize)) &&
                    validate::validate_voluntary_exit(
                        spec,
                        &pre_state.validators,
                        vi,
                        SignedVoluntaryExitView::epoch(ssz),
                        current_epoch,
                    )
                    .is_ok() &&
                    // Electra: the exit waits until the validator's partial
                    // withdrawals drain.
                    stf::get_pending_balance_to_withdraw(&pre_state.pending, vi) == 0
            })
            .take(MAX_VOLUNTARY_EXITS);
        for (_, ssz) in includable {
            out.extend_from_slice(ssz);
        }
    }

    /// Drops exits that can never be included again: the validator's exit is
    /// initiated in `finalized`, by this exit, an earlier one or a slashing.
    /// Exits not yet includable stay.
    pub(super) fn prune(&mut self, finalized: &StateReadView) {
        let validators = &finalized.validators;
        self.exits.retain(|&vi, _| {
            let keep =
                vi as usize >= validators.count() || validators.exit_epoch(vi as usize) == u64::MAX;
            if !keep && let Some(producer) = &mut self.producer {
                producer.produce(
                    &BeaconStateEvent::PoolChange(PoolChange::ExitRemoved { validator_index: vi })
                        .into(),
                );
            }
            keep
        });
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.exits.len()
    }
}
