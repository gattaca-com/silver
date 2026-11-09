use super::DecomposeError;
use crate::BeaconState;

impl BeaconState {
    /// The STF indexes the registries with these unchecked. A canonical state
    /// keeps them in range and the STF preserves that, so one check at load
    /// covers every fork built on it.
    pub(super) fn check_indices(&self) -> Result<(), DecomposeError> {
        let validators = self.validators.finalized().validator_count();
        let builders = self.builders.finalized().len();
        let slot = self.slot_states.finalized().state();
        let epoch = self.epoch.finalized();

        // An empty registry leaves its cursor at 0.
        if validators > 0 {
            in_range(
                "next_withdrawal_validator_index",
                slot.next_withdrawal_validator_index,
                validators,
            )?;
        }
        if builders > 0 {
            in_range(
                "next_withdrawal_builder_index",
                slot.next_withdrawal_builder_index,
                builders,
            )?;
        }
        for &index in &epoch.state().proposer_lookahead {
            in_range("proposer_lookahead", index, validators)?;
        }

        self.pending.partial_withdrawals.with_finalized_locked(|q| {
            q.entries().iter().try_for_each(|w| {
                in_range("pending_partial_withdrawals.index", w.index, validators)
            })
        })?;
        self.pending.consolidations.with_finalized_locked(|q| {
            q.entries().iter().try_for_each(|c| {
                in_range("pending_consolidations.source_index", c.source_index, validators)?;
                in_range("pending_consolidations.target_index", c.target_index, validators)
            })
        })?;
        self.pending.builder_withdrawals.with_finalized_locked(|q| {
            q.entries().iter().try_for_each(|w| {
                in_range("builder_pending_withdrawals.builder_index", w.builder_index, builders)
            })
        })?;

        // Zero-amount payments and bids are empty slots or self-builds
        // (`BUILDER_INDEX_SELF_BUILD`); their builder index is never read.
        for p in slot.builder_pending_payments.iter().filter(|p| p.withdrawal.amount > 0) {
            in_range(
                "builder_pending_payments.builder_index",
                p.withdrawal.builder_index,
                builders,
            )?;
        }
        let bid = &slot.latest_execution_payload_bid;
        if bid.value > 0 {
            in_range("latest_execution_payload_bid.builder_index", bid.builder_index, builders)?;
        }

        if self.is_finalized_post_gloas() {
            for &index in epoch.ptc_window.committees().as_flattened() {
                in_range("ptc_window", index, validators)?;
            }
        }
        Ok(())
    }
}

fn in_range(field: &'static str, index: u64, count: usize) -> Result<(), DecomposeError> {
    if index < count as u64 {
        return Ok(());
    }
    Err(DecomposeError::IndexOutOfRange { field, index, count })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        BeaconState, SpecConfig,
        decompose::{
            DecomposeError,
            gloas::{G_NEXT_WITHDRAWAL_VALIDATOR_INDEX, G_PROPOSER_LOOKAHEAD, G_PTC_WINDOW},
        },
    };

    const GLOAS_PRE_STATE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tile/consensus-spec-tests/tests/mainnet/gloas/sanity/blocks/pyspec_tests/",
        "empty_block_transition/pre.ssz_snappy",
    );

    fn patched(ssz: &[u8], at: usize, value: u64) -> Result<BeaconState, DecomposeError> {
        let mut ssz = ssz.to_vec();
        ssz[at..at + 8].copy_from_slice(&value.to_le_bytes());
        BeaconState::from_checkpoint(&ssz, &SpecConfig::mainnet(), &[])
    }

    #[test]
    fn out_of_range_indices_rejected() {
        let path = PathBuf::from(GLOAS_PRE_STATE);
        let Ok(compressed) = std::fs::read(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };
        let ssz = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy decode");
        let state = BeaconState::from_checkpoint(&ssz, &SpecConfig::mainnet(), &[])
            .expect("canonical state passes");
        assert!(state.is_finalized_post_gloas());

        for (at, field) in [
            (G_NEXT_WITHDRAWAL_VALIDATOR_INDEX, "next_withdrawal_validator_index"),
            (G_PROPOSER_LOOKAHEAD + 3 * 8, "proposer_lookahead"),
            (G_PTC_WINDOW + 100 * 8, "ptc_window"),
        ] {
            match patched(&ssz, at, u64::MAX) {
                Err(DecomposeError::IndexOutOfRange { field: f, index: u64::MAX, .. }) => {
                    assert_eq!(f, field);
                }
                Err(e) => panic!("{field}: unexpected error {e}"),
                Ok(_) => panic!("{field}: out-of-range index accepted"),
            }
        }
    }
}
