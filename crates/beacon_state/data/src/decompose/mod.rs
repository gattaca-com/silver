use common::F3;
use flux_profiler::timed;

use crate::{BeaconState, SpecConfig, decode_checkpoint_pubkeys};

pub(crate) mod common;
mod fulu;
pub(crate) mod gloas;

pub use common::DecomposeError;
pub(crate) use common::{FULU_FIXED_PART, u64_le};

impl BeaconState {
    pub fn from_checkpoint(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkey_sidecar: &[u8],
    ) -> Result<Self, DecomposeError> {
        if !pubkey_sidecar.is_empty() {
            if let Ok(pubkeys) = decode_checkpoint_pubkeys(pubkey_sidecar) &&
                let Ok(state) = Self::decompose(ssz, cfg, Some(&pubkeys))
            {
                return Ok(state);
            }
            tracing::warn!("checkpoint pubkey sidecar unusable; decompressing from SSZ");
        }
        Self::decompose(ssz, cfg, None)
    }

    #[timed]
    pub fn decompose(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
    ) -> Result<Self, DecomposeError> {
        // `fork.current_version` sits at F3 + 4 (after `previous_version`).
        if ssz.get(F3 + 4..F3 + 8) == Some(cfg.gloas_fork_version.as_slice()) {
            return gloas::decompose(ssz, cfg, pubkeys);
        }
        Self::decompose_fulu(ssz, cfg, pubkeys)
    }

    /// Force the Gloas decoder regardless of the SSZ `fork.current_version`.
    #[doc(hidden)]
    pub fn decompose_gloas(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
    ) -> Result<Self, DecomposeError> {
        gloas::decompose(ssz, cfg, pubkeys)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::common::{F2, FULU_FIXED_PART, u64_le};
    use crate::{BeaconState, SpecConfig, types::SLOTS_PER_EPOCH};

    // EF fixture: a known-valid Fulu pre-state from sanity/blocks tests.
    // Path is relative to `crates/common/`; gracefully skipped when the
    // consensus-spec-tests checkout is missing.
    const EF_PRE_STATE: &str = concat!(
        "../beacon_state/consensus-spec-tests/tests/mainnet/fulu/sanity/blocks/",
        "pyspec_tests/deposit_top_up/pre.ssz_snappy",
    );

    #[test]
    fn decompose_ef_sanity_pre_state() {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), EF_PRE_STATE].iter().collect();
        let Ok(compressed) = std::fs::read(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };
        let ssz = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy decode");
        assert!(ssz.len() >= FULU_FIXED_PART);

        let cfg = SpecConfig::mainnet();
        let bs = BeaconState::decompose(&ssz, &cfg, None).expect("decompose");
        let imm = &bs.immutable;
        let epoch = bs.epoch.finalized();
        let longtail = bs.longtail.finalized();
        let validators = bs.validators.finalized();

        // Re-read the raw slot from the SSZ fixed part to cross-check.
        let raw_slot = u64_le(&ssz, F2);
        let slot_view = bs.slot_states.finalized_view();
        assert_eq!(slot_view.slot_number(), raw_slot);
        let cur_epoch = raw_slot / SLOTS_PER_EPOCH;

        // Validator columnar arrays should be populated and consistent.
        let n = validators.validator_count();
        assert!(n > 0, "no validators decoded");
        assert_eq!(validators.index_len(), n);

        // Spec invariant: finalized ≤ previous_justified ≤ current_justified
        //                          ≤ current_epoch.
        let est = &epoch.state;
        assert!(est.finalized_checkpoint.epoch <= est.previous_justified_checkpoint.epoch);
        assert!(est.previous_justified_checkpoint.epoch <= est.current_justified_checkpoint.epoch);
        assert!(est.current_justified_checkpoint.epoch <= cur_epoch);

        // Sync-committee indices either resolve to a real validator or are
        // sentinel u32::MAX (committee pubkey not in the registry).
        let committees = longtail.sync_committees();
        for (i, idx) in committees.indices().iter().enumerate() {
            if *idx != u32::MAX {
                assert!((*idx as usize) < n);
                let pk = &committees.current().pubkeys[i];
                assert_eq!(validators.find_by_pubkey(pk).map(|i| i as u32), Some(*idx));
            }
        }

        // Decompose is deterministic.
        let bs2 = BeaconState::decompose(&ssz, &cfg, None).expect("decompose 2");
        let imm2 = &bs2.immutable;
        assert_eq!(bs2.slot_states.finalized_view().slot_number(), slot_view.slot_number());
        assert_eq!(bs2.validators.finalized().validator_count(), n);
        assert_eq!(imm2.genesis_validators_root, imm.genesis_validators_root);
        assert_eq!(imm2.historical_roots_hash, imm.historical_roots_hash);
    }
}
