use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};

pub(super) struct ProposerPreferences {
    pub fee_recipient: [u8; 20],
    pub target_gas_limit: u64,
}

/// First valid preferences per `(proposal_slot, dependent_root)`.
#[derive(Default)]
pub(super) struct SeenProposerPreferences(FxHashMap<(Slot, B256), ProposerPreferences>);

impl SeenProposerPreferences {
    pub fn contains(&self, proposal_slot: Slot, dependent_root: &B256) -> bool {
        self.0.contains_key(&(proposal_slot, *dependent_root))
    }

    pub fn get(&self, proposal_slot: Slot, dependent_root: &B256) -> Option<&ProposerPreferences> {
        self.0.get(&(proposal_slot, *dependent_root))
    }

    pub fn insert(
        &mut self,
        proposal_slot: Slot,
        dependent_root: B256,
        prefs: ProposerPreferences,
    ) {
        self.0.insert((proposal_slot, dependent_root), prefs);
    }

    /// Bids for `slot` still read its preferences.
    pub fn on_slot(&mut self, slot: Slot) {
        self.0.retain(|&(proposal_slot, _), _| proposal_slot >= slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs() -> ProposerPreferences {
        ProposerPreferences { fee_recipient: [1; 20], target_gas_limit: 30_000_000 }
    }

    #[test]
    fn keyed_by_slot_and_dependent_root() {
        let mut seen = SeenProposerPreferences::default();
        seen.insert(10, [1; 32], prefs());
        assert!(seen.contains(10, &[1; 32]));
        assert_eq!(seen.get(10, &[1; 32]).map(|p| p.fee_recipient), Some([1; 20]));
        assert!(!seen.contains(10, &[2; 32]), "another dependent root");
        assert!(!seen.contains(11, &[1; 32]), "another slot");
    }

    #[test]
    fn a_new_slot_keeps_its_own_preferences() {
        let mut seen = SeenProposerPreferences::default();
        seen.insert(9, [1; 32], prefs());
        seen.insert(10, [1; 32], prefs());
        seen.on_slot(10);
        assert!(!seen.contains(9, &[1; 32]));
        assert!(seen.contains(10, &[1; 32]));
    }
}
