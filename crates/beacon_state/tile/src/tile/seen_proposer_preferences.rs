use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ProposerPreferences {
    pub fee_recipient: [u8; 20],
    pub target_gas_limit: u64,
}

struct SeenPreferences {
    preferences: ProposerPreferences,
    local: bool,
}

/// First valid preferences per `(proposal_slot, dependent_root)`.
#[derive(Default)]
pub(super) struct SeenProposerPreferences(FxHashMap<(Slot, B256), SeenPreferences>);

impl SeenProposerPreferences {
    pub fn contains(&self, proposal_slot: Slot, dependent_root: &B256) -> bool {
        self.0.contains_key(&(proposal_slot, *dependent_root))
    }

    pub fn get(&self, proposal_slot: Slot, dependent_root: &B256) -> Option<&ProposerPreferences> {
        self.0.get(&(proposal_slot, *dependent_root)).map(|seen| &seen.preferences)
    }

    pub fn is_local(&self, proposal_slot: Slot, dependent_root: &B256) -> bool {
        self.0.get(&(proposal_slot, *dependent_root)).is_some_and(|seen| seen.local)
    }

    pub fn insert(
        &mut self,
        proposal_slot: Slot,
        dependent_root: B256,
        prefs: ProposerPreferences,
        local: bool,
    ) {
        self.0
            .entry((proposal_slot, dependent_root))
            .and_modify(|seen| seen.local |= local && seen.preferences == prefs)
            .or_insert(SeenPreferences { preferences: prefs, local });
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
        seen.insert(10, [1; 32], prefs(), false);
        assert!(seen.contains(10, &[1; 32]));
        assert_eq!(seen.get(10, &[1; 32]).map(|p| p.fee_recipient), Some([1; 20]));
        assert!(!seen.contains(10, &[2; 32]), "another dependent root");
        assert!(!seen.contains(11, &[1; 32]), "another slot");
    }

    #[test]
    fn a_new_slot_keeps_its_own_preferences() {
        let mut seen = SeenProposerPreferences::default();
        seen.insert(9, [1; 32], prefs(), false);
        seen.insert(10, [1; 32], prefs(), true);
        seen.on_slot(10);
        assert!(!seen.contains(9, &[1; 32]));
        assert!(seen.contains(10, &[1; 32]));
        assert!(seen.is_local(10, &[1; 32]));
    }

    #[test]
    fn local_submission_must_match_the_first_preferences() {
        let mut seen = SeenProposerPreferences::default();
        seen.insert(10, [1; 32], prefs(), false);
        assert!(!seen.is_local(10, &[1; 32]));
        let other = ProposerPreferences { fee_recipient: [2; 20], ..prefs() };
        seen.insert(10, [1; 32], other, true);
        assert!(!seen.is_local(10, &[1; 32]));
        assert_eq!(seen.get(10, &[1; 32]).unwrap().fee_recipient, [1; 20]);
        seen.insert(10, [1; 32], prefs(), true);
        assert!(seen.is_local(10, &[1; 32]));
    }
}
