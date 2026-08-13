use silver_beacon_state_data::Epoch;

/// Lanes are indexed by epoch parity, so the {wall, wall-1} window maps each
/// epoch to a stable lane and rotation is a re-arm of whichever lane expired.
pub(super) struct SeenValidators {
    epochs: [Epoch; 2],
    bits: [Vec<u64>; 2],
}

impl SeenValidators {
    pub(super) fn new(validator_capacity: usize) -> Self {
        let words = validator_capacity.div_ceil(64);
        // Sentinels above any wall epoch, parities matching their lanes.
        Self { epochs: [u64::MAX - 1, u64::MAX], bits: [vec![0; words], vec![0; words]] }
    }

    pub(super) fn rotate_to(&mut self, wall_epoch: Epoch) {
        for epoch in [wall_epoch.saturating_sub(1), wall_epoch] {
            let lane = (epoch % 2) as usize;
            if self.epochs[lane] != epoch {
                self.epochs[lane] = epoch;
                self.bits[lane].fill(0);
            }
        }
    }

    pub(super) fn contains(&self, target_epoch: Epoch, validator: usize) -> bool {
        let lane = (target_epoch % 2) as usize;
        self.epochs[lane] == target_epoch &&
            self.bits[lane].get(validator / 64).is_some_and(|w| w & (1 << (validator % 64)) != 0)
    }

    pub(super) fn mark(&mut self, target_epoch: Epoch, validator: usize) {
        let lane = (target_epoch % 2) as usize;
        debug_assert!(self.epochs[lane] == target_epoch);
        if self.epochs[lane] != target_epoch {
            return;
        }
        let bits = &mut self.bits[lane];
        if validator / 64 >= bits.len() {
            bits.resize(validator / 64 + 1, 0);
        }
        bits[validator / 64] |= 1 << (validator % 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_lanes_contain_nothing() {
        let seen = SeenValidators::new(128);
        assert!(!seen.contains(0, 0));
        assert!(!seen.contains(1, 127));
    }

    #[test]
    fn mark_then_contains_within_window() {
        let mut seen = SeenValidators::new(128);
        seen.rotate_to(1);
        seen.mark(0, 7);
        seen.mark(1, 7);
        assert!(seen.contains(0, 7));
        assert!(seen.contains(1, 7));
        assert!(!seen.contains(0, 8));
        // Re-marking is a no-op, not a toggle.
        seen.mark(0, 7);
        assert!(seen.contains(0, 7));
    }

    #[test]
    fn rotation_clears_only_the_expired_lane() {
        let mut seen = SeenValidators::new(128);
        seen.rotate_to(0);
        seen.mark(0, 3);

        // Window {0, 1}: epoch 0 survives the first advance.
        seen.rotate_to(1);
        assert!(seen.contains(0, 3));

        // Window {1, 2}: epoch 0's lane is re-armed for epoch 2, so the
        // validator becomes markable again.
        seen.rotate_to(2);
        assert!(!seen.contains(0, 3));
        assert!(!seen.contains(2, 3));
        seen.mark(2, 3);
        assert!(seen.contains(2, 3));
    }

    #[test]
    fn out_of_window_epochs_read_empty() {
        let mut seen = SeenValidators::new(128);
        seen.rotate_to(5);
        seen.mark(5, 9);
        seen.mark(4, 9);
        // Claimed epochs sharing a live lane's parity must not read its bits.
        assert!(!seen.contains(7, 9));
        assert!(!seen.contains(3, 9));
        assert!(!seen.contains(6, 9));
    }

    #[test]
    fn rotation_within_an_epoch_keeps_marks() {
        let mut seen = SeenValidators::new(128);
        seen.rotate_to(4);
        seen.mark(4, 11);
        seen.rotate_to(4);
        assert!(seen.contains(4, 11));
    }

    #[test]
    fn marks_grow_past_construction_capacity() {
        let mut seen = SeenValidators::new(0);
        seen.rotate_to(0);
        assert!(!seen.contains(0, 200));
        seen.mark(0, 200);
        assert!(seen.contains(0, 200));
        assert!(!seen.contains(0, 5000));
    }
}
