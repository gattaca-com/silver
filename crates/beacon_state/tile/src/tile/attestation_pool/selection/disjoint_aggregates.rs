use crate::tile::attestation_pool::committee_bits::bit_positions;

/// Search steps before the best set found so far is returned as is. Honest
/// committees finish in about one step per aggregate; the budget only bounds
/// adversarial overlaps. The first path searched always takes the most
/// valuable aggregate left, so stopping early is never worse than greedy.
const SEARCH_BUDGET: u32 = 1 << 12;
const _: () = assert!(SEARCH_BUDGET >= u32::BITS);

/// One committee's aggregates by position: what each is worth, and which others
/// it overlaps. `overlaps[a]` has bit `b` set iff aggregates `a` and `b`
/// share a committee member, and never bit `a` itself.
pub(super) struct CommitteeAggregates<'a> {
    pub(super) values: &'a [u64],
    pub(super) overlaps: &'a [u32],
}

/// Aggregates, one bit per index, that share no committee member, so their
/// signatures add; and what they are worth together.
#[derive(Clone, Copy)]
pub(super) struct DisjointAggregates {
    pub(super) aggregates: u32,
    pub(super) value: u64,
}

impl DisjointAggregates {
    pub(super) const NONE: Self = Self { aggregates: 0, value: 0 };

    fn and(self, aggregates: u32, value: u64) -> Self {
        Self { aggregates: self.aggregates | aggregates, value: self.value + value }
    }
}

impl CommitteeAggregates<'_> {
    pub(super) fn most_valuable_disjoint(&self) -> DisjointAggregates {
        debug_assert_eq!(self.values.len(), self.overlaps.len());
        debug_assert!(self.values.len() <= u32::BITS as usize);
        let worth_taking = set_of((0..self.values.len()).filter(|&a| self.values[a] > 0));
        let (mut best, mut budget) = (DisjointAggregates::NONE, SEARCH_BUDGET);
        self.extend(DisjointAggregates::NONE, worth_taking, &mut best, &mut budget);
        best
    }

    /// Ties go to the highest index.
    fn most_valuable(&self, aggregates: u32) -> usize {
        bit_positions(aggregates.into()).max_by_key(|&a| self.values[a]).expect("non-empty")
    }

    fn value(&self, aggregates: u32) -> u64 {
        bit_positions(aggregates.into()).map(|a| self.values[a]).sum()
    }

    /// Tries the ways to extend `chosen` with aggregates from `remaining`,
    /// none of which overlaps `chosen`, keeping the most valuable in `best`.
    fn extend(
        &self,
        chosen: DisjointAggregates,
        remaining: u32,
        best: &mut DisjointAggregates,
        budget: &mut u32,
    ) {
        if chosen.value > best.value {
            *best = chosen;
        }
        if remaining == 0 || *budget == 0 {
            return;
        }
        *budget -= 1;
        if chosen.value + self.value(remaining) <= best.value {
            return;
        }

        let isolated =
            set_of(bit_positions(remaining.into()).filter(|&a| self.overlaps[a] & remaining == 0));
        if isolated != 0 {
            let chosen = chosen.and(isolated, self.value(isolated));
            return self.extend(chosen, remaining & !isolated, best, budget);
        }

        let a = self.most_valuable(remaining);
        let without_a = remaining & !(1 << a);
        let with_a = chosen.and(1 << a, self.values[a]);
        self.extend(with_a, without_a & !self.overlaps[a], best, budget);
        self.extend(chosen, without_a, best, budget);
    }
}

/// The set, one bit per index, of `aggregates`.
fn set_of(aggregates: impl Iterator<Item = usize>) -> u32 {
    aggregates.fold(0, |set, a| set | 1 << a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn most_valuable_disjoint(values: &[u64], overlapping: &[(usize, usize)]) -> (u32, u64) {
        let mut overlaps = vec![0u32; values.len()];
        for &(a, b) in overlapping {
            overlaps[a] |= 1 << b;
            overlaps[b] |= 1 << a;
        }
        let chosen = CommitteeAggregates { values, overlaps: &overlaps }.most_valuable_disjoint();
        (chosen.aggregates, chosen.value)
    }

    #[test]
    fn two_small_aggregates_beat_the_large_one_overlapping_both() {
        assert_eq!(most_valuable_disjoint(&[5, 3, 3], &[(0, 1), (0, 2)]), (0b110, 6));
    }

    #[test]
    fn aggregates_overlapping_nothing_are_all_taken() {
        assert_eq!(most_valuable_disjoint(&[1, 2, 3], &[]), (0b111, 6));
    }

    #[test]
    fn worthless_aggregates_are_never_taken() {
        assert_eq!(most_valuable_disjoint(&[0, 4], &[]), (0b10, 4));
    }

    #[test]
    fn matches_brute_force_on_a_ring_of_overlaps() {
        let values = [4, 1, 4, 1, 4, 1, 7];
        let overlapping: Vec<_> = (0..values.len()).map(|a| (a, (a + 1) % values.len())).collect();
        let brute = (0u32..1 << values.len())
            .filter(|set| {
                overlapping.iter().all(|&(a, b)| set & (1 << a) == 0 || set & (1 << b) == 0)
            })
            .map(|set| bit_positions(set.into()).map(|a| values[a]).sum::<u64>())
            .max()
            .unwrap();
        assert_eq!(most_valuable_disjoint(&values, &overlapping).1, brute);
    }
}
