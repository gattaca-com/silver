use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{metrics::timed, ssz_view::MAX_COMMITTEES_PER_SLOT};

use crate::counters::BeaconStateCounters;

/// Same derivation as the pool cap: two retained slots at
/// ≤ MAX_COMMITTEES_PER_SLOT committees each, ×4 headroom for competing
/// data_root variants.
const MAX_ENTRIES: usize = 4 * 2 * MAX_COMMITTEES_PER_SLOT;

/// Honest traffic per key is ≤ TARGET_AGGREGATORS_PER_COMMITTEE (16) heavily
/// overlapping patterns whose maximal antichain stays at 1-3. When full, new
/// patterns stop being stored; probes keep working and the union still
/// accumulates.
const MAX_PATTERNS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CoverageKey {
    slot: Slot,
    committee_index: u64,
    data_root: B256,
}

/// Patterns are raw SSZ bitlist bytes, terminator included: recorded
/// aggregates for one key all validated against the same committee, so their
/// terminators align and byte-wise `incoming & !stored == 0` subset tests are
/// exact. A probe whose byte length differs is simply never covered.
struct CommitteeCoverage {
    /// OR of every recorded pattern.
    union: Vec<u8>,
    /// Maximal antichain of recorded patterns (no member ⊆ another).
    antichain: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Coverage {
    /// ⊆ one recorded pattern — the spec's non-strict-superset IGNORE.
    BySuperset,
    /// ⊆ the union of recorded patterns but no single one: every vote it
    /// carries is already folded, yet it is not the spec-ignorable case.
    ByUnion,
    New,
}

/// Bit-coverage ledger of valid aggregates per (slot, committee, data_root).
///
/// Retention is the pool's two-slot window, not the full 33-slot propagation
/// range: a redundant aggregate older than the window can only reach the
/// verify stage from an aggregator index unseen this target epoch — the
/// first-seen (epoch, aggregator) rule spans the whole epoch — so deeper
/// retention would grow the map ~16× without shedding more verifies.
///
/// The spec also counts aggregates seen within verified blocks toward its
/// superset rule; block processing does not record here — missing that only
/// costs an occasional redundant verify.
pub(super) struct SeenAggregates {
    entries: FxHashMap<CoverageKey, CommitteeCoverage>,
    floor: Slot,
}

impl SeenAggregates {
    pub(super) fn new() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
        }
    }

    pub(super) fn coverage(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
        bits: &[u8],
    ) -> Coverage {
        let Some(entry) = self.entries.get(&CoverageKey { slot, committee_index, data_root })
        else {
            return Coverage::New;
        };
        // Not ⊆ union ⇒ not ⊆ any single pattern, so the one union pass
        // short-circuits the common new-coverage case before the antichain
        // scan.
        if bits.len() != entry.union.len() || !is_subset(bits, &entry.union) {
            return Coverage::New;
        }
        if entry.antichain.iter().any(|stored| is_subset(bits, stored)) {
            return Coverage::BySuperset;
        }
        Coverage::ByUnion
    }

    /// Record a fully verified aggregate's bits.
    pub(super) fn record(
        &mut self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
        bits: &[u8],
    ) {
        if slot < self.floor {
            return;
        }
        let key = CoverageKey { slot, committee_index, data_root };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.add(bits);
            return;
        }
        if self.entries.len() >= MAX_ENTRIES {
            BeaconStateCounters::SeenAggregatesFull.inc();
            tracing::debug!(slot, committee = committee_index, "seen-aggregates full");
            return;
        }
        if self.entries.keys().any(|k| k.slot == slot && k.committee_index == committee_index) {
            // Late-block / split-view signal: one committee attesting two
            // different AttestationData in the same slot.
            tracing::debug!(slot, committee = committee_index, "second data_root for committee");
        }
        self.entries.insert(key, CommitteeCoverage::new(bits));
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|key, _| key.slot >= floor);
    }
}

impl CommitteeCoverage {
    fn new(bits: &[u8]) -> Self {
        Self { union: bits.to_vec(), antichain: vec![bits.to_vec()] }
    }

    fn add(&mut self, bits: &[u8]) {
        debug_assert_eq!(bits.len(), self.union.len());
        if bits.len() != self.union.len() ||
            self.antichain.iter().any(|stored| is_subset(bits, stored))
        {
            return;
        }
        self.antichain.retain(|stored| !is_subset(stored, bits));
        if self.antichain.len() < MAX_PATTERNS {
            self.antichain.push(bits.to_vec());
        }
        for (u, b) in self.union.iter_mut().zip(bits) {
            *u |= b;
        }
    }
}

fn is_subset(inner: &[u8], outer: &[u8]) -> bool {
    debug_assert_eq!(inner.len(), outer.len());
    inner.iter().zip(outer).all(|(i, o)| i & !o == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: Slot = 3;
    const ROOT: B256 = [0xAB; 32];

    /// One-byte pattern for a 4-member committee: participant bits 0-3,
    /// terminator at bit 4.
    fn bits4(participants: u8) -> Vec<u8> {
        debug_assert!(participants < 0b1_0000);
        vec![0b0001_0000 | participants]
    }

    fn probe(seen: &SeenAggregates, bits: &[u8]) -> Coverage {
        seen.coverage(SLOT, 0, ROOT, bits)
    }

    #[test]
    fn unknown_key_probes_new() {
        let mut seen = SeenAggregates::new();
        assert_eq!(probe(&seen, &bits4(0b0110)), Coverage::New);
        seen.record(SLOT, 0, ROOT, &bits4(0b0110));
        assert_eq!(seen.coverage(SLOT, 1, ROOT, &bits4(0b0110)), Coverage::New);
        assert_eq!(seen.coverage(SLOT + 1, 0, ROOT, &bits4(0b0110)), Coverage::New);
        assert_eq!(seen.coverage(SLOT, 0, [0xCD; 32], &bits4(0b0110)), Coverage::New);
    }

    #[test]
    fn equal_and_subset_bits_are_superset_covered() {
        let mut seen = SeenAggregates::new();
        seen.record(SLOT, 0, ROOT, &bits4(0b0110));
        assert_eq!(probe(&seen, &bits4(0b0110)), Coverage::BySuperset);
        assert_eq!(probe(&seen, &bits4(0b0100)), Coverage::BySuperset);
        assert_eq!(probe(&seen, &bits4(0b0010)), Coverage::BySuperset);
    }

    #[test]
    fn strict_superset_is_new_until_recorded() {
        let mut seen = SeenAggregates::new();
        seen.record(SLOT, 0, ROOT, &bits4(0b0010));
        assert_eq!(probe(&seen, &bits4(0b0110)), Coverage::New);
        seen.record(SLOT, 0, ROOT, &bits4(0b0110));
        assert_eq!(probe(&seen, &bits4(0b0110)), Coverage::BySuperset);
        assert_eq!(probe(&seen, &bits4(0b0100)), Coverage::BySuperset);
    }

    #[test]
    fn union_covered_without_single_superset() {
        let mut seen = SeenAggregates::new();
        seen.record(SLOT, 0, ROOT, &bits4(0b0011));
        seen.record(SLOT, 0, ROOT, &bits4(0b1100));
        assert_eq!(probe(&seen, &bits4(0b0101)), Coverage::ByUnion);
        assert_eq!(probe(&seen, &bits4(0b1111)), Coverage::ByUnion);
        assert_eq!(probe(&seen, &bits4(0b0011)), Coverage::BySuperset);
    }

    /// Two-byte patterns for an 8-member committee (terminator = byte 1
    /// bit 0): subset tests must hold across the byte boundary.
    #[test]
    fn byte_boundary_patterns() {
        let mut seen = SeenAggregates::new();
        seen.record(SLOT, 0, ROOT, &[0b1000_0001, 0b01]);
        assert_eq!(probe(&seen, &[0b1000_0000, 0b01]), Coverage::BySuperset);
        assert_eq!(probe(&seen, &[0b0000_0001, 0b01]), Coverage::BySuperset);
        assert_eq!(probe(&seen, &[0b1000_0010, 0b01]), Coverage::New);
        // A different byte length is never covered.
        assert_eq!(probe(&seen, &bits4(0b0001)), Coverage::New);
    }

    /// Recording a pattern that covers stored ones must evict them, or the
    /// antichain silts up: fill the cap with 8 disjoint singletons, then
    /// record their union — it only fits (and probes BySuperset) if all 8
    /// were evicted.
    #[test]
    fn superset_record_evicts_covered_patterns() {
        // 9-member committee: participants 0-7 in byte 0, bit 8 in byte 1,
        // terminator at byte 1 bit 1.
        let bits9 = |b0: u8, b1: u8| vec![b0, b1 | 0b10];
        let mut seen = SeenAggregates::new();
        for i in 0..8 {
            seen.record(SLOT, 0, ROOT, &bits9(1 << i, 0));
        }
        seen.record(SLOT, 0, ROOT, &bits9(0xFF, 0));
        assert_eq!(seen.coverage(SLOT, 0, ROOT, &bits9(0xFF, 0)), Coverage::BySuperset);
        assert_eq!(seen.coverage(SLOT, 0, ROOT, &bits9(0b1010, 0)), Coverage::BySuperset);
    }

    /// At the pattern cap, new coverage stops being stored as a pattern
    /// (never BySuperset) but still accumulates in the union.
    #[test]
    fn pattern_cap_stops_storing_but_union_grows() {
        let bits9 = |b0: u8, b1: u8| vec![b0, b1 | 0b10];
        let mut seen = SeenAggregates::new();
        for i in 0..8 {
            seen.record(SLOT, 0, ROOT, &bits9(1 << i, 0));
        }
        seen.record(SLOT, 0, ROOT, &bits9(0, 1));
        // ByUnion pins both halves: not BySuperset (the pattern was not
        // stored) and not New (the union still absorbed it).
        assert_eq!(seen.coverage(SLOT, 0, ROOT, &bits9(0, 1)), Coverage::ByUnion);
        assert_eq!(seen.coverage(SLOT, 0, ROOT, &bits9(1, 0)), Coverage::BySuperset);
    }

    #[test]
    fn entry_cap_stops_new_keys() {
        let mut seen = SeenAggregates::new();
        for i in 0..MAX_ENTRIES {
            let mut root = [0u8; 32];
            root[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            seen.record(SLOT, 0, root, &bits4(0b0001));
        }
        seen.record(SLOT, 0, ROOT, &bits4(0b0001));
        assert_eq!(probe(&seen, &bits4(0b0001)), Coverage::New);
        // Existing keys are intact.
        assert_eq!(seen.coverage(SLOT, 0, [0u8; 32], &bits4(0b0001)), Coverage::BySuperset);
    }

    #[test]
    fn prune_drops_expired_slots_and_floors_recording() {
        let mut seen = SeenAggregates::new();
        seen.record(SLOT, 0, ROOT, &bits4(0b0001));
        seen.record(SLOT + 1, 0, ROOT, &bits4(0b0001));

        seen.prune_before(SLOT + 1);

        assert_eq!(probe(&seen, &bits4(0b0001)), Coverage::New);
        assert_eq!(seen.coverage(SLOT + 1, 0, ROOT, &bits4(0b0001)), Coverage::BySuperset);
        seen.record(SLOT, 0, ROOT, &bits4(0b0001));
        assert_eq!(probe(&seen, &bits4(0b0001)), Coverage::New);
    }
}
