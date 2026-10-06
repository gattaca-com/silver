use rustc_hash::FxHashMap;

use super::{ForkChoiceNode, NodeLookup, PayloadStatus, vote::branch_voted_for};
use crate::stf::VoteTarget;

/// A few epochs' worth of targets. Below this size we never compact early.
pub(super) const MIN_COMPACT_AT: usize = 4096;

/// Placeholder at id 0, which means "no vote". Its value is never read.
const UNSET: VoteTarget = VoteTarget {
    block_root: [0; 32],
    target_epoch: 0,
    attestation_slot: 0,
    payload_present: false,
};

/// The distinct targets that votes point at. A vote stores a small id instead
/// of the whole target, and id 0 means "no vote". An epoch has only a few
/// hundred distinct targets, so the table stays small.
pub(super) struct VoteTargets {
    table: Vec<VoteTarget>,
    ids: FxHashMap<VoteTarget, u32>,
    /// Compact once the table reaches this size. This keeps it small even when
    /// finality stalls and `prune` stops running.
    compact_at: usize,
    /// Buffers reused between calls, so resolving and compacting do not
    /// allocate.
    resolved: Vec<Option<(usize, PayloadStatus)>>,
    remap: Vec<u32>,
    spare: Vec<VoteTarget>,
}

impl Default for VoteTargets {
    fn default() -> Self {
        Self {
            table: vec![UNSET],
            ids: FxHashMap::default(),
            compact_at: MIN_COMPACT_AT,
            resolved: Vec::new(),
            remap: Vec::new(),
            spare: Vec::new(),
        }
    }
}

impl VoteTargets {
    pub(super) fn needs_compaction(&self) -> bool {
        self.table.len() >= self.compact_at
    }

    pub(super) fn get_or_insert(&mut self, target: &VoteTarget) -> u32 {
        *self.ids.entry(*target).or_insert_with(|| {
            self.table.push(*target);
            (self.table.len() - 1) as u32
        })
    }

    pub(super) fn get(&self, id: u32) -> &VoteTarget {
        &self.table[id as usize]
    }

    /// For every id, the tree node it votes for and on which branch. `None`
    /// means no weight: the id is "no vote", or its block is not in the tree.
    pub(super) fn resolve(
        &mut self,
        lookup: &NodeLookup,
        nodes: &[ForkChoiceNode],
    ) -> &[Option<(usize, PayloadStatus)>] {
        self.resolved.clear();
        self.resolved.extend(self.table.iter().map(|t| {
            let node = lookup.get(&t.block_root)?;
            Some((node, branch_voted_for(&nodes[node], t.attestation_slot, t.payload_present)))
        }));
        self.resolved[0] = None;
        &self.resolved
    }

    /// Removes unused targets and reindexes the rest.
    pub(super) fn compact<'a>(&mut self, ids: impl Iterator<Item = &'a mut u32>) {
        self.remap.clear();
        self.remap.resize(self.table.len(), 0);
        self.spare.clear();
        self.spare.push(UNSET);
        self.ids.clear();
        for id in ids.filter(|id| **id != 0) {
            let new_id = &mut self.remap[*id as usize];
            if *new_id == 0 {
                *new_id = self.spare.len() as u32;
                let target = self.table[*id as usize];
                self.ids.insert(target, *new_id);
                self.spare.push(target);
            }
            *id = *new_id;
        }
        std::mem::swap(&mut self.table, &mut self.spare);
        self.compact_at = (2 * self.table.len()).max(MIN_COMPACT_AT);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{MIN_COMPACT_AT, VoteTargets};
    use crate::stf::VoteTarget;

    fn target(i: u8) -> VoteTarget {
        VoteTarget {
            block_root: [i; 32],
            target_epoch: i as u64,
            attestation_slot: i as u64 * 32,
            payload_present: false,
        }
    }

    /// Gossip repeats the same few targets millions of times per epoch. The
    /// table must hold each distinct target only once.
    #[test]
    fn stores_each_distinct_target_once() {
        let mut targets = VoteTargets::default();
        let first: Vec<_> = (1..=5).map(|i| targets.get_or_insert(&target(i))).collect();
        for round in 0..1000 {
            let i = (round % 5) as usize;
            assert_eq!(targets.get_or_insert(&target(i as u8 + 1)), first[i]);
        }
        assert_eq!(targets.len(), 1 + 5);
        assert_eq!(targets.ids.len(), 5);
    }

    /// Compaction renumbers ids. Each id must still point at the same target,
    /// and targets nothing points at must be gone.
    #[test]
    fn compact_keeps_every_id_on_its_target() {
        let mut targets = VoteTargets::default();
        let [_, two, three] = [1, 2, 3].map(|i| targets.get_or_insert(&target(i)));
        let mut ids = vec![three, 0, three, two, 0, 0, three, three];
        let before: Vec<_> = ids.iter().map(|&id| *targets.get(id)).collect();

        targets.compact(ids.iter_mut());

        let after: Vec<_> = ids.iter().map(|&id| *targets.get(id)).collect();
        assert!(after == before, "an id changed target");
        assert_eq!(targets.len(), 3, "unset, target 3 and target 2");
        assert!(!targets.ids.contains_key(&target(1)));
        for (id, t) in targets.table.iter().enumerate().skip(1) {
            assert_eq!(targets.ids[t], id as u32);
        }
        assert_eq!(targets.compact_at, MIN_COMPACT_AT);
    }
}
