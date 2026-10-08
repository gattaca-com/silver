use std::ops::{Index, IndexMut, Range};

use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationDataView, MAX_COMMITTEES_PER_SLOT,
};

use super::{InsertOutcome, committee_store::CommitteeId};

/// Retention is the inclusion window, the previous and current epoch, plus
/// one slot of clock disparity past it.
pub(super) const RETAINED_SLOTS: usize = 2 * SLOTS_PER_EPOCH as usize + 1;
/// Competing vote candidates a slot holds. Honest traffic keeps ~1 per slot,
/// and each costs an attacker a real committee member's one attestation per
/// epoch.
pub(super) const MAX_SLOT_CANDIDATES: usize = 4;
pub(super) const MAX_CANDIDATES: usize = RETAINED_SLOTS * MAX_SLOT_CANDIDATES;

/// The vote candidates of the retained slots. A candidate's id is
/// `slot % RETAINED_SLOTS * MAX_SLOT_CANDIDATES + offset`, `offset` being its
/// place among its slot's candidates.
pub(super) struct VoteCandidates {
    slots: [SlotCandidates; RETAINED_SLOTS],
    candidates: Box<[VoteCandidate]>,
    floor: Slot,
}

#[derive(Clone, Copy)]
struct SlotCandidates {
    slot: Slot,
    count: usize,
}

impl SlotCandidates {
    fn ids(&self, position: usize) -> Range<usize> {
        position * MAX_SLOT_CANDIDATES..position * MAX_SLOT_CANDIDATES + self.count
    }
}

/// An AttestationData someone voted for.
#[derive(Clone, Copy)]
pub(super) struct VoteCandidate {
    data_root: B256,
    data: [u8; ATTESTATION_DATA_SIZE],
    /// Bit `i` is set while committee `i` is open in the store.
    committees: u64,
}

impl VoteCandidate {
    const EMPTY: Self =
        Self { data_root: [0; 32], data: [0; ATTESTATION_DATA_SIZE], committees: 0 };

    pub(super) fn data(&self) -> AttestationDataView<'_> {
        AttestationDataView::new(&self.data)
    }

    /// Indices of the open committees, ascending.
    pub(super) fn committees(&self) -> impl Iterator<Item = usize> {
        let committees = self.committees;
        (0..MAX_COMMITTEES_PER_SLOT).filter(move |&index| committees & 1 << index != 0)
    }

    pub(super) fn is_open(&self, index: usize) -> bool {
        self.committees & 1 << index != 0
    }

    /// Marks committee `index` open; `false` when it already was.
    pub(super) fn open(&mut self, index: usize) -> bool {
        let opened = !self.is_open(index);
        self.committees |= 1 << index;
        opened
    }
}

impl VoteCandidates {
    pub(super) fn new() -> Self {
        Self {
            slots: [SlotCandidates { slot: 0, count: 0 }; RETAINED_SLOTS],
            candidates: vec![VoteCandidate::EMPTY; MAX_CANDIDATES].into_boxed_slice(),
            floor: 0,
        }
    }

    /// Ids of `slot`'s candidates; empty unless `slot` is retained.
    fn ids(&self, slot: Slot) -> Range<usize> {
        let position = slot as usize % RETAINED_SLOTS;
        let slot_candidates = &self.slots[position];
        if slot < self.floor || slot_candidates.slot != slot {
            return 0..0;
        }
        slot_candidates.ids(position)
    }

    /// Every retained candidate's id, newest slot first.
    pub(super) fn retained_ids(&self) -> impl Iterator<Item = usize> + '_ {
        let slots = self.floor..self.floor + RETAINED_SLOTS as Slot;
        slots.rev().flat_map(|slot| self.ids(slot))
    }

    pub(super) fn find(&self, slot: Slot, data_root: B256) -> Option<usize> {
        self.ids(slot).find(|&id| self.candidates[id].data_root == data_root)
    }

    /// The candidate for `data`, added when new.
    pub(super) fn find_or_add(
        &mut self,
        data: AttestationDataView,
        data_root: B256,
    ) -> Result<usize, InsertOutcome> {
        let slot = data.slot();
        if slot < self.floor {
            return Err(InsertOutcome::Stale);
        }
        if slot >= self.floor + RETAINED_SLOTS as Slot {
            return Err(InsertOutcome::Full);
        }
        if let Some(id) = self.find(slot, data_root) {
            return Ok(id);
        }

        let position = slot as usize % RETAINED_SLOTS;
        let slot_candidates = &mut self.slots[position];
        if slot_candidates.slot != slot {
            if slot_candidates.count > 0 {
                return Err(InsertOutcome::Full);
            }
            slot_candidates.slot = slot;
        }
        if slot_candidates.count == MAX_SLOT_CANDIDATES {
            return Err(InsertOutcome::Full);
        }
        let id = slot_candidates.ids(position).end;
        slot_candidates.count += 1;
        self.candidates[id] = VoteCandidate { data_root, data: *data.as_bytes(), committees: 0 };
        Ok(id)
    }

    /// Drops the candidates of slots below `floor`, passing each of their
    /// open committees to `close`.
    pub(super) fn prune_before(&mut self, floor: Slot, mut close: impl FnMut(CommitteeId)) {
        self.floor = floor;
        for (position, slot_candidates) in self.slots.iter_mut().enumerate() {
            if slot_candidates.slot >= floor {
                continue;
            }
            for id in slot_candidates.ids(position) {
                for index in self.candidates[id].committees() {
                    close(CommitteeId::new(id, index));
                }
                self.candidates[id].committees = 0;
            }
            slot_candidates.count = 0;
        }
    }
}

impl Index<usize> for VoteCandidates {
    type Output = VoteCandidate;

    fn index(&self, id: usize) -> &VoteCandidate {
        &self.candidates[id]
    }
}

impl IndexMut<usize> for VoteCandidates {
    fn index_mut(&mut self, id: usize) -> &mut VoteCandidate {
        &mut self.candidates[id]
    }
}
