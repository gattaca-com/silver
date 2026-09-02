use silver_common::DataKind;

use super::BATCH;

pub type Slot = u64;

pub(super) const FETCH_CEILING: u64 = 2 * BATCH;

const N: usize = FETCH_CEILING as usize;
const MASK: u64 = N as u64 - 1;

const _: () = assert!(N.is_power_of_two(), "ring index is a mask, not a modulo");

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum BlockState {
    #[default]
    Unknown,
    Empty,
    Parked,
    Applied,
}

#[derive(Clone, Copy, Default)]
pub(super) struct SeenBlocks {
    pub(super) root: [u8; 32],
    pub(super) count: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Needs {
    pub(super) data_availability_floor: Slot,
    pub(super) custodies_columns: bool,
    pub(super) gloas_fork_slot: Slot,
}

impl Needs {
    pub(super) fn reachable(self, kind: DataKind, last: Slot) -> bool {
        match kind {
            DataKind::Block => true,
            DataKind::Columns => self.custodies_columns && last > self.data_availability_floor,
            DataKind::Envelope => last >= self.gloas_fork_slot,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Coverage {
    pub block: BlockState,
    pub columns_covered: bool,
    pub envelope_covered: bool,
}

impl Coverage {
    pub(super) fn owes(self, kind: DataKind, slot: Slot, needs: Needs) -> bool {
        if self.block == BlockState::Empty {
            return false;
        }
        match kind {
            DataKind::Block => self.block == BlockState::Unknown,
            DataKind::Columns => {
                needs.custodies_columns &&
                    !self.columns_covered &&
                    slot > needs.data_availability_floor
            }
            DataKind::Envelope => !self.envelope_covered && slot >= needs.gloas_fork_slot,
        }
    }

    fn complete(self, slot: Slot, needs: Needs) -> bool {
        matches!(self.block, BlockState::Empty | BlockState::Applied) &&
            DataKind::ALL.iter().all(|&kind| !self.owes(kind, slot, needs))
    }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    slot: Slot,
    coverage: Coverage,
    seen_blocks: SeenBlocks,
}

pub struct SyncWindow {
    slots: [Entry; N],
    applied_head: Slot,
    tail: Slot,
    finalized: Slot,
    awaiting_start: bool,
}

impl SyncWindow {
    pub fn new() -> Self {
        Self {
            slots: [Entry::default(); N],
            applied_head: 0,
            tail: 0,
            finalized: 0,
            awaiting_start: true,
        }
    }

    pub fn record_status(&mut self, slot: Slot, finalized_slot: Slot, following: bool) {
        self.applied_head = slot;
        self.finalized = finalized_slot;
        let tail = if self.awaiting_start || following {
            self.awaiting_start = false;
            slot
        } else {
            self.tail
        };
        self.set_tail(tail);
    }

    fn set_tail(&mut self, slot: Slot) {
        self.tail = slot.max(self.finalized);
    }

    pub(super) fn restart_at_next_status(&mut self) {
        self.awaiting_start = true;
    }

    pub fn tail(&self) -> Slot {
        self.tail
    }

    pub(super) fn applied_head(&self) -> Slot {
        self.applied_head
    }

    pub(super) fn advance_tail(&mut self, end: Slot, needs: Needs) -> bool {
        let before = self.tail;
        let mut tail = self.tail;
        while tail < end {
            let slot = tail + 1;
            if !self.coverage(slot).complete(slot, needs) {
                break;
            }
            tail = slot;
        }
        self.set_tail(tail);
        self.tail != before
    }

    pub fn ceiling(&self) -> Slot {
        self.tail + FETCH_CEILING
    }

    pub fn coverage(&self, slot: Slot) -> Coverage {
        self.entry(slot).coverage
    }

    pub(super) fn seen_blocks(&self, slot: Slot) -> SeenBlocks {
        self.entry(slot).seen_blocks
    }

    fn entry(&self, slot: Slot) -> Entry {
        let entry = self.slots[(slot & MASK) as usize];
        if entry.slot == slot { entry } else { Entry::default() }
    }

    fn update(&mut self, slot: Slot, f: impl FnOnce(&mut Entry)) {
        if slot > self.ceiling() || slot <= self.tail {
            return;
        }
        let entry = &mut self.slots[(slot & MASK) as usize];
        if entry.slot != slot {
            debug_assert!(
                entry.slot <= self.tail,
                "slot {slot} would evict live slot {}",
                entry.slot
            );
            *entry = Entry { slot, ..Entry::default() };
        }
        f(entry);
    }

    pub fn block_received(
        &mut self,
        slot: Slot,
        block_root: [u8; 32],
        parent_slot: Option<Slot>,
        applied: bool,
    ) {
        let state = match applied {
            true => BlockState::Applied,
            false => BlockState::Parked,
        };
        // Never downgrade: a sibling at this slot may already have applied, and
        // parking another one says nothing about that.
        self.update(slot, |e| {
            if state == BlockState::Applied ||
                matches!(e.coverage.block, BlockState::Unknown | BlockState::Empty)
            {
                e.coverage.block = state;
                e.seen_blocks.root = block_root;
            }
            e.seen_blocks.count += 1;
        });
        if let Some(parent) = parent_slot {
            for empty in (parent + 1)..slot {
                self.mark_empty(empty);
            }
        }
    }

    pub fn mark_empty(&mut self, slot: Slot) {
        self.update(slot, |e| {
            if e.coverage.block == BlockState::Unknown {
                e.coverage.block = BlockState::Empty;
            }
        });
    }

    pub fn columns_covered(&mut self, slot: Slot) {
        self.update(slot, |e| e.coverage.columns_covered = true);
    }

    pub fn envelope_covered(&mut self, slot: Slot) {
        self.update(slot, |e| e.coverage.envelope_covered = true);
    }

    /// Slots above the tail, up to `up_to`, for which we have neither a block
    /// nor proof there was none — the run that says we are behind on *blocks*
    /// rather than on data or on a quiet chain.
    pub fn unknown_blocks_up_to_slot(&self, up_to: Slot) -> u64 {
        let last = up_to.min(self.ceiling());
        (self.tail + 1..=last)
            .take_while(|&s| self.coverage(s).block == BlockState::Unknown)
            .count() as u64
    }

    pub(super) fn reseed_for_new_target(&mut self) {
        self.set_tail(self.tail.min(self.applied_head));
        self.drop(self.tail);
    }

    pub fn on_reorg(&mut self, lca_slot: Slot) {
        self.applied_head = self.applied_head.min(lca_slot);
        self.set_tail(self.tail.min(lca_slot));
        self.drop(lca_slot);
    }

    fn drop(&mut self, up_to: Slot) {
        for entry in &mut self.slots {
            if entry.slot > up_to {
                *entry = Entry::default();
            }
        }
    }
}
