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
    tail: Slot,
    /// The tail is never lowered past this.
    floor: Slot,
}

impl SyncWindow {
    pub fn new() -> Self {
        Self { slots: [Entry::default(); N], tail: 0, floor: 0 }
    }

    pub(super) fn set_tail(&mut self, slot: Slot) {
        self.tail = slot.max(self.floor);
    }

    pub(super) fn set_floor(&mut self, floor: Slot) {
        self.floor = floor;
        self.tail = self.tail.max(floor);
    }

    pub fn tail(&self) -> Slot {
        self.tail
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

    pub(super) fn drop_above(&mut self, up_to: Slot) {
        for entry in &mut self.slots {
            if entry.slot > up_to {
                *entry = Entry::default();
            }
        }
    }

    /// Replace a slot's coverage with a fresh description of it. Emptiness
    /// proven by a peer's silence is kept where the description knows nothing.
    pub(super) fn reseed(&mut self, slot: Slot, coverage: Coverage) {
        self.update(slot, |e| {
            let silence = e.coverage.block == BlockState::Empty;
            e.coverage = coverage;
            if silence && coverage.block == BlockState::Unknown {
                e.coverage.block = BlockState::Empty;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needs() -> Needs {
        Needs { data_availability_floor: 0, custodies_columns: false, gloas_fork_slot: u64::MAX }
    }

    /// The ring must let the tail go wherever it is put, or the second range
    /// would be dropped for sitting under the first.
    #[test]
    fn bare_window_reseeds_onto_a_lower_range() {
        let mut window = SyncWindow::new();
        window.set_tail(999);
        window.block_received(1000, [1; 32], None, true);
        assert!(window.advance_tail(1031, needs()), "its own coverage moves the tail");
        assert_eq!(window.tail(), 1000);

        window.set_tail(967);
        window.drop_above(967);
        window.block_received(968, [2; 32], None, true);
        assert_eq!(
            window.coverage(968).block,
            BlockState::Applied,
            "the next range down is tracked, not discarded"
        );
    }

    #[test]
    fn reseeding_overwrites_coverage_but_keeps_silence() {
        let mut window = SyncWindow::new();
        window.set_tail(9);
        window.columns_covered(10);
        window.mark_empty(11);

        let unknown = Coverage::default();
        window.reseed(10, unknown);
        window.reseed(11, unknown);
        assert!(!window.coverage(10).columns_covered, "uncovered again");
        assert_eq!(window.coverage(11).block, BlockState::Empty, "silence survives");

        window.reseed(11, Coverage { block: BlockState::Applied, ..unknown });
        assert_eq!(window.coverage(11).block, BlockState::Applied, "a block beats silence");
    }
}
