mod chain;
mod codec;
mod rebuild;

use std::{collections::BTreeMap, io::Error};

use chain::Chain;
pub(super) use rebuild::read_block;
use silver_common::{PREFILL_SLOTS, Prefill, merkle::B256};

use super::{
    Payload,
    backfill::{BlockFacts, Needs},
    block_index::BlockIndex,
};

/// Where each kind stops being missing.
#[derive(Clone, Copy)]
pub(super) struct Floors {
    pub(super) blocks: u64,
    pub(super) columns: u64,
    pub(super) envelopes: u64,
}

impl Floors {
    pub(super) fn lowest_missing(self, custody: u128) -> u64 {
        let columns = if custody == 0 { u64::MAX } else { self.columns };
        columns.min(self.envelopes)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Block {
    pub(super) facts: BlockFacts,
    pub(super) needs: Needs,
    /// The slots in `(facts.slot, to]` hold no block. Only the finalized block
    /// proves anything above itself: the checkpoint is empty up to its slot.
    pub(super) to: u64,
}

impl Block {
    pub(super) fn new(
        facts: BlockFacts,
        needs: Needs,
        finalized_slot: u64,
        finalized_root: B256,
    ) -> Self {
        let to = if facts.block_root == finalized_root { finalized_slot } else { facts.slot };
        Self { facts, needs, to }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Missing {
    pub(super) columns: u128,
    pub(super) envelope: bool,
}

impl Missing {
    fn is_none(self) -> bool {
        self.columns == 0 && !self.envelope
    }
}

pub(super) fn window_start(end: u64) -> u64 {
    end.saturating_sub(PREFILL_SLOTS - 1)
}

/// What finalized history is on disk, kept as where it is complete and what
/// the held blocks are missing. Every writer proves completeness as it writes:
/// promotion walks the finalized chain, backfill links each block to the one
/// above it. A slot outside every span is unknown rather than empty.
pub(super) struct Coverage {
    /// The missing column masks were cut against this custody, so a coverage
    /// persisted under another one is rebuilt rather than trusted.
    custody: u128,
    chain: Chain,
    missing: BTreeMap<u64, Missing>,
    /// Groups below this were only indexed, never read: a held block there
    /// may need columns or an envelope nobody has recorded yet.
    examined_below: u64,
    version: u64,
    persisted: u64,
}

impl Coverage {
    pub(super) fn new(custody: u128) -> Self {
        Self {
            custody,
            chain: Chain::default(),
            missing: BTreeMap::new(),
            examined_below: 0,
            version: 0,
            persisted: 0,
        }
    }

    pub(super) fn load(store_dir: &str, custody: u128) -> Result<Option<Self>, Error> {
        codec::load(store_dir, custody)
    }

    pub(super) fn custody(&self) -> u128 {
        self.custody
    }

    pub(super) fn version(&self) -> u64 {
        self.version
    }

    fn touch(&mut self) {
        self.version += 1;
    }

    pub(super) fn persist_if_changed(
        &mut self,
        store_dir: &str,
        scratch: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if self.persisted == self.version {
            return Ok(());
        }
        codec::persist(self, store_dir, scratch)?;
        self.persisted = self.version;
        Ok(())
    }

    /// The root the next backfilled block must have to link below what we
    /// hold. `None` while the finalized block itself is not held, when it is
    /// the anchor.
    pub(super) fn wanted_parent(&self, finalized_slot: u64) -> Option<B256> {
        self.chain.top(finalized_slot).map(|top| top.wanted_parent)
    }

    pub(super) fn child_payload(&self, block_root: B256) -> Option<B256> {
        self.chain.child_payload(block_root)
    }

    pub(super) fn child_slot(&self, blocks: &BlockIndex, slot: u64) -> Option<u64> {
        let child = blocks.next_held_above(slot)?;
        self.chain.same_span(slot, child).then_some(child)
    }

    pub(super) fn note_block(&mut self, block: Block, blocks: &BlockIndex) {
        if !self.chain.note(&block, blocks) {
            return;
        }
        let columns = if block.needs.columns { self.custody } else { 0 };
        self.set_missing(block.facts.slot, Missing { columns, envelope: block.needs.envelope });
        self.touch();
    }

    pub(super) fn set_missing(&mut self, slot: u64, missing: Missing) {
        let before = match missing.is_none() {
            true => self.missing.remove(&slot),
            false => self.missing.insert(slot, missing),
        };
        if before.unwrap_or_default() != missing {
            self.touch();
        }
    }

    pub(super) fn note_columns(&mut self, slot: u64, present: u128) {
        let Some(entry) = self.missing.get_mut(&slot) else { return };
        if entry.columns & present == 0 {
            return;
        }
        entry.columns &= !present;
        if entry.is_none() {
            self.missing.remove(&slot);
        }
        self.touch();
    }

    pub(super) fn note_envelope(&mut self, slot: u64) {
        let Some(entry) = self.missing.get_mut(&slot) else { return };
        if !entry.envelope {
            return;
        }
        entry.envelope = false;
        if entry.is_none() {
            self.missing.remove(&slot);
        }
        self.touch();
    }

    pub(super) fn columns_missing(&self, slot: u64) -> u128 {
        if !self.chain.contains(slot) {
            return self.custody;
        }
        self.missing.get(&slot).map_or(0, |missing| missing.columns & self.custody)
    }

    pub(super) fn envelope_missing(&self, slot: u64) -> bool {
        if !self.chain.contains(slot) {
            return true;
        }
        self.missing.get(&slot).is_some_and(|missing| missing.envelope)
    }

    #[cfg(test)]
    pub(super) fn is_complete(&self, slot: u64) -> bool {
        self.columns_missing(slot) == 0 && !self.envelope_missing(slot)
    }

    pub(super) fn drop_below(&mut self, payload: Payload, earliest_slot: u64) {
        let before = self.missing.len();
        let mut changed = false;
        match payload {
            Payload::Block => {
                changed = self.chain.drop_below(earliest_slot);
                self.missing.retain(|&slot, _| slot >= earliest_slot);
            }
            Payload::Column => {
                for (_, entry) in self.missing.range_mut(..earliest_slot) {
                    changed |= entry.columns != 0;
                    entry.columns = 0;
                }
                self.missing.retain(|_, missing| !missing.is_none());
            }
            Payload::Envelope => {
                for (_, entry) in self.missing.range_mut(..earliest_slot) {
                    changed |= entry.envelope;
                    entry.envelope = false;
                }
                self.missing.retain(|_, missing| !missing.is_none());
            }
        }
        if changed || self.missing.len() != before {
            self.touch();
        }
    }

    /// The slot we may tell peers we serve from.
    pub(super) fn claim(&self, finalized_slot: u64, floor: u64, missing_from: u64) -> u64 {
        let held_from = self.chain.top(finalized_slot).map_or(finalized_slot, |top| top.from);
        let owed_to = self.missing.last_key_value().map_or(0, |(&slot, _)| slot + 1);
        let unexamined = if self.unexamined_above(missing_from) { self.examined_below } else { 0 };
        held_from.max(owed_to).max(unexamined).max(floor).min(finalized_slot)
    }

    /// The highest slot still missing something: the one under the chain,
    /// or a held block missing columns or an envelope.
    pub(super) fn next_window_end(&self, floors: Floors, finalized_slot: u64) -> Option<u64> {
        let hole = match self.chain.top(finalized_slot) {
            Some(top) => top.from.checked_sub(1),
            None => Some(finalized_slot),
        };
        let missing = self.missing.last_key_value().map(|(&slot, _)| slot);
        let end = hole.into_iter().chain(missing).max()?;
        (end >= floors.blocks).then_some(end)
    }

    /// The window from `start`, and whether anything in it is missing.
    pub(super) fn describe(
        &self,
        blocks: &BlockIndex,
        start: u64,
        floors: Floors,
        finalized_slot: u64,
    ) -> (Prefill, bool) {
        let complete = self.chain.bits(start);
        let held = blocks.held_bits(start);
        let have_block = complete & held;
        let unfinalized = !below(finalized_slot + 1, start);
        let known_empty =
            ((complete & !held) | below(floors.blocks, start) | unfinalized) & !have_block;

        // Only a held block needs columns or an envelope.
        let mut columns_covered = u32::MAX;
        let mut envelopes = u32::MAX;
        let mut columns_missing = 0u128;
        for (&slot, missing) in self.missing.range(start..start + PREFILL_SLOTS) {
            let bit = 1u32 << (slot - start);
            if have_block & bit == 0 {
                continue;
            }
            let absent = missing.columns & self.custody;
            if absent != 0 && below(floors.columns, start) & bit == 0 {
                columns_covered &= !bit;
                columns_missing |= absent;
            }
            if missing.envelope && below(floors.envelopes, start) & bit == 0 {
                envelopes &= !bit;
            }
        }

        let prefill =
            Prefill { start, have_block, known_empty, columns_covered, envelopes, columns_missing };
        let anything_missing = !known_empty & (!have_block | !columns_covered | !envelopes) != 0;
        (prefill, anything_missing)
    }
}

fn below(bound: u64, start: u64) -> u32 {
    match bound.saturating_sub(start) {
        0 => 0,
        n if n >= PREFILL_SLOTS => u32::MAX,
        n => (1u32 << n) - 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backfill::PayloadFacts;

    const CUSTODY: u128 = 0b111;
    const NOTHING: Needs = Needs { columns: false, envelope: false };

    fn floors() -> Floors {
        Floors { blocks: 1, columns: 1, envelopes: u64::MAX }
    }

    fn root(slot: u64) -> B256 {
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&slot.to_le_bytes());
        root
    }

    fn bit(prefill: &Prefill, field: u32, slot: u64) -> bool {
        field & (1u32 << (slot - prefill.start)) != 0
    }

    /// Land blocks top-down, as promotion does: each links to the next in
    /// the list, the last to `anchor`. The first is the finalized block and
    /// `needs` applies to it.
    fn land(
        coverage: &mut Coverage,
        blocks: &mut BlockIndex,
        slots: &[u64],
        anchor: B256,
        finalized: u64,
        needs: Needs,
    ) {
        for (i, &slot) in slots.iter().enumerate() {
            blocks.hold(root(slot), slot);
            let facts = BlockFacts {
                slot,
                block_root: root(slot),
                parent_root: slots.get(i + 1).map_or(anchor, |&parent| root(parent)),
                payload: PayloadFacts::default(),
            };
            let needs = if i == 0 { needs } else { NOTHING };
            coverage.note_block(Block::new(facts, needs, finalized, root(slots[0])), blocks);
        }
    }

    fn next(
        coverage: &Coverage,
        blocks: &BlockIndex,
        floors: Floors,
        finalized: u64,
    ) -> Option<(Prefill, bool)> {
        let end = coverage.next_window_end(floors, finalized)?;
        Some(coverage.describe(blocks, window_start(end), floors, finalized))
    }

    /// Absence from disk is not evidence either way.
    #[test]
    fn block_chain_proves_the_slots_it_skipped_empty() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[996, 992], [0xAA; 32], 1000, NOTHING);

        let (described, _) = coverage.describe(&blocks, 969, floors(), 1000);
        for held in [992, 996] {
            assert!(bit(&described, described.have_block, held), "slot {held} is held");
        }
        for empty in (993..996).chain(997..=1000) {
            assert!(bit(&described, described.known_empty, empty), "slot {empty} was skipped");
        }
        assert_eq!(described.have_block & described.known_empty, 0);

        let (prefill, needs) = next(&coverage, &blocks, floors(), 1000).expect("the hole below");
        assert_eq!(prefill.start, 991 - 31, "the window ends right under the chain");
        assert_eq!(prefill.have_block | prefill.known_empty, 0, "and nothing in it is known");
        assert!(needs);
        assert_eq!(coverage.wanted_parent(1000), Some([0xAA; 32]));
    }

    /// Only the finalized block proves the slots above it empty. A block
    /// promoted under it must not: when the finalized block's own write fails,
    /// its slot has to stay unknown so backfill asks for it.
    #[test]
    fn block_under_a_failed_finalized_block_proves_nothing_above_itself() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[90], [0xAA; 32], 90, NOTHING);

        // Finality moves to 100: the block at 100 is indexed but never lands,
        // the two under it do.
        blocks.index(root(100), 100);
        for slot in [96, 92] {
            blocks.hold(root(slot), slot);
            let facts = BlockFacts {
                slot,
                block_root: root(slot),
                parent_root: root(slot - 4),
                payload: PayloadFacts::default(),
            };
            coverage.note_block(Block::new(facts, NOTHING, 100, root(100)), &blocks);
        }
        let (described, _) = coverage.describe(&blocks, 69, floors(), 100);
        assert!(!bit(&described, described.known_empty, 100), "100 is not proven empty");
        assert!(!bit(&described, described.have_block, 100));
        for empty in [93, 94, 95] {
            assert!(bit(&described, described.known_empty, empty), "92 links over {empty}");
        }
        assert_eq!(coverage.wanted_parent(100), None, "the chain does not reach finality");
        assert_eq!(
            next(&coverage, &blocks, floors(), 100).unwrap().0.start + 31,
            100,
            "so 100 is asked"
        );

        land(&mut coverage, &mut blocks, &[100], root(96), 100, NOTHING);
        assert_eq!(coverage.wanted_parent(100), Some(root(88)), "the served block heals the chain");
        assert_eq!(
            next(&coverage, &blocks, floors(), 100).unwrap().0.start + 31,
            91,
            "and the walk moves on"
        );
    }

    /// The window ends where the chain does, so the block it wants next is
    /// inside it even under an empty run nothing on our side can prove.
    #[test]
    fn the_window_slides_down_with_the_chain() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[1000], root(996), 1000, NOTHING);
        let (prefill, _) = next(&coverage, &blocks, floors(), 1000).unwrap();
        assert_eq!((prefill.start, prefill.start + 31), (968, 999));

        // 996 lands and wants 990: the five slots between are unknown, and
        // the window moves so 990 is asked for alongside them.
        land(&mut coverage, &mut blocks, &[996], root(990), 1000, NOTHING);
        let (prefill, _) = next(&coverage, &blocks, floors(), 1000).unwrap();
        assert_eq!((prefill.start, prefill.start + 31), (964, 995));
        for unknown in 990..=995 {
            assert!(!bit(&prefill, prefill.known_empty, unknown), "{unknown} is asked for");
        }
    }

    /// The original bug: a held block missing only its envelope keeps its
    /// window published until the envelope lands.
    #[test]
    fn block_missing_its_envelope_keeps_its_window_published() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        let needs = Needs { columns: false, envelope: true };
        land(&mut coverage, &mut blocks, &[993, 992], [0; 32], 993, needs);
        let floors = Floors { blocks: 992, columns: 1, envelopes: 1 };

        let (prefill, needs) =
            next(&coverage, &blocks, floors, 993).expect("993 needs its envelope");
        assert!(needs);
        assert_eq!(prefill.start + 31, 993, "the window ends at the missing block");
        assert!(bit(&prefill, prefill.envelopes, 992), "992's envelope is on disk");
        assert!(!bit(&prefill, prefill.envelopes, 993), "993's is the hole");
        assert!(bit(&prefill, prefill.have_block, 993), "though its block is held");

        coverage.note_envelope(993);
        assert!(
            next(&coverage, &blocks, floors, 993).is_none(),
            "filling it leaves nothing missing above block retention"
        );
        assert!(coverage.missing.is_empty(), "and the entry is gone");
    }

    #[test]
    fn columns_are_missing_only_when_the_block_says_so() {
        for (needs, covered) in [(NOTHING, true), (Needs { columns: true, envelope: false }, false)]
        {
            let mut blocks = BlockIndex::default();
            let mut coverage = Coverage::new(CUSTODY);
            land(&mut coverage, &mut blocks, &[992], [0; 32], 992, needs);

            let (described, _) = coverage.describe(&blocks, 992, floors(), 992);
            assert_eq!(bit(&described, described.columns_covered, 992), covered);
            assert_eq!(described.columns_missing, if covered { 0 } else { CUSTODY });
            assert_eq!(coverage.is_complete(992), covered);
        }
    }

    /// The lower island is not claimed until the chain links into it.
    #[test]
    fn island_below_a_hole_joins_when_the_chain_reaches_it() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[501, 500], [0xAA; 32], 501, NOTHING);
        land(&mut coverage, &mut blocks, &[961], root(960), 961, NOTHING);
        assert_eq!(coverage.chain.spans().len(), 2);

        assert_eq!(coverage.claim(961, 1, 1), 961, "the island below is not claimed");
        let (prefill, _) = next(&coverage, &blocks, floors(), 961).expect("the hole");
        assert_eq!(prefill.start + 31, 960);
        assert!(
            !bit(&prefill, prefill.have_block, 960) && !bit(&prefill, prefill.known_empty, 960)
        );

        land(&mut coverage, &mut blocks, &[960], root(501), 961, NOTHING);
        let spans = coverage.chain.spans();
        assert_eq!(spans.len(), 1, "linked into the island");
        assert_eq!((spans[0].from, spans[0].to), (500, 961));
        assert_eq!(coverage.wanted_parent(961), Some([0xAA; 32]), "and wants what it wanted");
        assert_eq!(coverage.claim(961, 1, 1), 500);
    }

    #[test]
    fn hole_at_the_top_is_asked_for_first() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[500], [0; 32], 500, NOTHING);

        let (prefill, _) = next(&coverage, &blocks, floors(), 1000).expect("the top is short");
        assert_eq!(prefill.start + 31, 1000);
        assert_eq!(coverage.wanted_parent(1000), None, "the finalized root is the anchor");
    }

    /// Below its floor a kind was pruned or never existed, so the engine is
    /// handed coverage rather than a floor; the truncation that moved the floor
    /// prunes the entry.
    #[test]
    fn floors_are_reported_as_coverage() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        let needs = Needs { columns: true, envelope: true };
        land(&mut coverage, &mut blocks, &[992], [0; 32], 1000, needs);
        let floors = Floors { blocks: 1, columns: 4_000, envelopes: 4_000 };

        let (described, needs) = coverage.describe(&blocks, 992, floors, 1000);
        assert!(bit(&described, described.columns_covered, 992), "below the column floor");
        assert_eq!(described.envelopes, u32::MAX, "below the fork: no envelope ever existed");
        assert_eq!(described.columns_missing, 0);
        assert!(!needs, "992 needs nothing the floors do not cover");

        coverage.drop_below(Payload::Column, 4_000);
        coverage.drop_below(Payload::Envelope, 4_000);
        assert!(coverage.missing.is_empty(), "and its entry is pruned with the data");
        let (prefill, _) = next(&coverage, &blocks, floors, 1000).expect("the history below");
        assert_eq!(prefill.start + 31, 991);
    }

    #[test]
    fn the_claim_is_held_above_the_retention_floor() {
        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[2, 1], [0; 32], 2, NOTHING);
        assert_eq!(coverage.claim(2, 1, 1), 1, "the whole chain is held");
        assert_eq!(coverage.claim(2, 2, 1), 2, "but not below the floor");
    }

    /// A coverage cut against another custody, or one that does not parse, is
    /// not trusted.
    #[test]
    fn coverage_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("silver_coverage_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.to_string_lossy().into_owned();

        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        let needs = Needs { columns: true, envelope: true };
        land(&mut coverage, &mut blocks, &[996, 992], [0xAA; 32], 1000, needs);
        coverage.note_columns(996, 0b1);
        coverage.persist_if_changed(&store, &mut Vec::new()).unwrap();

        assert!(Coverage::load(&store, CUSTODY << 1).unwrap().is_none());
        let reloaded = Coverage::load(&store, CUSTODY).unwrap().expect("persisted");
        assert_eq!(reloaded.chain, coverage.chain);
        assert_eq!(reloaded.columns_missing(996), 0b110);
        assert!(reloaded.envelope_missing(996));
        assert_eq!(
            reloaded.describe(&blocks, 969, floors(), 1000),
            coverage.describe(&blocks, 969, floors(), 1000)
        );

        let file = dir.join("coverage.bin");
        let mut bytes = std::fs::read(&file).unwrap();
        bytes.push(0);
        std::fs::write(&file, &bytes).unwrap();
        assert!(Coverage::load(&store, CUSTODY).unwrap().is_none(), "trailing bytes: rebuilt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_is_written_once_per_change() {
        let dir = std::env::temp_dir().join(format!("silver_coverage_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.to_string_lossy().into_owned();
        let file = dir.join("coverage.bin");

        let mut blocks = BlockIndex::default();
        let mut coverage = Coverage::new(CUSTODY);
        land(&mut coverage, &mut blocks, &[992], [0; 32], 1000, NOTHING);
        coverage.persist_if_changed(&store, &mut Vec::new()).unwrap();
        assert!(file.exists());
        std::fs::remove_file(&file).unwrap();

        coverage.persist_if_changed(&store, &mut Vec::new()).unwrap();
        assert!(!file.exists(), "nothing changed since");
        coverage.set_missing(992, Missing { columns: 0b1, envelope: false });
        coverage.persist_if_changed(&store, &mut Vec::new()).unwrap();
        assert!(file.exists(), "a change is written");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
