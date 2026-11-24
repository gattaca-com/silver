#[cfg(test)]
use std::io::Write;
use std::{
    fs::OpenOptions,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};

use fxhash::FxHashMap;
use silver_common::merkle::B256;

use super::SLOTS_PER_DIR;

const RECORD_LEN: usize = 32 + 8;
const FILE_NAME: &str = "block_index.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) block_root: B256,
    pub(super) slot: u64,
}

impl Record {
    pub(super) fn encode(&self) -> [u8; RECORD_LEN] {
        let mut bytes = [0u8; RECORD_LEN];
        bytes[..32].copy_from_slice(&self.block_root);
        bytes[32..].copy_from_slice(&self.slot.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8; RECORD_LEN]) -> Self {
        Self {
            block_root: bytes[..32].try_into().expect("32 of RECORD_LEN"),
            slot: u64::from_le_bytes(bytes[32..].try_into().expect("8 of RECORD_LEN")),
        }
    }
}

pub(super) fn file(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

#[cfg(test)]
pub(super) fn append(dir: &Path, record: Record) -> Result<(), Error> {
    append_bytes(dir, &record.encode())
}

#[cfg(test)]
fn append_bytes(dir: &Path, bytes: &[u8]) -> Result<(), Error> {
    OpenOptions::new().append(true).create(true).open(file(dir))?.write_all(bytes)
}

/// Records up to the first torn one, or one outside `dir`'s slot group. The
/// file is cut there, so later appends stay aligned.
pub(super) fn load_dir(dir: &Path, sink: &mut impl FnMut(Record)) -> Result<(), Error> {
    let Some(group) = dir.file_name().and_then(|name| name.to_str()?.parse::<u64>().ok()) else {
        return Ok(());
    };
    let path = file(dir);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut valid = 0;
    for chunk in bytes.chunks_exact(RECORD_LEN) {
        let record = Record::decode(chunk.try_into().expect("chunks of RECORD_LEN"));
        if !(group..group + SLOTS_PER_DIR).contains(&record.slot) {
            break;
        }
        sink(record);
        valid += RECORD_LEN;
    }
    if valid < bytes.len() {
        silver_log::warn!(?path, valid, len = bytes.len(), "block index cut at a bad record");
        OpenOptions::new().write(true).open(&path)?.set_len(valid as u64)?;
    }
    Ok(())
}

/// Finalized block files by slot. The root map cannot answer by slot.
#[derive(Default)]
struct Held(Vec<u64>);

impl Held {
    fn has(&self, slot: u64) -> bool {
        self.0.get((slot / 64) as usize).is_some_and(|word| word >> (slot % 64) & 1 == 1)
    }

    fn set(&mut self, slot: u64) {
        let word = (slot / 64) as usize;
        if word >= self.0.len() {
            self.0.resize(word + 1, 0);
        }
        self.0[word] |= 1u64 << (slot % 64);
    }

    fn clear_below(&mut self, slot: u64) {
        let word = (slot / 64) as usize;
        let whole = word.min(self.0.len());
        self.0[..whole].fill(0);
        if let Some(partial) = self.0.get_mut(word) {
            *partial &= u64::MAX << (slot % 64);
        }
    }

    fn bits(&self, start: u64) -> u32 {
        let word = (start / 64) as usize;
        let shift = start % 64;
        let low = self.0.get(word).copied().unwrap_or(0) >> shift;
        let high = match shift > 32 {
            true => self.0.get(word + 1).copied().unwrap_or(0) << (64 - shift),
            false => 0,
        };
        (low | high) as u32
    }

    fn descending(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().enumerate().rev().filter(|(_, word)| **word != 0).flat_map(|(i, word)| {
            let word = *word;
            (0..64)
                .rev()
                .filter(move |bit| word >> bit & 1 == 1)
                .map(move |bit| i as u64 * 64 + bit)
        })
    }

    fn next_above(&self, slot: u64) -> Option<u64> {
        let mut word = (slot / 64) as usize;
        let mut bits = *self.0.get(word)? & !(u64::MAX >> (63 - slot % 64));
        loop {
            if bits != 0 {
                return Some(word as u64 * 64 + bits.trailing_zeros() as u64);
            }
            word += 1;
            bits = *self.0.get(word)?;
        }
    }
}

/// The finalized blocks: root → slot, and which slots have a file. A root is
/// indexed when its promotion is queued and held once its file is down, so a
/// root indexed at a slot not held is a block that finalized but was never
/// written.
pub(super) struct BlockIndex {
    by_root: FxHashMap<B256, u64>,
    by_slot: FxHashMap<u64, B256>,
    held: Held,
    floor: u64,
}

impl Default for BlockIndex {
    fn default() -> Self {
        Self {
            by_root: FxHashMap::default(),
            by_slot: FxHashMap::default(),
            held: Held::default(),
            floor: u64::MAX,
        }
    }
}

impl BlockIndex {
    pub(super) fn load(blocks_dir: &Path) -> Result<Self, Error> {
        let mut index = Self::default();
        for group in std::fs::read_dir(blocks_dir)? {
            load_dir(&group?.path(), &mut |record| index.hold(record.block_root, record.slot))?;
        }
        Ok(index)
    }

    pub(super) fn index(&mut self, root: B256, slot: u64) {
        self.by_root.insert(root, slot);
        self.by_slot.insert(slot, root);
        self.floor = self.floor.min(slot);
    }

    pub(super) fn hold(&mut self, root: B256, slot: u64) {
        self.index(root, slot);
        self.held.set(slot);
    }

    pub(super) fn slot_of(&self, root: &B256) -> Option<u64> {
        self.by_root.get(root).copied()
    }

    pub(super) fn contains(&self, root: &B256) -> bool {
        self.by_root.contains_key(root)
    }

    pub(super) fn holds(&self, slot: u64) -> bool {
        self.held.has(slot)
    }

    pub(super) fn drop_below(&mut self, first_retained: u64) {
        for slot in self.floor..first_retained {
            if let Some(root) = self.by_slot.remove(&slot) {
                self.by_root.remove(&root);
            }
        }
        self.held.clear_below(first_retained);
        self.floor = self.floor.max(first_retained);
    }

    pub(super) fn root_at(&self, slot: u64) -> Option<B256> {
        self.held.has(slot).then(|| self.by_slot.get(&slot).copied()).flatten()
    }

    /// The block at `slot` is `root`, and its file is down.
    pub(super) fn written(&self, root: &B256, slot: u64) -> bool {
        self.slot_of(root) == Some(slot) && self.held.has(slot)
    }

    /// The slot of a block that finalized but whose file never landed.
    pub(super) fn unwritten(&self, root: &B256) -> Option<u64> {
        self.slot_of(root).filter(|&slot| !self.held.has(slot))
    }

    /// The 32 slots from `start` with a block file, as bits.
    pub(super) fn held_bits(&self, start: u64) -> u32 {
        self.held.bits(start)
    }

    pub(super) fn held_descending(&self) -> impl Iterator<Item = u64> + '_ {
        self.held.descending()
    }

    pub(super) fn next_held_above(&self, slot: u64) -> Option<u64> {
        self.held.next_above(slot)
    }

    pub(super) fn slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_root.values().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(dir: &Path) -> Vec<Record> {
        let mut records = Vec::new();
        load_dir(dir, &mut |record| records.push(record)).unwrap();
        records
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("silver_block_index_{name}_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn records_round_trip_through_the_file() {
        let root = scratch("round_trip");
        let dir = root.join("0");
        std::fs::create_dir(&dir).unwrap();
        assert!(load(&dir).is_empty());
        let written =
            [Record { block_root: [1; 32], slot: 40 }, Record { block_root: [2; 32], slot: 44 }];
        for record in written {
            append(&dir, record).unwrap();
        }

        assert_eq!(load(&dir), written);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A crash mid-append leaves a partial record; the next append after a
    /// reload must still be readable.
    #[test]
    fn torn_tail_is_cut_before_the_next_append() {
        let root = scratch("torn_tail");
        let dir = root.join("128");
        std::fs::create_dir(&dir).unwrap();
        let first = Record { block_root: [1; 32], slot: 130 };
        append(&dir, first).unwrap();
        append_bytes(&dir, &[0xFF; RECORD_LEN / 2]).unwrap();

        assert_eq!(load(&dir), [first]);
        let second = Record { block_root: [2; 32], slot: 131 };
        append(&dir, second).unwrap();
        assert_eq!(load(&dir), [first, second]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A record whose slot lies outside its group is corrupt: loading stops
    /// there instead of sizing the held map by it.
    #[test]
    fn record_outside_its_group_ends_the_file() {
        let root = scratch("outside_group");
        let dir = root.join("128");
        std::fs::create_dir(&dir).unwrap();
        let kept = Record { block_root: [1; 32], slot: 200 };
        append(&dir, kept).unwrap();
        append(&dir, Record { block_root: [2; 32], slot: 1 << 62 }).unwrap();
        append(&dir, Record { block_root: [3; 32], slot: 201 }).unwrap();

        assert_eq!(load(&dir), [kept]);
        assert_eq!(std::fs::metadata(file(&dir)).unwrap().len(), RECORD_LEN as u64);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn indexed_root_is_unwritten_until_held() {
        let mut index = BlockIndex::default();
        index.index([1; 32], 40);
        assert_eq!(index.unwritten(&[1; 32]), Some(40));
        assert!(!index.holds(40));

        index.hold([1; 32], 40);
        assert_eq!(index.unwritten(&[1; 32]), None);
        assert!(index.holds(40));
        assert_eq!(index.unwritten(&[2; 32]), None, "never indexed");
    }

    #[test]
    fn dropped_slots_are_forgotten_in_every_view() {
        let mut index = BlockIndex::default();
        for (byte, slot) in [(1u8, 100u64), (2, 200), (3, 300)] {
            index.hold([byte; 32], slot);
        }
        index.index([4; 32], 150);
        assert_eq!(index.root_at(150), None, "indexed but not held");

        index.drop_below(256);
        for (root, slot) in [([1; 32], 100), ([2; 32], 200), ([4; 32], 150)] {
            assert_eq!(index.slot_of(&root), None, "slot {slot}");
            assert_eq!(index.root_at(slot), None, "slot {slot}");
            assert!(!index.holds(slot), "slot {slot}");
        }
        assert_eq!(index.slot_of(&[3; 32]), Some(300));
        assert_eq!(index.root_at(300), Some([3; 32]));
        assert!(index.holds(300));
        assert_eq!(index.held_descending().collect::<Vec<_>>(), vec![300]);
        assert_eq!(index.next_held_above(0), Some(300));

        index.hold([5; 32], 260);
        index.drop_below(300);
        assert_eq!(index.slot_of(&[5; 32]), None, "swept from the previous boundary");
        assert_eq!(index.slot_of(&[3; 32]), Some(300));
    }

    #[test]
    fn window_bits_span_words() {
        let mut held = Held::default();
        for slot in [100, 127, 128, 131, 190] {
            held.set(slot);
        }
        let bits = held.bits(100);
        for slot in 100..132 {
            assert_eq!(bits >> (slot - 100) & 1 == 1, held.has(slot), "slot {slot}");
        }
        assert_eq!(held.bits(160), 1 << 30, "190 alone, from the last word");
        assert_eq!(held.bits(192), 0, "past the map");
    }
}
