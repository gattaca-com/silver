use std::{
    io::{Error, ErrorKind, Read, Write},
    path::Path,
};

use fxhash::FxHashMap;
use silver_common::merkle::B256;

use crate::store::io::{open_file_read, open_file_write};

const RECORD_LEN: usize = 32 + 8;
const FILE_NAME: &str = "block_index.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) block_root: B256,
    pub(super) slot: u64,
}

impl Record {
    fn encode(&self) -> [u8; RECORD_LEN] {
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

/// Written in one call: a torn append misaligns every fixed-width record after
/// it when the write is retried.
pub(super) fn append(dir: &Path, record: Record) -> Result<(), Error> {
    open_file_write(dir.join(FILE_NAME), true)?.write_all(&record.encode())
}

pub(super) fn load_dir(dir: &Path, sink: &mut impl FnMut(Record)) -> Result<(), Error> {
    let mut file = match open_file_read(dir.join(FILE_NAME)) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut bytes = [0u8; RECORD_LEN];
    while file.read_exact(&mut bytes).is_ok() {
        sink(Record::decode(&bytes));
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
#[derive(Default)]
pub(super) struct BlockIndex {
    by_root: FxHashMap<B256, u64>,
    held: Held,
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
    }

    pub(super) fn hold(&mut self, root: B256, slot: u64) {
        self.by_root.insert(root, slot);
        self.held.set(slot);
    }

    /// The file is down: its record goes into `dir`'s index file, then the
    /// slot is held.
    pub(super) fn landed(&mut self, dir: &Path, root: B256, slot: u64) -> Result<(), Error> {
        append(dir, Record { block_root: root, slot })?;
        self.hold(root, slot);
        Ok(())
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
        let dir = scratch("round_trip");
        assert!(load(&dir).is_empty());
        let written =
            [Record { block_root: [1; 32], slot: 40 }, Record { block_root: [2; 32], slot: 44 }];
        for record in written {
            append(&dir, record).unwrap();
        }

        assert_eq!(load(&dir), written);
        let _ = std::fs::remove_dir_all(&dir);
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
