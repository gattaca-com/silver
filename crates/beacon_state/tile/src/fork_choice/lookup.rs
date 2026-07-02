use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
};

use silver_beacon_state_data::B256;

use super::MAX_FORK_CHOICE_NODES;

/// Identity hasher for block roots: a `block_root` is already a 32-byte
/// cryptographic hash, so its leading 8 bytes are a ready-made uniform key —
/// re-hashing them would be pure waste. `NodeLookup` only ever keys on `B256`,
/// which hashes as a single `write` of its 32 bytes (last-write-wins guards
/// against any stray shorter write).
#[derive(Default)]
struct RootHasher(u64);

impl Hasher for RootHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            self.0 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

pub struct NodeLookup(HashMap<B256, u32, BuildHasherDefault<RootHasher>>);

impl Default for NodeLookup {
    fn default() -> Self {
        Self(HashMap::with_capacity_and_hasher(
            MAX_FORK_CHOICE_NODES,
            BuildHasherDefault::default(),
        ))
    }
}

impl NodeLookup {
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }

    pub(super) fn insert(&mut self, root: B256, node_idx: usize) {
        self.0.insert(root, node_idx as u32);
    }

    #[inline]
    pub(super) fn get(&self, root: &B256) -> Option<usize> {
        self.0.get(root).map(|&i| i as usize)
    }
}
