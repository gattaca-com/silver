use super::builder_hash;
use crate::{
    DecomposeError,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder, builder_capacity},
    hash_tree::FinalizedHashTree,
};

/// SSZ-serialised `Builder`: pubkey(48) + version(1) + execution_address(20) +
/// balance(8) + deposit_epoch(8) + withdrawable_epoch(8).
const BUILDER_SSZ: usize = 93;

pub struct FinalizedBuilders {
    pub(super) builders: Box<[Builder]>,
    pub(super) count: usize,
    pub(super) hash: FinalizedHashTree,
}

impl Default for FinalizedBuilders {
    fn default() -> Self {
        Self::from_builders(&[])
    }
}

impl FinalizedBuilders {
    fn from_builders(parsed: &[Builder]) -> Self {
        let count = parsed.len();
        let capacity = builder_capacity(count);
        let mut builders = vec![Builder::default(); capacity].into_boxed_slice();
        builders[..count].copy_from_slice(parsed);
        let hash = FinalizedHashTree::from_leaves(
            (0..count).map(|i| builder_hash(&builders[i])),
            capacity,
        );
        Self { builders, count, hash }
    }

    pub(crate) fn from_ssz(bytes: &[u8]) -> Result<Self, DecomposeError> {
        if !bytes.len().is_multiple_of(BUILDER_SSZ) {
            return Err(DecomposeError::GloasFieldLen {
                field: "builders",
                len: bytes.len(),
                size: BUILDER_SSZ,
            });
        }
        let count = bytes.len() / BUILDER_SSZ;
        if count > BUILDER_REGISTRY_LIMIT {
            return Err(DecomposeError::GloasTooMany {
                field: "builders",
                n: count,
                max: BUILDER_REGISTRY_LIMIT,
            });
        }
        let parsed: Vec<Builder> = (0..count)
            .map(|i| {
                let s = &bytes[i * BUILDER_SSZ..];
                Builder {
                    pubkey: s[0..48].try_into().unwrap(),
                    version: s[48],
                    execution_address: s[49..69].try_into().unwrap(),
                    balance: u64::from_le_bytes(s[69..77].try_into().unwrap()),
                    deposit_epoch: u64::from_le_bytes(s[77..85].try_into().unwrap()),
                    withdrawable_epoch: u64::from_le_bytes(s[85..93].try_into().unwrap()),
                }
            })
            .collect();
        Ok(Self::from_builders(&parsed))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub(super) fn get(&self, i: usize) -> Option<&Builder> {
        (i < self.count).then(|| &self.builders[i])
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.builders.len()
    }

    #[inline]
    pub fn hash(&self) -> &FinalizedHashTree {
        &self.hash
    }
}
