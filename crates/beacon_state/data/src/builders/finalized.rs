use std::io::{self, Write};

use super::builder_hash;
use crate::{
    DecomposeError,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder, builder_capacity},
    hash_tree::GloasFinalized,
};

/// SSZ-serialised `Builder`: pubkey(48) + version(1) + execution_address(20) +
/// balance(8) + deposit_epoch(8) + withdrawable_epoch(8).
const BUILDER_SSZ: usize = 93;

pub struct FinalizedBuilders {
    pub(super) builders: Box<[Builder]>,
    pub(super) count: usize,
    pub(super) hash: GloasFinalized,
}

impl Default for FinalizedBuilders {
    fn default() -> Self {
        Self::from_ssz(&[]).expect("empty builders registry is valid")
    }
}

impl FinalizedBuilders {
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

        // One allocation: the capacity-sized registry, filled in place from the
        // SSZ bytes (no intermediate parsed buffer). Tail past `count` stays
        // spec-default for the append headroom.
        let mut builders = vec![Builder::default(); builder_capacity(count)].into_boxed_slice();
        for (i, slot) in builders[..count].iter_mut().enumerate() {
            let s = &bytes[i * BUILDER_SSZ..];
            *slot = Builder {
                pubkey: s[0..48].try_into().unwrap(),
                version: s[48],
                execution_address: s[49..69].try_into().unwrap(),
                balance: u64::from_le_bytes(s[69..77].try_into().unwrap()),
                deposit_epoch: u64::from_le_bytes(s[77..85].try_into().unwrap()),
                withdrawable_epoch: u64::from_le_bytes(s[85..93].try_into().unwrap()),
            };
        }

        let hash = GloasFinalized::from_leaf_hashes(
            builders[..count].iter().map(builder_hash),
            builder_capacity(count),
        );
        Ok(Self { builders, count, hash })
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.count * BUILDER_SSZ
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for b in self.as_slice() {
            w.write_all(&b.pubkey)?;
            w.write_all(&[b.version])?;
            w.write_all(&b.execution_address)?;
            w.write_all(&b.balance.to_le_bytes())?;
            w.write_all(&b.deposit_epoch.to_le_bytes())?;
            w.write_all(&b.withdrawable_epoch.to_le_bytes())?;
        }
        Ok(())
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
    pub(super) fn as_slice(&self) -> &[Builder] {
        &self.builders[..self.count]
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.builders.len()
    }

    #[inline]
    pub fn hash(&self) -> &GloasFinalized {
        &self.hash
    }

    pub(super) fn ensure_capacity(&mut self, end: usize) {
        if end > self.builders.len() {
            let mut grown = vec![Builder::default(); builder_capacity(end)].into_boxed_slice();
            grown[..self.count].copy_from_slice(&self.builders[..self.count]);
            self.builders = grown;
        }
    }
}
