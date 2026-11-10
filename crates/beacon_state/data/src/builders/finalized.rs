use std::io::{self, Write};

use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder, builder_capacity},
};

/// SSZ-serialised `Builder`: pubkey(48) + version(1) + execution_address(20) +
/// balance(8) + deposit_epoch(8) + withdrawable_epoch(8).
const BUILDER_SSZ: usize = 93;

pub struct FinalizedBuilders {
    /// Its length is the builder count, so a racing reader's slice never
    /// covers slots its block has not filled.
    pub(super) builders: RetainedVec<Builder>,
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
        // SSZ bytes (no intermediate parsed buffer).
        let mut builders = RetainedVec::with_capacity(builder_capacity(count));
        builders.extend(bytes.chunks_exact(BUILDER_SSZ).map(|s| Builder {
            pubkey: s[0..48].try_into().unwrap(),
            version: s[48],
            execution_address: s[49..69].try_into().unwrap(),
            balance: u64::from_le_bytes(s[69..77].try_into().unwrap()),
            deposit_epoch: u64::from_le_bytes(s[77..85].try_into().unwrap()),
            withdrawable_epoch: u64::from_le_bytes(s[85..93].try_into().unwrap()),
        }));

        Ok(Self { builders })
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.len() * BUILDER_SSZ
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
        self.builders.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.builders.is_empty()
    }

    #[inline]
    pub(super) fn get(&self, i: usize) -> Option<&Builder> {
        self.builders.get(i)
    }

    #[inline]
    pub(super) fn as_slice(&self) -> &[Builder] {
        &self.builders
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.builders.capacity()
    }

    pub(super) fn ensure_capacity(&mut self, end: usize) {
        if end > self.builders.capacity() {
            self.builders.grow_to(builder_capacity(end));
        }
    }
}
