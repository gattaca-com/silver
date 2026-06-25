use super::delta::BuildersDelta;
use crate::{
    DecomposeError,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder},
};

/// SSZ-serialised `Builder`: pubkey(48) + version(1) + execution_address(20) +
/// balance(8) + deposit_epoch(8) + withdrawable_epoch(8).
const BUILDER_SSZ: usize = 93;

#[derive(Default)]
pub struct FinalizedBuilders {
    builders: Vec<Builder>,
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
        let builders = (0..count)
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
        Ok(Self { builders })
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
    pub(super) fn as_slice(&self) -> &[Builder] {
        &self.builders
    }

    pub(super) fn promote(&mut self, delta: &BuildersDelta) {
        self.builders.extend(delta.appended().iter().cloned());
    }
}
