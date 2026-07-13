use std::{fs::create_dir_all, io::Error, path::Path};

use silver_common::TRead;

use super::{Payload, io};

mod blocks;
mod columns;
mod envelopes;

pub(super) use blocks::UnfinalizedBlocks;
pub(super) use columns::{UnfinalizedColumns, columns_of};
pub(super) use envelopes::UnfinalizedEnvelopes;

#[derive(Debug)]
pub(super) enum PayloadSsz {
    Ref(TRead),
    Owned(Vec<u8>),
}

impl PayloadSsz {
    pub(super) fn bytes(&self) -> Result<&[u8], Error> {
        match self {
            PayloadSsz::Ref(ssz) => Ok(ssz.buffer().map_err(Error::other)?.0),
            PayloadSsz::Owned(ssz) => Ok(ssz),
        }
    }
}

#[derive(Debug)]
pub(super) enum PayloadKey {
    Block { parent_root: [u8; 32], block_root: [u8; 32] },
    Column { block_root: [u8; 32], column: u64 },
    Envelope { block_root: [u8; 32] },
}

impl PayloadKey {
    pub(super) fn payload(&self) -> Payload {
        match self {
            PayloadKey::Block { .. } => Payload::Block,
            PayloadKey::Column { .. } => Payload::Column,
            PayloadKey::Envelope { .. } => Payload::Envelope,
        }
    }

    pub(super) fn unfinalized_name(&self, slot: u64) -> String {
        match self {
            PayloadKey::Block { parent_root, block_root } => {
                io::unfinalized_name(slot, parent_root, block_root)
            }
            PayloadKey::Column { block_root, column } => {
                io::unfinalized_column_name(slot, block_root, *column)
            }
            PayloadKey::Envelope { block_root } => io::unfinalized_envelope_name(slot, block_root),
        }
    }

    pub(super) fn finalized_name(&self, slot: u64) -> String {
        match self {
            PayloadKey::Block { .. } => format!("{slot}_block.ssz"),
            PayloadKey::Column { column, .. } => format!("{slot}_{column}.ssz"),
            PayloadKey::Envelope { .. } => format!("{slot}_envelope.ssz"),
        }
    }
}

fn read_unfinalized_dir(dir: &Path, mut visit: impl FnMut(&str)) -> Result<(), Error> {
    create_dir_all(dir)?;
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        if let Some(name) = name.to_str() {
            visit(name);
        }
    }
    Ok(())
}
