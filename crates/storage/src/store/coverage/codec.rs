use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind, Read, Write},
    path::Path,
};

use silver_common::merkle::B256;

use super::{
    Coverage, Missing,
    chain::{Chain, Span},
};
use crate::store::io::{open_file_read, open_file_write};

const FILE_NAME: &str = "coverage.bin";

pub(super) fn load(store_dir: &str, custody: u128) -> Result<Option<Coverage>, Error> {
    let mut file = match open_file_read(Path::new(store_dir).join(FILE_NAME)) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let decoded = decode(&bytes, custody);
    if decoded.is_none() {
        tracing::info!("coverage file not usable; rebuilding from the block files");
    }
    Ok(decoded)
}

/// Written after the data it describes, so a crash leaves it behind the
/// disk and never ahead of it.
pub(super) fn persist(
    coverage: &Coverage,
    store_dir: &str,
    scratch: &mut Vec<u8>,
) -> Result<(), Error> {
    scratch.clear();
    encode(coverage, scratch);
    let path = Path::new(store_dir).join(FILE_NAME);
    let staged = Path::new(store_dir).join(format!("{FILE_NAME}.partial"));
    open_file_write(&staged, false)?.write_all(scratch)?;
    std::fs::rename(&staged, &path)
}

fn encode(coverage: &Coverage, out: &mut Vec<u8>) {
    out.extend_from_slice(&coverage.custody.to_le_bytes());
    out.extend_from_slice(&coverage.examined_below.to_le_bytes());
    out.extend_from_slice(&(coverage.chain.spans().len() as u32).to_le_bytes());
    for span in coverage.chain.spans() {
        out.extend_from_slice(&span.from.to_le_bytes());
        out.extend_from_slice(&span.to.to_le_bytes());
        out.extend_from_slice(&span.wanted_parent);
        out.extend_from_slice(&span.wanted_payload);
    }
    out.extend_from_slice(&(coverage.missing.len() as u32).to_le_bytes());
    for (slot, missing) in &coverage.missing {
        out.extend_from_slice(&slot.to_le_bytes());
        out.extend_from_slice(&missing.columns.to_le_bytes());
        out.push(missing.envelope as u8);
    }
}

fn decode(bytes: &[u8], custody: u128) -> Option<Coverage> {
    let mut cursor = Cursor { bytes, at: 0 };
    let persisted = cursor.u128()?;
    if persisted != custody {
        tracing::info!(
            persisted = format_args!("{persisted:#x}"),
            current = format_args!("{custody:#x}"),
            "custody changed since coverage was written"
        );
        return None;
    }
    let examined_below = cursor.u64()?;
    let mut spans = Vec::new();
    for _ in 0..cursor.u32()? {
        spans.push(Span {
            from: cursor.u64()?,
            to: cursor.u64()?,
            wanted_parent: cursor.b256()?,
            wanted_payload: cursor.b256()?,
        });
    }
    let mut missing = BTreeMap::new();
    for _ in 0..cursor.u32()? {
        let slot = cursor.u64()?;
        let entry = Missing { columns: cursor.u128()?, envelope: cursor.take(1)?[0] != 0 };
        missing.insert(slot, entry);
    }
    let well_formed = cursor.at == bytes.len() &&
        spans.iter().all(|span| span.from <= span.to) &&
        spans.windows(2).all(|pair| pair[0].to < pair[1].from);
    if !well_formed {
        tracing::warn!("coverage file malformed");
        return None;
    }
    Some(Coverage {
        custody,
        chain: Chain::from_ascending(spans),
        missing,
        examined_below,
        version: 0,
        persisted: 0,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let out = self.bytes.get(self.at..self.at + len)?;
        self.at += len;
        Some(out)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }

    fn u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.take(16)?.try_into().expect("16")))
    }

    fn b256(&mut self) -> Option<B256> {
        Some(self.take(32)?.try_into().expect("32"))
    }
}
