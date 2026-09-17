use std::{
    io::{Cursor, Write},
    str,
    time::Instant,
};

use silver_common::{
    CacheFrameError, CacheFrameRef, CacheSegment, ForkName, TProducer,
    cell_store::{CellSource, ColumnAvailability},
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        partial_column::{
            PARTIAL_HEADER_FIXED, PartialLayout, PartialSidecarPlan, fulu_group_id, gloas_group_id,
        },
    },
};
use silver_gossip::{ColumnGroupKey, PartialFrame, PartsMetadata};

pub(super) struct PartialResponse {
    pub group: ColumnGroupKey,
    pub slot: u64,
    pub metadata: PartsMetadata,
    pub column: Option<ColumnAvailability>,
    pub rows: u128,
    pub header: bool,
}

impl PartialResponse {
    pub fn write(
        &self,
        producer: &mut TProducer,
        expires: Instant,
    ) -> Result<CacheFrameRef, CacheFrameError> {
        let mut topic = Cursor::new([0u8; 96]);
        let digest = self.group.domain.digest();
        write!(
            topic,
            "/eth2/{:02x}{:02x}{:02x}{:02x}/data_column_sidecar_{}/ssz_snappy",
            digest[0], digest[1], digest[2], digest[3], self.group.column
        )
        .unwrap();
        let topic = str::from_utf8(&topic.get_ref()[..topic.position() as usize]).unwrap();
        let fulu = self.group.domain.format() == ForkName::Fulu;
        let mut group = gloas_group_id(&self.group.block_root, self.slot);
        let group = if fulu {
            group[..33].copy_from_slice(&fulu_group_id(&self.group.block_root));
            &group[..33]
        } else {
            &group[..]
        };
        let header = self.header.then(|| self.column.and_then(|column| column.header)).flatten();
        if self.header && (!fulu || header.is_none()) {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        let header_bytes = if header.is_some() {
            PARTIAL_HEADER_FIXED + self.metadata.n_rows * BYTES_PER_KZG_COMMITMENT
        } else {
            0
        };
        let plan = if self.rows != 0 || header.is_some() {
            if self.column.is_none_or(|c| {
                self.rows & !c.available != 0 ||
                    (self.rows != 0 && c.full.is_none() && c.assembly.is_none())
            }) {
                return Err(CacheFrameError::InvalidDescriptor);
            }
            let layout =
                if fulu { PartialLayout::Fulu { header_bytes } } else { PartialLayout::Gloas };
            Some(
                PartialSidecarPlan::new(layout, self.rows, self.metadata.n_rows)
                    .ok_or(CacheFrameError::InvalidDescriptor)?,
            )
        } else {
            None
        };
        let frame = PartialFrame {
            topic,
            group_id: group,
            plan,
            header: header.map(|read| CacheSegment::DataColumns {
                read,
                offset: 0,
                length: header_bytes,
            }),
            metadata: Some(self.metadata),
        };
        frame.write(
            producer,
            CellSegments { column: self.column, rows: self.rows, proof: false },
            CellSegments { column: self.column, rows: self.rows, proof: true },
            expires,
        )
    }
}

#[derive(Clone)]
struct CellSegments {
    column: Option<ColumnAvailability>,
    rows: u128,
    proof: bool,
}

impl Iterator for CellSegments {
    type Item = CacheSegment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rows == 0 {
            return None;
        }
        let row = self.rows.trailing_zeros() as usize;
        self.rows &= self.rows - 1;
        let cell = self.column?.cell(row)?;
        let length = if self.proof { BYTES_PER_KZG_PROOF } else { BYTES_PER_CELL };
        Some(match cell.source {
            CellSource::Full { read, cell, proof } => CacheSegment::DataColumns {
                read,
                offset: if self.proof { proof } else { cell },
                length,
            },
            CellSource::Assembly { reservation, row } => CacheSegment::Shared {
                reservation,
                part: row,
                second: self.proof,
                offset: 0,
                length,
            },
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.rows.count_ones() as usize;
        (count, Some(count))
    }
}

impl ExactSizeIterator for CellSegments {}
