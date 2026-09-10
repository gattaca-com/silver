use silver_beacon_state_data::ForkName;
use silver_common::{
    SubLayout, SubReservationError, SubReservationRef, TProducer,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        DATA_COLUMN_SIDECAR_GLOAS_MIN, DATA_COLUMN_SIDECAR_MIN, DataColumnSidecarFuluView,
        DataColumnSidecarGloasView,
    },
};

use crate::BlockRoot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitmentContext {
    pub block_root: BlockRoot,
    pub slot: u64,
    pub format: ForkName,
    pub blob_count: usize,
}

impl CommitmentContext {
    pub(super) fn full_offsets(
        self,
        bytes: &[u8],
        context: &[u8],
        column: usize,
    ) -> Option<(usize, usize)> {
        let rows = self.blob_count;
        match self.format {
            ForkName::Fulu => {
                if !DataColumnSidecarFuluView::check_size(bytes) ||
                    DataColumnSidecarFuluView::index(bytes) != column as u64 ||
                    DataColumnSidecarFuluView::column(bytes).len() != rows * BYTES_PER_CELL ||
                    DataColumnSidecarFuluView::kzg_commitments(bytes).len() !=
                        rows * BYTES_PER_KZG_COMMITMENT ||
                    DataColumnSidecarFuluView::kzg_proofs(bytes).len() !=
                        rows * BYTES_PER_KZG_PROOF ||
                    bytes[20..356] != context[4..340] ||
                    DataColumnSidecarFuluView::kzg_commitments(bytes) != &context[340..]
                {
                    return None;
                }
                Some((
                    DATA_COLUMN_SIDECAR_MIN,
                    DATA_COLUMN_SIDECAR_MIN + rows * (BYTES_PER_CELL + BYTES_PER_KZG_COMMITMENT),
                ))
            }
            ForkName::Gloas => {
                if !DataColumnSidecarGloasView::check_size(bytes) ||
                    DataColumnSidecarGloasView::index(bytes) != column as u64 ||
                    DataColumnSidecarGloasView::slot(bytes) != self.slot ||
                    DataColumnSidecarGloasView::beacon_block_root(bytes) != &self.block_root ||
                    DataColumnSidecarGloasView::column(bytes).len() != rows * BYTES_PER_CELL ||
                    DataColumnSidecarGloasView::kzg_proofs(bytes).len() !=
                        rows * BYTES_PER_KZG_PROOF
                {
                    return None;
                }
                Some((
                    DATA_COLUMN_SIDECAR_GLOAS_MIN,
                    DATA_COLUMN_SIDECAR_GLOAS_MIN + rows * BYTES_PER_CELL,
                ))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ContextData<'a> {
    Fulu { signed_header: &'a [u8; 208], inclusion_proof: &'a [u8; 128], commitments: &'a [u8] },
    Gloas { commitments: &'a [u8] },
}

impl<'a> ContextData<'a> {
    pub(super) fn valid_for(self, context: CommitmentContext) -> bool {
        let format_matches = match self {
            Self::Fulu { signed_header, .. } => {
                context.format == ForkName::Fulu && signed_header[..8] == context.slot.to_le_bytes()
            }
            Self::Gloas { .. } => context.format == ForkName::Gloas,
        };
        format_matches && self.commitments().len() == context.blob_count * BYTES_PER_KZG_COMMITMENT
    }

    fn commitments(self) -> &'a [u8] {
        match self {
            Self::Fulu { commitments, .. } | Self::Gloas { commitments } => commitments,
        }
    }

    pub(super) fn encoded_len(self) -> usize {
        self.commitments().len() + if matches!(self, Self::Fulu { .. }) { 340 } else { 0 }
    }

    pub(super) fn write(self, out: &mut [u8]) {
        match self {
            Self::Fulu { signed_header, inclusion_proof, commitments } => {
                out[..4].copy_from_slice(&340u32.to_le_bytes());
                out[4..212].copy_from_slice(signed_header);
                out[212..340].copy_from_slice(inclusion_proof);
                out[340..].copy_from_slice(commitments);
            }
            Self::Gloas { commitments } => out.copy_from_slice(commitments),
        }
    }

    pub(super) fn matches(self, bytes: &[u8]) -> bool {
        if bytes.len() != self.encoded_len() {
            return false;
        }
        match self {
            Self::Fulu { signed_header, inclusion_proof, commitments } => {
                bytes[..4] == 340u32.to_le_bytes() &&
                    bytes[4..212] == *signed_header &&
                    bytes[212..340] == *inclusion_proof &&
                    bytes[340..] == *commitments
            }
            Self::Gloas { commitments } => bytes == commitments,
        }
    }

    pub(super) fn reserve_column(
        self,
        context: CommitmentContext,
        column: usize,
        producer: &mut TProducer,
    ) -> Result<SubReservationRef, SubReservationError> {
        let layout = SubLayout {
            parts: context.blob_count,
            first_len: BYTES_PER_CELL,
            second_len: BYTES_PER_KZG_PROOF,
        };
        let mut prefix = [0; DATA_COLUMN_SIDECAR_MIN];
        prefix[..8].copy_from_slice(&(column as u64).to_le_bytes());
        let (length, middle) = match self {
            Self::Fulu { signed_header, inclusion_proof, commitments } => {
                let cells_end = DATA_COLUMN_SIDECAR_MIN + context.blob_count * BYTES_PER_CELL;
                prefix[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(&(cells_end as u32).to_le_bytes());
                prefix[16..20]
                    .copy_from_slice(&((cells_end + commitments.len()) as u32).to_le_bytes());
                prefix[20..228].copy_from_slice(signed_header);
                prefix[228..356].copy_from_slice(inclusion_proof);
                (DATA_COLUMN_SIDECAR_MIN, commitments)
            }
            Self::Gloas { .. } => {
                prefix[8..12]
                    .copy_from_slice(&(DATA_COLUMN_SIDECAR_GLOAS_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(
                    &((DATA_COLUMN_SIDECAR_GLOAS_MIN + context.blob_count * BYTES_PER_CELL) as u32)
                        .to_le_bytes(),
                );
                prefix[16..24].copy_from_slice(&context.slot.to_le_bytes());
                prefix[24..56].copy_from_slice(&context.block_root);
                (DATA_COLUMN_SIDECAR_GLOAS_MIN, &[][..])
            }
        };
        producer.sub_reservation(layout, &prefix[..length], middle)
    }
}
