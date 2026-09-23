use silver_beacon_state_data::ForkName;

use super::CommitmentContext;
use crate::ssz_view::{
    BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, DATA_COLUMN_SIDECAR_GLOAS_MIN,
    DATA_COLUMN_SIDECAR_MIN, DataColumnSidecarFuluView, partial_column::PARTIAL_HEADER_FIXED,
};

#[derive(Clone, Copy)]
pub enum ContextData<'a> {
    Fulu { signed_header: &'a [u8; 208], inclusion_proof: &'a [u8; 128], commitments: &'a [u8] },
    Gloas { commitments: &'a [u8] },
}

impl<'a> ContextData<'a> {
    pub fn column_prefix(
        self,
        context: CommitmentContext,
        column: usize,
    ) -> ([u8; DATA_COLUMN_SIDECAR_MIN], usize) {
        let mut prefix = [0; DATA_COLUMN_SIDECAR_MIN];
        prefix[..8].copy_from_slice(&(column as u64).to_le_bytes());
        let length = match self {
            Self::Fulu { signed_header, inclusion_proof, .. } => {
                prefix[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(
                    &((DATA_COLUMN_SIDECAR_MIN + context.blob_count * BYTES_PER_CELL) as u32)
                        .to_le_bytes(),
                );
                prefix[16..20].copy_from_slice(
                    &((DATA_COLUMN_SIDECAR_MIN +
                        context.blob_count * (BYTES_PER_CELL + BYTES_PER_KZG_COMMITMENT))
                        as u32)
                        .to_le_bytes(),
                );
                prefix[20..228].copy_from_slice(signed_header);
                prefix[228..356].copy_from_slice(inclusion_proof);
                DATA_COLUMN_SIDECAR_MIN
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
                DATA_COLUMN_SIDECAR_GLOAS_MIN
            }
        };
        (prefix, length)
    }

    #[inline]
    pub fn from_fulu_sidecar(bytes: &'a [u8]) -> Option<Self> {
        if !DataColumnSidecarFuluView::check_size(bytes) {
            return None;
        }
        Some(Self::Fulu {
            signed_header: bytes.get(20..228)?.try_into().ok()?,
            inclusion_proof: DataColumnSidecarFuluView::inclusion_proof(bytes),
            commitments: DataColumnSidecarFuluView::kzg_commitments(bytes),
        })
    }

    #[inline]
    pub fn valid_for(self, context: CommitmentContext) -> bool {
        let format_matches = match self {
            Self::Fulu { signed_header, .. } => {
                context.format == ForkName::Fulu && signed_header[..8] == context.slot.to_le_bytes()
            }
            Self::Gloas { .. } => context.format == ForkName::Gloas,
        };
        format_matches && self.commitments().len() == context.blob_count * BYTES_PER_KZG_COMMITMENT
    }

    #[inline]
    pub fn commitments(self) -> &'a [u8] {
        match self {
            Self::Fulu { commitments, .. } | Self::Gloas { commitments } => commitments,
        }
    }

    /// Inverse of [`Self::write`]: borrow the components back out of an encoded
    /// buffer. `None` if a Fulu buffer is shorter than the fixed header.
    #[inline]
    pub fn from_encoded(bytes: &'a [u8], format: ForkName) -> Option<Self> {
        match format {
            ForkName::Fulu => {
                if bytes.len() < PARTIAL_HEADER_FIXED {
                    return None;
                }
                Some(Self::Fulu {
                    signed_header: bytes[4..212].try_into().ok()?,
                    inclusion_proof: bytes[212..PARTIAL_HEADER_FIXED].try_into().ok()?,
                    commitments: &bytes[PARTIAL_HEADER_FIXED..],
                })
            }
            ForkName::Gloas => Some(Self::Gloas { commitments: bytes }),
            _ => None,
        }
    }

    /// A Fulu context is stored as PartialDataColumnHeader SSZ, so it can
    /// later be referenced verbatim as a partial frame's header ranges.
    #[inline]
    pub fn encoded_len(self) -> usize {
        self.commitments().len() +
            if matches!(self, Self::Fulu { .. }) { PARTIAL_HEADER_FIXED } else { 0 }
    }

    #[inline]
    pub fn write(self, out: &mut [u8]) {
        match self {
            Self::Fulu { signed_header, inclusion_proof, commitments } => {
                out[..4].copy_from_slice(&(PARTIAL_HEADER_FIXED as u32).to_le_bytes());
                out[4..212].copy_from_slice(signed_header);
                out[212..PARTIAL_HEADER_FIXED].copy_from_slice(inclusion_proof);
                out[PARTIAL_HEADER_FIXED..].copy_from_slice(commitments);
            }
            Self::Gloas { commitments } => out.copy_from_slice(commitments),
        }
    }

    #[inline]
    pub fn matches(self, bytes: &[u8]) -> bool {
        if bytes.len() != self.encoded_len() {
            return false;
        }
        match self {
            Self::Fulu { signed_header, inclusion_proof, commitments } => {
                bytes[..4] == (PARTIAL_HEADER_FIXED as u32).to_le_bytes() &&
                    bytes[4..212] == *signed_header &&
                    bytes[212..PARTIAL_HEADER_FIXED] == *inclusion_proof &&
                    bytes[PARTIAL_HEADER_FIXED..] == *commitments
            }
            Self::Gloas { commitments } => bytes == commitments,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_encoded_inverts_write() {
        let header = [7u8; 208];
        let proof = [9u8; 128];
        let commitments = [3u8; 96];

        let fulu = ContextData::Fulu {
            signed_header: &header,
            inclusion_proof: &proof,
            commitments: &commitments,
        };
        let mut buf = vec![0u8; fulu.encoded_len()];
        fulu.write(&mut buf);
        match ContextData::from_encoded(&buf, ForkName::Fulu).unwrap() {
            ContextData::Fulu { signed_header, inclusion_proof, commitments: c } => {
                assert_eq!(signed_header, &header);
                assert_eq!(inclusion_proof, &proof);
                assert_eq!(c, &commitments);
            }
            ContextData::Gloas { .. } => panic!("expected Fulu"),
        }

        let gloas = ContextData::Gloas { commitments: &commitments };
        let mut buf = vec![0u8; gloas.encoded_len()];
        gloas.write(&mut buf);
        match ContextData::from_encoded(&buf, ForkName::Gloas).unwrap() {
            ContextData::Gloas { commitments: c } => assert_eq!(c, &commitments),
            ContextData::Fulu { .. } => panic!("expected Gloas"),
        }

        assert!(ContextData::from_encoded(&[0u8; 8], ForkName::Fulu).is_none());
    }
}
