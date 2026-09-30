use crate::ssz_view::{
    BYTES_PER_BLOB, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, NUMBER_OF_COLUMNS,
};

/// The `engine_getPayloadV5` result as the engine tile frames it: a
/// [`Self::HEADER_LEN`] header, then the payload, commitments and requests
/// SSZ, then every blob's `NUMBER_OF_COLUMNS` cell proofs and the blobs. All
/// but the header is in `BlockContents` order, so a produced block's contents
/// splice in the payload and `after_payload` as they are.
pub struct PayloadFrame<'a> {
    pub execution_payload: &'a [u8],
    /// Commitments, requests, cell proofs and blobs: what follows the body's
    /// `bls_to_execution_changes` in `BlockContents`.
    pub after_payload: &'a [u8],
    pub blob_count: usize,
    pub commitments: &'a [u8],
    pub execution_requests: &'a [u8],
    pub block_value: [u8; 32],
}

impl<'a> PayloadFrame<'a> {
    pub const CELL_PROOFS_PER_BLOB_LEN: usize = NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF;
    /// Payload and requests lengths, blob count, `shouldOverrideBuilder` and
    /// the little-endian `blockValue`.
    pub const HEADER_LEN: usize = 4 + 4 + 1 + 1 + 32;

    pub fn write_header(
        header: &mut [u8],
        payload_len: usize,
        requests_len: usize,
        blob_count: u8,
        should_override_builder: bool,
        block_value: &[u8; 32],
    ) {
        header[..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        header[4..8].copy_from_slice(&(requests_len as u32).to_le_bytes());
        header[8] = blob_count;
        header[9] = should_override_builder as u8;
        header[10..Self::HEADER_LEN].copy_from_slice(block_value);
    }

    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let (header, rest) = frame.split_at_checked(Self::HEADER_LEN)?;
        let payload_len = u32::from_le_bytes(header[..4].try_into().expect("4 bytes")) as usize;
        let requests_len = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes")) as usize;
        let blob_count = header[8] as usize;
        let (execution_payload, after_payload) = rest.split_at_checked(payload_len)?;
        let (commitments, rest) =
            after_payload.split_at_checked(blob_count * BYTES_PER_KZG_COMMITMENT)?;
        let (execution_requests, cell_proofs_and_blobs) = rest.split_at_checked(requests_len)?;
        let tail_len = blob_count * (Self::CELL_PROOFS_PER_BLOB_LEN + BYTES_PER_BLOB);
        (cell_proofs_and_blobs.len() == tail_len).then_some(())?;
        Some(Self {
            execution_payload,
            after_payload,
            blob_count,
            commitments,
            execution_requests,
            block_value: header[10..].try_into().expect("32 bytes"),
        })
    }

    pub fn cell_proofs_len(&self) -> usize {
        self.blob_count * Self::CELL_PROOFS_PER_BLOB_LEN
    }
}
