use crate::ssz_view::{
    BYTES_PER_BLOB, BYTES_PER_KZG_PROOF, NUMBER_OF_COLUMNS, SignedExecutionPayloadEnvelopeView,
};

pub struct SignedEnvelopeContents<'a> {
    pub signed_envelope: &'a [u8],
    pub kzg_proofs: &'a [u8],
    pub blobs: &'a [u8],
}

impl<'a> SignedEnvelopeContents<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let fixed = bytes.get(..12)?;
        let offset =
            |at| u32::from_le_bytes(fixed[at..at + 4].try_into().expect("4 bytes")) as usize;
        let [envelope_at, proofs_at, blobs_at] = [offset(0), offset(4), offset(8)];
        if envelope_at != 12 || envelope_at > proofs_at || proofs_at > blobs_at {
            return None;
        }
        let contents = Self {
            signed_envelope: bytes.get(envelope_at..proofs_at)?,
            kzg_proofs: bytes.get(proofs_at..blobs_at)?,
            blobs: bytes.get(blobs_at..)?,
        };
        (SignedExecutionPayloadEnvelopeView::check_canonical(contents.signed_envelope) &&
            contents.blobs.len().is_multiple_of(BYTES_PER_BLOB) &&
            contents.kzg_proofs.len() ==
                contents.blob_count() * NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF)
            .then_some(contents)
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.len() / BYTES_PER_BLOB
    }
}
