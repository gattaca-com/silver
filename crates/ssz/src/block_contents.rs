use crate::ssz_view::{
    BYTES_PER_BLOB, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, BeaconBlockBodyFuluView,
    NUMBER_OF_COLUMNS, SignedBeaconBlockView,
};

/// Offsets of `signed_block`, `kzg_proofs` and `blobs`.
const SIGNED_BLOCK_CONTENTS_FIXED: usize = 3 * 4;
const CELL_PROOFS_PER_BLOB: usize = NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF;

/// A Fulu `SignedBlockContents`: the signed block with every blob and its
/// cell proofs.
pub struct SignedBlockContents<'a> {
    pub signed_block: &'a [u8],
    pub kzg_proofs: &'a [u8],
    pub blobs: &'a [u8],
}

impl<'a> SignedBlockContents<'a> {
    /// Accepts only contents whose proofs and blobs match the block's
    /// commitments, one blob and `NUMBER_OF_COLUMNS` proofs per commitment.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let [block_at, proofs_at, blobs_at] = Self::offsets(buf)?;
        if block_at != SIGNED_BLOCK_CONTENTS_FIXED ||
            block_at > proofs_at ||
            proofs_at > blobs_at ||
            blobs_at > buf.len()
        {
            return None;
        }
        let contents = Self {
            signed_block: &buf[block_at..proofs_at],
            kzg_proofs: &buf[proofs_at..blobs_at],
            blobs: &buf[blobs_at..],
        };
        let blobs = contents.commitment_count()?;
        (contents.kzg_proofs.len() == blobs * CELL_PROOFS_PER_BLOB &&
            contents.blobs.len() == blobs * BYTES_PER_BLOB)
            .then_some(contents)
    }

    /// The signed block of contents [`Self::parse`] already accepted.
    pub fn signed_block(buf: &'a [u8]) -> Option<&'a [u8]> {
        let [block_at, proofs_at, _] = Self::offsets(buf)?;
        buf.get(block_at..proofs_at)
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.len() / BYTES_PER_BLOB
    }

    pub fn blob(&self, index: usize) -> &'a [u8; BYTES_PER_BLOB] {
        self.blobs[index * BYTES_PER_BLOB..(index + 1) * BYTES_PER_BLOB]
            .try_into()
            .expect("BYTES_PER_BLOB bytes")
    }

    pub fn cell_proofs(&self, index: usize) -> &'a [u8] {
        &self.kzg_proofs[index * CELL_PROOFS_PER_BLOB..(index + 1) * CELL_PROOFS_PER_BLOB]
    }

    fn offsets(buf: &[u8]) -> Option<[usize; 3]> {
        let fixed = buf.get(..SIGNED_BLOCK_CONTENTS_FIXED)?;
        Some(std::array::from_fn(|i| {
            u32::from_le_bytes(fixed[4 * i..4 * i + 4].try_into().expect("4 bytes")) as usize
        }))
    }

    fn commitment_count(&self) -> Option<usize> {
        if !SignedBeaconBlockView::check_size(self.signed_block) {
            return None;
        }
        let body = SignedBeaconBlockView::body(self.signed_block);
        let commitments = BeaconBlockBodyFuluView::blob_kzg_commitments(body)?.len();
        commitments
            .is_multiple_of(BYTES_PER_KZG_COMMITMENT)
            .then_some(commitments / BYTES_PER_KZG_COMMITMENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssz_view::BEACON_BLOCK_BODY_FIXED;

    /// A signed block whose body commits to `blobs` blobs and holds nothing
    /// else.
    fn signed_block(blobs: usize) -> Vec<u8> {
        let mut block = vec![0; 184 + BEACON_BLOCK_BODY_FIXED];
        block[..4].copy_from_slice(&100u32.to_le_bytes());
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        let body = &mut block[184..];
        let end = (BEACON_BLOCK_BODY_FIXED + blobs * BYTES_PER_KZG_COMMITMENT) as u32;
        for at in [200, 204, 208, 212, 216, 380, 384, 388] {
            body[at..at + 4].copy_from_slice(&(BEACON_BLOCK_BODY_FIXED as u32).to_le_bytes());
        }
        body[392..396].copy_from_slice(&end.to_le_bytes());
        block.resize(block.len() + blobs * BYTES_PER_KZG_COMMITMENT, 0);
        block
    }

    fn contents(block: &[u8], proofs: usize, blobs: usize) -> Vec<u8> {
        let proofs_at = SIGNED_BLOCK_CONTENTS_FIXED + block.len();
        let blobs_at = proofs_at + proofs;
        let mut out = Vec::new();
        for at in [SIGNED_BLOCK_CONTENTS_FIXED, proofs_at, blobs_at] {
            out.extend_from_slice(&(at as u32).to_le_bytes());
        }
        out.extend_from_slice(block);
        out.resize(blobs_at + blobs, 0);
        out
    }

    #[test]
    fn contents_matching_the_commitments_parse() {
        let block = signed_block(2);
        let bytes = contents(&block, 2 * CELL_PROOFS_PER_BLOB, 2 * BYTES_PER_BLOB);
        let parsed = SignedBlockContents::parse(&bytes).unwrap();
        assert_eq!(parsed.signed_block, block);
        assert_eq!(parsed.blob_count(), 2);
        assert_eq!(SignedBlockContents::signed_block(&bytes), Some(block.as_slice()));
    }

    #[test]
    fn contents_disagreeing_with_the_commitments_are_refused() {
        let block = signed_block(2);
        for (proofs, blobs) in [
            (CELL_PROOFS_PER_BLOB, 2 * BYTES_PER_BLOB),
            (2 * CELL_PROOFS_PER_BLOB, BYTES_PER_BLOB),
            (2 * BYTES_PER_KZG_PROOF, 2 * BYTES_PER_BLOB),
        ] {
            assert!(SignedBlockContents::parse(&contents(&block, proofs, blobs)).is_none());
        }
        assert!(SignedBlockContents::parse(&[0; 8]).is_none());
    }
}
