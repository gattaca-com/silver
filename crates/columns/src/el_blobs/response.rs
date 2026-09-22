use silver_common::{
    MAX_BLOBS_PER_BLOCK,
    ssz_view::{BYTES_PER_KZG_PROOF, NUMBER_OF_COLUMNS},
};

#[derive(Clone, Copy)]
pub(super) struct BlobEntry<'a> {
    blob: &'a [u8],
    pub(super) proofs: &'a [u8],
}

impl BlobEntry<'_> {
    pub(super) fn compute_cells(self) -> Option<Box<[c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB]>> {
        let blob = match c_kzg::Blob::from_bytes(self.blob) {
            Ok(blob) => blob,
            Err(error) => {
                tracing::error!(?error, "el blob decode failed");
                return None;
            }
        };
        match c_kzg::ethereum_kzg_settings(0).compute_cells(&blob) {
            Ok(cells) => Some(cells),
            Err(error) => {
                tracing::error!(?error, "compute_cells failed");
                None
            }
        }
    }
}

pub(super) struct BlobResponse<'a> {
    entries: [Option<BlobEntry<'a>>; MAX_BLOBS_PER_BLOCK],
    count: usize,
    present: usize,
}

impl<'a> BlobResponse<'a> {
    pub(super) fn parse(mut bytes: &'a [u8], expected: usize) -> Option<Self> {
        if expected > MAX_BLOBS_PER_BLOCK {
            return None;
        }
        let (count, remaining) = bytes.split_first_chunk::<4>()?;
        bytes = remaining;
        let count = u32::from_le_bytes(*count) as usize;
        let mut response =
            Self { entries: [None; MAX_BLOBS_PER_BLOCK], count: expected, present: 0 };
        // A null JSON result is encoded as a zero-length list.
        if count == 0 && bytes.is_empty() {
            return Some(response);
        }
        if count != expected {
            return None;
        }
        for entry in &mut response.entries[..count] {
            let (&present, remaining) = bytes.split_first()?;
            bytes = remaining;
            if present == 0 {
                continue;
            }
            if present != 1 {
                return None;
            }
            let (&proof_count, remaining) = bytes.split_first()?;
            bytes = remaining;
            if proof_count as usize != NUMBER_OF_COLUMNS {
                return None;
            }
            let (proofs, remaining) =
                bytes.split_at_checked(NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF)?;
            let (length, remaining) = remaining.split_first_chunk::<4>()?;
            let length = u32::from_le_bytes(*length) as usize;
            if length != c_kzg::BYTES_PER_BLOB {
                return None;
            }
            let (blob, remaining) = remaining.split_at_checked(length)?;
            bytes = remaining;
            *entry = Some(BlobEntry { blob, proofs });
            response.present += 1;
        }
        bytes.is_empty().then_some(response)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.present == self.count
    }

    pub(super) fn present(&self) -> impl Iterator<Item = (usize, BlobEntry<'a>)> + '_ {
        self.entries[..self.count]
            .iter()
            .enumerate()
            .filter_map(|(row, entry)| Some((row, (*entry)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(rows: &[bool]) -> Vec<u8> {
        let mut bytes = (rows.len() as u32).to_le_bytes().to_vec();
        for (row, &present) in rows.iter().enumerate() {
            bytes.push(u8::from(present));
            if present {
                bytes.push(NUMBER_OF_COLUMNS as u8);
                bytes.resize(bytes.len() + NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF, row as u8);
                bytes.extend_from_slice(&(c_kzg::BYTES_PER_BLOB as u32).to_le_bytes());
                bytes.resize(bytes.len() + c_kzg::BYTES_PER_BLOB, row as u8);
            }
        }
        bytes
    }

    #[test]
    fn missing_entries_preserve_blob_rows() {
        let bytes = frame(&[true, false, true]);
        let response = BlobResponse::parse(&bytes, 3).unwrap();
        assert!(!response.is_complete());
        assert_eq!(
            response
                .present()
                .map(|(row, entry)| (row, entry.blob[0], entry.proofs[0]))
                .collect::<Vec<_>>(),
            [(0, 0, 0), (2, 2, 2)]
        );
        assert!(BlobResponse::parse(&frame(&[true, true]), 2).unwrap().is_complete());
        assert_eq!(BlobResponse::parse(&frame(&[false, false]), 2).unwrap().present().count(), 0);
        assert_eq!(BlobResponse::parse(&0u32.to_le_bytes(), 2).unwrap().present().count(), 0);
    }

    #[test]
    fn malformed_frames_are_rejected_before_exposing_entries() {
        let bytes = frame(&[true, false]);
        for end in [0, 3, 4, 5, 6, 100, bytes.len() - 1] {
            assert!(BlobResponse::parse(&bytes[..end], 2).is_none());
        }
        assert!(BlobResponse::parse(&bytes, 1).is_none());
        assert!(BlobResponse::parse(&bytes, MAX_BLOBS_PER_BLOCK + 1).is_none());
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(BlobResponse::parse(&bad, 2).is_none());
        let mut bad = bytes.clone();
        bad[4] = 2;
        assert!(BlobResponse::parse(&bad, 2).is_none());
        let mut bad = bytes.clone();
        bad[5] -= 1;
        assert!(BlobResponse::parse(&bad, 2).is_none());
        let mut bad = bytes;
        bad[6 + NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF] ^= 1;
        assert!(BlobResponse::parse(&bad, 2).is_none());
    }
}
