//! Decoded commitments of recent batches. The sidecars of one block carry the
//! same commitments, so only the first column of a block decodes them.

use crate::bls::{COMPRESSED_LEN, blst_p1_affine, uncompress_in_g1};

const CAPACITY: usize = 256;

#[derive(Default)]
pub struct CommitmentCache {
    entries: Vec<([u8; COMPRESSED_LEN], blst_p1_affine)>,
    next_eviction: usize,
    missing: Vec<usize>,
    missing_keys: Vec<[u8; COMPRESSED_LEN]>,
    decoded: Vec<Option<blst_p1_affine>>,
}

impl CommitmentCache {
    /// The point of each of `unique`, in order. False if any is not a valid G1
    /// point; invalid encodings are never cached.
    pub fn decode(
        &mut self,
        unique: &[[u8; COMPRESSED_LEN]],
        out: &mut Vec<blst_p1_affine>,
    ) -> bool {
        out.clear();
        self.missing.clear();
        self.missing_keys.clear();
        for (i, key) in unique.iter().enumerate() {
            match self.entries.iter().find(|(cached, _)| cached == key) {
                Some((_, point)) => out.push(*point),
                None => {
                    out.push(blst_p1_affine::default());
                    self.missing.push(i);
                    self.missing_keys.push(*key);
                }
            }
        }
        if self.missing.is_empty() {
            return true;
        }

        self.decoded.clear();
        self.decoded.resize(self.missing.len(), None);
        uncompress_in_g1(&self.missing_keys, &mut self.decoded);
        let mut all_valid = true;
        for (slot, decoded) in self.decoded.iter().enumerate() {
            match decoded {
                Some(point) => {
                    out[self.missing[slot]] = *point;
                    let entry = (self.missing_keys[slot], *point);
                    if self.entries.len() < CAPACITY {
                        self.entries.push(entry);
                    } else {
                        self.entries[self.next_eviction] = entry;
                        self.next_eviction = (self.next_eviction + 1) % CAPACITY;
                    }
                }
                None => all_valid = false,
            }
        }
        all_valid
    }
}

#[cfg(test)]
mod tests {
    use blst::{
        blst_p1, blst_p1_add_or_double_affine, blst_p1_affine_compress, blst_p1_affine_generator,
        blst_p1_from_affine, blst_p1_to_affine,
    };

    use super::*;

    /// Distinct valid encodings: 1·G, 2·G, ...
    fn valid_encodings(count: usize) -> Vec<[u8; COMPRESSED_LEN]> {
        // SAFETY: blst returns a pointer to its static generator.
        let generator = unsafe { *blst_p1_affine_generator() };
        let mut point = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_from_affine(&mut point, &generator) };
        (0..count)
            .map(|_| {
                let mut affine = blst_p1_affine::default();
                let mut bytes = [0u8; COMPRESSED_LEN];
                // SAFETY: valid pointers; blst writes 48 bytes.
                unsafe {
                    blst_p1_to_affine(&mut affine, &point);
                    blst_p1_affine_compress(bytes.as_mut_ptr(), &affine);
                    let current = point;
                    blst_p1_add_or_double_affine(&mut point, &current, &generator);
                }
                bytes
            })
            .collect()
    }

    fn invalid_encoding() -> [u8; COMPRESSED_LEN] {
        let mut bytes = valid_encodings(1)[0];
        bytes[47] ^= 1;
        bytes
    }

    #[test]
    fn a_hit_returns_the_decoded_point() {
        let keys = valid_encodings(5);
        let mut cache = CommitmentCache::default();
        let (mut first, mut second) = (Vec::new(), Vec::new());
        assert!(cache.decode(&keys, &mut first));
        assert_eq!(cache.entries.len(), 5);
        let mut reordered = keys.clone();
        reordered.reverse();
        assert!(cache.decode(&reordered, &mut second));
        assert_eq!(cache.entries.len(), 5, "no miss, no new entry");
        first.reverse();
        assert!(first == second);
    }

    #[test]
    fn invalid_encodings_fail_and_are_not_cached() {
        let valid = valid_encodings(3);
        let invalid = invalid_encoding();
        let mut cache = CommitmentCache::default();
        let mut out = Vec::new();
        let batch = [valid[0], invalid, valid[1]];
        assert!(!cache.decode(&batch, &mut out));
        assert!(cache.entries.iter().all(|(key, _)| *key != invalid));
        assert!(!cache.decode(&batch, &mut out), "still rejected on the second call");
        assert!(cache.decode(&valid, &mut out));
    }

    #[test]
    fn the_oldest_entries_are_evicted() {
        let keys = valid_encodings(CAPACITY + 3);
        let mut cache = CommitmentCache::default();
        let mut out = Vec::new();
        assert!(cache.decode(&keys[..CAPACITY], &mut out));
        assert!(cache.decode(&keys[CAPACITY..], &mut out));
        assert_eq!(cache.entries.len(), CAPACITY);
        let cached = |key: &[u8; COMPRESSED_LEN]| cache.entries.iter().any(|(k, _)| k == key);
        assert!(keys[..3].iter().all(|key| !cached(key)));
        assert!(keys[3..].iter().all(cached));

        let mut again = Vec::new();
        assert!(cache.decode(&keys, &mut again), "evicted keys decode again");
        let mut fresh = Vec::new();
        assert!(CommitmentCache::default().decode(&keys, &mut fresh));
        assert!(again == fresh);
    }
}
