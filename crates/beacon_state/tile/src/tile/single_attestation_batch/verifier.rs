use silver_common::metrics::timed;

use super::PendingAttestation;
use crate::{bls::SameMessageBatch, tile::attestation_root_memo::AttestationRootGroup};

pub(super) struct EntryVerifier {
    batch: SameMessageBatch,
    buckets: [Vec<usize>; AttestationRootGroup::COUNT],
    touched: Vec<usize>,
    fallback: Vec<usize>,
    verdicts: Vec<bool>,
}

impl Default for EntryVerifier {
    fn default() -> Self {
        Self {
            batch: SameMessageBatch::default(),
            buckets: std::array::from_fn(|_| Vec::new()),
            touched: Vec::new(),
            fallback: Vec::new(),
            verdicts: Vec::new(),
        }
    }
}

impl EntryVerifier {
    #[timed]
    pub(super) fn verify(&mut self, entries: &[PendingAttestation]) -> Vec<bool> {
        self.clear(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            match entry.root_group {
                Some(group) => {
                    let group = group.index();
                    if self.buckets[group].is_empty() {
                        self.touched.push(group);
                    }
                    self.buckets[group].push(index);
                }
                None => self.fallback.push(index),
            }
        }
        for &group in &self.touched {
            Self::verify_groups(
                &mut self.batch,
                &mut self.verdicts,
                entries,
                &mut self.buckets[group],
            );
        }
        Self::verify_groups(&mut self.batch, &mut self.verdicts, entries, &mut self.fallback);
        std::mem::take(&mut self.verdicts)
    }

    pub(super) fn recycle_verdicts(&mut self, mut verdicts: Vec<bool>) {
        verdicts.clear();
        self.verdicts = verdicts;
    }

    fn clear(&mut self, len: usize) {
        for group in self.touched.drain(..) {
            self.buckets[group].clear();
        }
        self.fallback.clear();
        self.verdicts.clear();
        self.verdicts.resize(len, false);
    }

    fn verify_groups(
        batch: &mut SameMessageBatch,
        verdicts: &mut [bool],
        entries: &[PendingAttestation],
        indices: &mut [usize],
    ) {
        indices.sort_unstable_by_key(|&index| entries[index].signing_root);
        let mut start = 0;
        while start < indices.len() {
            let signing_root = entries[indices[start]].signing_root;
            let end = start +
                indices[start..]
                    .partition_point(|&index| entries[index].signing_root == signing_root);
            batch.clear();
            for &index in &indices[start..end] {
                batch.push(entries[index].public_key, entries[index].signature);
            }
            for (&index, valid) in
                indices[start..end].iter().zip(batch.verify(&signing_root).iter().copied())
            {
                verdicts[index] = valid;
            }
            start = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::{PublicKey, SecretKey, Signature};

    use super::super::super::super::bls::{DST, SameMessageBatch};

    fn signed(seed: u8, message: [u8; 32]) -> (PublicKey, [u8; 96]) {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        let key = SecretKey::key_gen(&ikm, &[]).unwrap();
        (key.sk_to_pk(), key.sign(&message, DST, &[]).to_bytes())
    }

    #[test]
    fn attributes_one_bad_signature() {
        let message = [7u8; 32];
        let (pk0, sig0) = signed(1, message);
        let (pk1, _) = signed(2, message);
        let (_, wrong_sig) = signed(3, message);
        let mut batch = SameMessageBatch::default();
        batch.push(pk0, Signature::from_bytes(&sig0).unwrap());
        batch.push(pk1, Signature::from_bytes(&wrong_sig).unwrap());
        assert_eq!(batch.verify(&message), [true, false]);
    }

    #[test]
    fn rejects_signatures_that_only_verify_as_an_unweighted_sum() {
        let message = [11u8; 32];
        let (pk0, _) = signed(4, message);
        let (pk1, sig1) = signed(5, message);
        let (_, sig0) = signed(4, message);
        let mut batch = SameMessageBatch::default();
        batch.push(pk0, Signature::from_bytes(&sig1).unwrap());
        batch.push(pk1, Signature::from_bytes(&sig0).unwrap());
        assert_eq!(batch.verify(&message), [false, false]);
    }

    #[test]
    fn all_invalid_checks_each_subgroup_and_leaf_once() {
        let message = [12u8; 32];
        let pairs: Vec<_> = (0..128u8).map(|index| signed(index + 1, message)).collect();
        let mut batch = SameMessageBatch::default();
        for index in 0..pairs.len() {
            batch.push(pairs[index].0, Signature::from_bytes(&pairs[(index + 1) % 128].1).unwrap());
        }
        assert_eq!(batch.verify(&message), vec![false; 128]);
        assert_eq!(batch.operation_counts(), (128, 128, 3));
    }

    #[test]
    fn invalid_signatures_in_both_halves_are_attributed_at_the_bound() {
        let message = [13u8; 32];
        let pairs: Vec<_> = (0..128u8).map(|index| signed(index + 1, message)).collect();
        let invalid_indices = [10, 100];
        let mut batch = SameMessageBatch::default();
        for index in 0..pairs.len() {
            let signature_index =
                if invalid_indices.contains(&index) { (index + 1) % 128 } else { index };
            batch.push(pairs[index].0, Signature::from_bytes(&pairs[signature_index].1).unwrap());
        }
        let mut expected = vec![true; 128];
        for index in invalid_indices {
            expected[index] = false;
        }
        assert_eq!(batch.verify(&message), expected);
        assert_eq!(batch.operation_counts(), (128, 128, 3));
    }
}
