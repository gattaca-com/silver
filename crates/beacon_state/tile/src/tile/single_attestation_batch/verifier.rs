#[cfg(test)]
use std::cell::Cell;

use blst::{
    BLST_ERROR, MultiPoint,
    min_pk::{PublicKey, Signature},
};
use ring::rand::{SecureRandom, SystemRandom};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::B256;
use silver_common::metrics::timed;

use super::PendingAttestation;
use crate::bls::DST;

#[timed]
pub(crate) fn verify_entries(entries: &[PendingAttestation]) -> Vec<bool> {
    if let [entry] = entries {
        return vec![verify_single(&entry.public_key, &entry.signature, &entry.signing_root, true)];
    }
    let mut groups: FxHashMap<B256, Vec<usize>> = FxHashMap::default();
    for (index, entry) in entries.iter().enumerate() {
        groups.entry(entry.signing_root).or_default().push(index);
    }
    let mut verdicts = vec![false; entries.len()];
    for (signing_root, indices) in groups {
        let mut batch = SameMessageBatch::default();
        for &index in &indices {
            batch.push(entries[index].public_key, entries[index].signature);
        }
        for (index, valid) in indices.into_iter().zip(batch.verify(&signing_root)) {
            verdicts[index] = valid;
        }
    }
    verdicts
}

fn verify_single(
    public_key: &PublicKey,
    signature: &Signature,
    message: &B256,
    signature_groupcheck: bool,
) -> bool {
    signature.verify(signature_groupcheck, message, DST, &[], public_key, false) ==
        BLST_ERROR::BLST_SUCCESS
}

#[derive(Default)]
struct SameMessageBatch {
    public_keys: Vec<PublicKey>,
    signatures: Vec<Signature>,
    #[cfg(test)]
    subgroup_checks: Cell<usize>,
    #[cfg(test)]
    singleton_verifies: Cell<usize>,
}

impl SameMessageBatch {
    fn push(&mut self, public_key: PublicKey, signature: Signature) {
        self.public_keys.push(public_key);
        self.signatures.push(signature);
    }

    fn verify(&self, message: &B256) -> Vec<bool> {
        let subgroup_valid: Vec<_> = self
            .signatures
            .iter()
            .map(|signature| {
                #[cfg(test)]
                self.subgroup_checks.set(self.subgroup_checks.get() + 1);
                signature.validate(true).is_ok()
            })
            .collect();
        let mut verdicts = vec![false; self.public_keys.len()];
        self.verify_range(message, &subgroup_valid, 0, self.public_keys.len(), &mut verdicts);
        verdicts
    }

    fn verify_range(
        &self,
        message: &B256,
        subgroup_valid: &[bool],
        start: usize,
        end: usize,
        verdicts: &mut [bool],
    ) {
        if start == end {
            return;
        }
        if end - start == 1 {
            if subgroup_valid[start] {
                #[cfg(test)]
                self.singleton_verifies.set(self.singleton_verifies.get() + 1);
                verdicts[start] = verify_single(
                    &self.public_keys[start],
                    &self.signatures[start],
                    message,
                    false,
                );
            }
            return;
        }
        if subgroup_valid[start..end].iter().all(|&valid| valid) &&
            self.verify_weighted(message, start, end)
        {
            verdicts[start..end].fill(true);
            return;
        }
        let middle = start + (end - start) / 2;
        self.verify_range(message, subgroup_valid, start, middle, verdicts);
        self.verify_range(message, subgroup_valid, middle, end, verdicts);
    }

    fn verify_weighted(&self, message: &B256, start: usize, end: usize) -> bool {
        debug_assert!(end - start >= 2);
        let mut scalars = vec![0u8; (end - start) * 8];
        if SystemRandom::new().fill(&mut scalars).is_err() {
            return false;
        }
        for scalar in scalars.chunks_exact_mut(8) {
            if scalar.iter().all(|&byte| byte == 0) {
                scalar[0] = 1;
            }
        }
        let public_key = self.public_keys[start..end].mult(&scalars, 64).to_public_key();
        let signature = self.signatures[start..end].mult(&scalars, 64).to_signature();
        signature.fast_aggregate_verify_pre_aggregated(false, message, DST, &public_key) ==
            BLST_ERROR::BLST_SUCCESS
    }

    #[cfg(test)]
    fn operation_counts(&self) -> (usize, usize) {
        (self.subgroup_checks.get(), self.singleton_verifies.get())
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::{PublicKey, SecretKey, Signature};

    use super::{DST, SameMessageBatch};

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

        assert_eq!(batch.verify(&message), vec![true, false]);
    }

    #[test]
    fn rejects_signatures_that_only_verify_as_an_unweighted_sum() {
        let message = [11u8; 32];
        let (pk0, sig0) = signed(4, message);
        let (pk1, sig1) = signed(5, message);
        let mut batch = SameMessageBatch::default();
        batch.push(pk0, Signature::from_bytes(&sig1).unwrap());
        batch.push(pk1, Signature::from_bytes(&sig0).unwrap());

        assert_eq!(batch.verify(&message), vec![false, false]);
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
        assert_eq!(batch.operation_counts(), (128, 128));
    }
}
