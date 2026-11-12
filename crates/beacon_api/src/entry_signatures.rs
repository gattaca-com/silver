use std::collections::HashSet;

use silver_beacon_state_data::{
    B256, StateReadView,
    bls::{CheckedSignature, PublicKey, SigBatch, SignatureChecker},
};

pub(crate) struct SignatureCheck {
    /// A body may hold one entry per validator and epoch.
    pub(crate) validator: u64,
    pub(crate) epoch: u64,
    pub(crate) pubkey: PublicKey,
    pub(crate) signature: [u8; 96],
    pub(crate) signing_root: B256,
}

/// Only active validators sign duties, and activation waits on finality, so
/// every state names the same key at their index.
pub(crate) fn signing_key(view: &StateReadView<'_>, index: u64) -> Option<PublicKey> {
    let index = usize::try_from(index).ok().filter(|&index| index < view.validators.count())?;
    Some(*view.validators.pubkey_decompressed(index))
}

/// Single checks after a failed batch stop at this many forgeries. A client
/// that signs its own duties sends none, so a body past it is not worth one
/// pairing per entry.
const MAX_FORGED_PER_BODY: usize = 16;

/// A failed batch falls back to one check per entry, so only the forgeries
/// fail.
pub(crate) struct EntrySignatures {
    pending: Vec<PendingCheck>,
    /// Validator and epoch of every check pushed for this body.
    seen: HashSet<(u64, u64)>,
    repeated: Vec<usize>,
    forged: Vec<usize>,
    unchecked: Vec<usize>,
    checker: SignatureChecker,
    batch: SigBatch,
}

struct PendingCheck {
    body_index: usize,
    check: SignatureCheck,
    /// Decompressed and subgroup-checked; `None` for a malformed signature.
    signature: Option<CheckedSignature>,
}

/// Body indices in the order they were pushed.
pub(crate) struct Refused<'a> {
    /// Not verified: an earlier entry has the same validator and epoch.
    pub(crate) repeated: &'a [usize],
    pub(crate) forged: &'a [usize],
    /// Left unverified once [`MAX_FORGED_PER_BODY`] forgeries were found.
    pub(crate) unchecked: &'a [usize],
}

impl EntrySignatures {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            seen: HashSet::new(),
            repeated: Vec::new(),
            forged: Vec::new(),
            unchecked: Vec::new(),
            checker: SignatureChecker::with_capacity(0),
            batch: SigBatch::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.seen.clear();
        self.repeated.clear();
    }

    pub(crate) fn push(&mut self, body_index: usize, check: SignatureCheck) {
        if self.seen.insert((check.validator, check.epoch)) {
            self.pending.push(PendingCheck { body_index, check, signature: None });
        } else {
            self.repeated.push(body_index);
        }
    }

    pub(crate) fn verify(&mut self) -> Refused<'_> {
        let Self { pending, repeated, forged, unchecked, checker, batch, .. } = self;
        checker.check_each(
            pending,
            |entry| &entry.check.signature,
            |entry, signature| entry.signature = signature,
        );

        batch.clear();
        for entry in pending.iter() {
            if let Some(signature) = entry.signature {
                batch.push_parsed(&entry.check.pubkey, signature, entry.check.signing_root);
            }
        }
        let batch_valid = batch.verify_all();

        forged.clear();
        unchecked.clear();
        for PendingCheck { body_index, check, signature } in pending.drain(..) {
            let Some(signature) = signature else {
                forged.push(body_index);
                continue;
            };
            if batch_valid {
                continue;
            }
            if forged.len() >= MAX_FORGED_PER_BODY {
                unchecked.push(body_index);
            } else if !batch.verify_one(&check.pubkey, &signature, &check.signing_root) {
                forged.push(body_index);
            }
        }
        Refused { repeated, forged, unchecked }
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::bls::test_keys::{pubkey_pk, sign};

    use super::*;

    fn check(signer: usize, epoch: u8, validator: usize) -> SignatureCheck {
        let signing_root = [epoch; 32];
        SignatureCheck {
            validator: validator as u64,
            epoch: epoch as u64,
            pubkey: pubkey_pk(validator),
            signature: sign(signer, &signing_root),
            signing_root,
        }
    }

    fn verified(signatures: &mut EntrySignatures, checks: Vec<SignatureCheck>) -> [Vec<usize>; 3] {
        signatures.clear();
        for (body_index, check) in checks.into_iter().enumerate() {
            signatures.push(body_index, check);
        }
        let Refused { repeated, forged, unchecked } = signatures.verify();
        [repeated.to_vec(), forged.to_vec(), unchecked.to_vec()]
    }

    #[test]
    fn a_body_holds_one_entry_per_validator_and_epoch() {
        let mut signatures = EntrySignatures::new();
        let body = || vec![check(0, 1, 0), check(1, 1, 0), check(0, 2, 0), check(1, 1, 1)];
        assert_eq!(verified(&mut signatures, body()), [vec![1], vec![], vec![]]);
        assert_eq!(verified(&mut signatures, body()), [vec![1], vec![], vec![]], "the next body");
    }

    #[test]
    fn single_checks_stop_at_the_forgery_cap() {
        let mut body: Vec<_> =
            (0..MAX_FORGED_PER_BODY as u8 + 3).map(|epoch| check(1, epoch, 0)).collect();
        body.push(check(0, 200, 0));
        let [repeated, forged, unchecked] = verified(&mut EntrySignatures::new(), body);
        assert!(repeated.is_empty());
        assert_eq!(forged, (0..MAX_FORGED_PER_BODY).collect::<Vec<_>>());
        assert_eq!(unchecked, (MAX_FORGED_PER_BODY..MAX_FORGED_PER_BODY + 4).collect::<Vec<_>>());
    }
}
