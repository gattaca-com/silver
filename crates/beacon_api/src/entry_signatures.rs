use silver_beacon_state_data::{
    B256, StateReadView,
    bls::{CheckedSignature, PublicKey, SigBatch, SignatureChecker},
};

pub(crate) struct SignatureCheck {
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

/// A failed batch falls back to one check per entry, so only the forgeries
/// fail.
pub(crate) struct EntrySignatures {
    pending: Vec<PendingCheck>,
    checked: Vec<Option<CheckedSignature>>,
    forged: Vec<usize>,
    checker: SignatureChecker,
    batch: SigBatch,
}

struct PendingCheck {
    body_index: usize,
    check: SignatureCheck,
}

impl EntrySignatures {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            checked: Vec::new(),
            forged: Vec::new(),
            checker: SignatureChecker::with_capacity(0),
            batch: SigBatch::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }

    pub(crate) fn push(&mut self, body_index: usize, check: SignatureCheck) {
        self.pending.push(PendingCheck { body_index, check });
    }

    /// The body indices of the pending entries whose signature fails, in the
    /// order they were pushed.
    pub(crate) fn verify(&mut self) -> &[usize] {
        let Self { pending, checked, forged, checker, batch } = self;
        checked.clear();
        checker.check_all(pending.iter().map(|entry| &entry.check.signature), |signature| {
            checked.push(signature)
        });

        batch.clear();
        for (entry, signature) in pending.iter().zip(checked.iter()) {
            if let Some(signature) = signature {
                batch.push_parsed(&entry.check.pubkey, *signature, entry.check.signing_root);
            }
        }
        let batch_valid = batch.verify_all();

        forged.clear();
        for (PendingCheck { body_index, check }, signature) in pending.drain(..).zip(checked.iter())
        {
            let valid = signature.is_some_and(|signature| {
                batch_valid || batch.verify_one(&check.pubkey, &signature, &check.signing_root)
            });
            if !valid {
                forged.push(body_index);
            }
        }
        forged
    }
}
