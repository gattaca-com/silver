use silver_common::metrics::timed;

use super::QueuedAttestation;
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
    pub(super) fn verify(&mut self, entries: &[QueuedAttestation]) -> Vec<bool> {
        self.clear(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            match entry.pending.root_group {
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
            Self::verify_group(
                &mut self.batch,
                &mut self.verdicts,
                entries,
                &mut self.buckets[group],
            );
        }
        Self::verify_fallback(&mut self.batch, &mut self.verdicts, entries, &mut self.fallback);
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

    fn verify_group(
        batch: &mut SameMessageBatch,
        verdicts: &mut [bool],
        entries: &[QueuedAttestation],
        indices: &mut [usize],
    ) {
        let Some(&first) = indices.first() else { return };
        let signing_root = entries[first].pending.signing_root;
        if indices.iter().all(|&index| entries[index].pending.signing_root == signing_root) {
            Self::verify_indices(batch, verdicts, entries, indices, &signing_root);
        } else {
            Self::verify_fallback(batch, verdicts, entries, indices);
        }
    }

    fn verify_fallback(
        batch: &mut SameMessageBatch,
        verdicts: &mut [bool],
        entries: &[QueuedAttestation],
        indices: &mut [usize],
    ) {
        indices.sort_unstable_by_key(|&index| entries[index].pending.signing_root);
        let mut start = 0;
        while start < indices.len() {
            let signing_root = entries[indices[start]].pending.signing_root;
            let end = start +
                indices[start..].partition_point(|&index| {
                    entries[index].pending.signing_root == signing_root
                });
            Self::verify_indices(batch, verdicts, entries, &indices[start..end], &signing_root);
            start = end;
        }
    }

    fn verify_indices(
        batch: &mut SameMessageBatch,
        verdicts: &mut [bool],
        entries: &[QueuedAttestation],
        indices: &[usize],
        signing_root: &[u8; 32],
    ) {
        batch.clear();
        for &index in indices {
            batch.push(entries[index].pending.public_key, entries[index].pending.signature);
        }
        for (&index, valid) in indices.iter().zip(batch.verify(signing_root).iter().copied()) {
            verdicts[index] = valid;
        }
    }
}
