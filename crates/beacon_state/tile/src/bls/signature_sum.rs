use std::marker::PhantomData;

use blst::{blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_cneg, blst_p2s_add};

use super::{AggregateSignature, Signature, aggregator::sig_affine};

/// blst shares one inversion across a batch: ~1.8× faster than adding one at
/// a time at 256 signatures, no faster below 16.
const BATCH: usize = 256;

/// A sum of signatures, added and subtracted in batches. The signatures
/// must outlive it, as it keeps pointers to them until a batch is summed.
pub(crate) struct SignatureSum<'s> {
    added: Batch,
    subtracted: Batch,
    _signatures: PhantomData<&'s Signature>,
}

struct Batch {
    pending: [*const blst_p2_affine; BATCH],
    len: usize,
    sum: blst_p2,
}

impl Batch {
    const EMPTY: Self =
        Self { pending: [std::ptr::null(); BATCH], len: 0, sum: unsafe { std::mem::zeroed() } };

    fn push(&mut self, signature: &Signature) {
        self.pending[self.len] = sig_affine(signature);
        self.len += 1;
        if self.len == BATCH {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        let mut sum = blst_p2::default();
        unsafe {
            blst_p2s_add(&mut sum, self.pending.as_ptr(), self.len);
            blst_p2_add_or_double(&mut self.sum, &self.sum, &sum);
        }
        self.len = 0;
    }
}

impl<'s> SignatureSum<'s> {
    pub(crate) fn new() -> Self {
        Self { added: Batch::EMPTY, subtracted: Batch::EMPTY, _signatures: PhantomData }
    }

    pub(crate) fn add(&mut self, signature: &'s Signature) {
        self.added.push(signature);
    }

    pub(crate) fn subtract(&mut self, signature: &'s Signature) {
        self.subtracted.push(signature);
    }

    pub(crate) fn add_sum(&mut self, sum: &AggregateSignature) {
        let sum = unsafe { &*(sum as *const AggregateSignature as *const blst_p2) };
        unsafe { blst_p2_add_or_double(&mut self.added.sum, &self.added.sum, sum) };
    }

    pub(crate) fn finish(mut self) -> AggregateSignature {
        self.added.flush();
        self.subtracted.flush();
        let mut sum = self.added.sum;
        unsafe {
            blst_p2_cneg(&mut self.subtracted.sum, true);
            blst_p2_add_or_double(&mut sum, &sum, &self.subtracted.sum);
            std::mem::transmute::<blst_p2, AggregateSignature>(sum)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bls::{DST, EMPTY_AGGREGATE},
        test_signing::privkey,
    };

    fn signatures(count: usize) -> Vec<Signature> {
        (0..count).map(|i| privkey(i % 3).sign(&(i as u64).to_le_bytes(), DST, &[])).collect()
    }

    fn one_by_one<'a>(signatures: impl IntoIterator<Item = &'a Signature>) -> [u8; 96] {
        let mut sum = EMPTY_AGGREGATE;
        for signature in signatures {
            sum.add_signature(signature, false).expect("infallible without groupcheck");
        }
        sum.to_signature().to_bytes()
    }

    #[test]
    fn matches_adding_one_by_one_across_batches() {
        let signatures = signatures(BATCH * 2 + 3);
        let mut sum = SignatureSum::new();
        for signature in &signatures {
            sum.add(signature);
        }

        assert_eq!(sum.finish().to_signature().to_bytes(), one_by_one(&signatures));
    }

    #[test]
    fn subtracting_leaves_the_rest() {
        let signatures = signatures(BATCH + 5);
        let (kept, dropped) = signatures.split_at(7);
        let mut all = EMPTY_AGGREGATE;
        for signature in &signatures {
            all.add_signature(signature, false).expect("infallible without groupcheck");
        }
        let mut sum = SignatureSum::new();
        sum.add_sum(&all);
        for signature in dropped {
            sum.subtract(signature);
        }

        assert_eq!(sum.finish().to_signature().to_bytes(), one_by_one(kept));
    }

    #[test]
    fn repeated_signatures_double() {
        let signatures = signatures(2);
        let repeated = [&signatures[0], &signatures[0], &signatures[1]];
        let mut sum = SignatureSum::new();
        for signature in repeated {
            sum.add(signature);
        }

        assert_eq!(sum.finish().to_signature().to_bytes(), one_by_one(repeated));
    }
}
