use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p1s_add,
    blst_p2_affine,
};

use super::{PublicKey, Signature};

// `pk_affine` / `sig_affine` cast the blst newtypes to their inner affine
// points. blst-rs declares both as `#[repr(transparent)]` single-field
// wrappers.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<PublicKey>() == size_of::<blst_p1_affine>());
    assert!(align_of::<PublicKey>() == align_of::<blst_p1_affine>());
    assert!(size_of::<Signature>() == size_of::<blst_p2_affine>());
    assert!(align_of::<Signature>() == align_of::<blst_p2_affine>());
};

#[inline]
pub(crate) fn pk_affine(pk: &PublicKey) -> &blst_p1_affine {
    unsafe { &*(pk as *const PublicKey as *const blst_p1_affine) }
}

#[inline]
pub(crate) fn sig_affine(sig: &Signature) -> &blst_p2_affine {
    unsafe { &*(sig as *const Signature as *const blst_p2_affine) }
}

/// Reusable pointer table for `blst_p1s_add`. The pointers are only live
/// inside the single `sum` call that fills the table (cleared on entry), so
/// moving the idle buffer across threads is sound despite the raw pointers.
#[derive(Default)]
pub(crate) struct PubkeyAggregator(Vec<*const blst_p1_affine>);
unsafe impl Send for PubkeyAggregator {}

impl PubkeyAggregator {
    /// Batched affine addition — one shared inversion for the whole set,
    /// ~1.8× the serial `AggregatePublicKey::add_public_key` loop. `None`
    /// for an empty set (no identity element to report).
    fn sum<'a>(&mut self, pks: impl IntoIterator<Item = &'a PublicKey>) -> Option<blst_p1> {
        self.0.clear();
        self.0.extend(pks.into_iter().map(|pk| pk_affine(pk) as *const blst_p1_affine));
        (!self.0.is_empty()).then(|| {
            let mut sum = blst_p1::default();
            unsafe { blst_p1s_add(&mut sum, self.0.as_ptr(), self.0.len()) };
            sum
        })
    }

    fn to_public_key(sum: blst_p1) -> PublicKey {
        let mut affine = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut affine, &sum) };
        unsafe { std::mem::transmute::<blst_p1_affine, PublicKey>(affine) }
    }

    pub(crate) fn aggregate<'a>(
        &mut self,
        pks: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Option<PublicKey> {
        self.sum(pks).map(Self::to_public_key)
    }

    /// `Σ committees − Σ missing = Σ present`: the same group element as
    /// summing the attesters directly, but the point work scales with the
    /// (typically 2-5%) missing fraction. Both iterators must cover the same
    /// committees.
    pub(crate) fn aggregate_subtracted<'a>(
        &mut self,
        committees: impl IntoIterator<Item = &'a PublicKey>,
        missing: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Option<PublicKey> {
        let mut sum = self.sum(committees)?;
        if let Some(mut missing) = self.sum(missing) {
            unsafe {
                blst_p1_cneg(&mut missing, true);
                blst_p1_add_or_double(&mut sum, &sum, &missing);
            }
        }
        Some(Self::to_public_key(sum))
    }

    /// Identity for an empty set, for position-indexed tables where every
    /// entry must hold a valid point.
    pub(crate) fn aggregate_or_identity<'a>(
        &mut self,
        pks: impl IntoIterator<Item = &'a PublicKey>,
    ) -> PublicKey {
        Self::to_public_key(self.sum(pks).unwrap_or_default())
    }
}
