use core::{ptr, slice};

use blst::{
    MultiPoint, blst_hash_to_g2, blst_p2, blst_p2_affine, blst_p2_affine_in_g2,
    blst_p2_affine_on_curve, blst_p2_to_affine,
};

use super::encoding::less_than_p;

/// An on-curve G2 subgroup point in canonical blst Montgomery form.
/// Infinity is allowed; public-key admission must reject it separately.
///
/// ```compile_fail,E0624
/// use silver_crypto_simd::bls::G2Point;
/// G2Point::from_subgroup_unchecked(Default::default());
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct G2Point(blst_p2_affine);

impl G2Point {
    pub fn from_blst(point: blst_p2_affine) -> Option<Self> {
        if !less_than_p(&point.x.fp[0].l) ||
            !less_than_p(&point.x.fp[1].l) ||
            !less_than_p(&point.y.fp[0].l) ||
            !less_than_p(&point.y.fp[1].l)
        {
            return None;
        }
        // SAFETY: the pointer refers to a complete affine point with reduced
        // coordinates.
        let valid = unsafe { blst_p2_affine_on_curve(&point) && blst_p2_affine_in_g2(&point) };
        valid.then_some(Self(point))
    }

    /// Trusts that the coordinates are canonical and the point is on-curve and
    /// in G2. Violating this contract can invalidate cryptographic
    /// verdicts, but does not cause undefined behavior.
    pub(crate) const fn from_subgroup_unchecked(point: blst_p2_affine) -> Self {
        Self(point)
    }

    pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> Self {
        let mut point = blst_p2::default();
        let mut affine = blst_p2_affine::default();
        // SAFETY: the slices supply their lengths; augmentation is empty.
        unsafe {
            blst_hash_to_g2(
                &mut point,
                message.as_ptr(),
                message.len(),
                dst.as_ptr(),
                dst.len(),
                ptr::null(),
                0,
            );
            blst_p2_to_affine(&mut affine, &point);
        }
        // blst's hash-to-curve clears the cofactor.
        Self::from_subgroup_unchecked(affine)
    }

    /// Scalars are consecutive 64-bit little-endian integers, one per point.
    /// An empty sum is infinity.
    pub fn weighted_sum(points: &[Self], scalars: &[u8]) -> Self {
        assert_eq!(scalars.len(), points.len() * size_of::<u64>());
        let mut affine = blst_p2_affine::default();
        if !points.is_empty() {
            // SAFETY: repr(transparent) preserves the affine layout and alignment.
            // The borrowed view cannot mutate the checked points.
            let raw = unsafe { slice::from_raw_parts(points.as_ptr().cast(), points.len()) };
            let sum = <[blst_p2_affine]>::mult(raw, scalars, u64::BITS as usize);
            unsafe { blst_p2_to_affine(&mut affine, &sum) };
        }
        // Subgroup points are closed under scalar multiplication and addition.
        Self::from_subgroup_unchecked(affine)
    }

    pub const fn as_blst(&self) -> &blst_p2_affine {
        &self.0
    }

    pub const fn into_blst(self) -> blst_p2_affine {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use blst::{
        BLST_ERROR, blst_fp2_add, blst_p2_add_or_double, blst_p2_affine_generator, blst_p2_cneg,
        blst_p2_from_affine, blst_p2_mult, blst_p2_uncompress,
    };

    use super::*;
    use crate::bls::constants::P_U64;

    #[test]
    fn accepts_subgroup_points_and_infinity() {
        let generator = unsafe { *blst_p2_affine_generator() };
        for raw in [generator, blst_p2_affine::default()] {
            let point = G2Point::from_blst(raw).expect("subgroup point");
            assert_eq!(point.as_blst(), &raw);
            assert_eq!(point.into_blst(), raw);
        }
        let trusted = G2Point::from_subgroup_unchecked(generator);
        assert_eq!(trusted.into_blst(), generator);
    }

    #[test]
    fn rejects_off_curve_and_noncanonical_points() {
        let generator = unsafe { *blst_p2_affine_generator() };
        let checked = G2Point::from_blst(generator).unwrap();
        let mut changed = checked.into_blst();
        // Scaling (x, y) by (4, 8) preserves the subgroup relation on a different
        // curve.
        unsafe {
            for _ in 0..2 {
                blst_fp2_add(&mut changed.x, &changed.x, &changed.x);
            }
            for _ in 0..3 {
                blst_fp2_add(&mut changed.y, &changed.y, &changed.y);
            }
        }
        assert!(!unsafe { blst_p2_affine_on_curve(&changed) });
        assert!(unsafe { blst_p2_affine_in_g2(&changed) });
        assert!(G2Point::from_blst(changed).is_none());
        assert_eq!(checked.as_blst(), &generator);

        let mut noncanonical = generator;
        noncanonical.x.fp[0].l = P_U64;
        assert!(G2Point::from_blst(noncanonical).is_none());
        noncanonical.x.fp[0].l = [u64::MAX; 6];
        assert!(G2Point::from_blst(noncanonical).is_none());
    }

    #[test]
    fn rejects_curve_points_outside_subgroup() {
        let mut bytes = [0u8; 96];
        bytes[0] = 0x80;
        let mut point = blst_p2_affine::default();
        let found = (1..=255).any(|i| {
            bytes[95] = i;
            unsafe {
                blst_p2_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS &&
                    !blst_p2_affine_in_g2(&point)
            }
        });
        assert!(found);
        assert!(unsafe { blst_p2_affine_on_curve(&point) });
        assert!(G2Point::from_blst(point).is_none());
    }

    #[test]
    fn hashes_match_blst_for_messages_and_domains() {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        for message in [b"".as_slice(), b"typed points", &[0; 32], &[255; 256]] {
            for domain in [b"".as_slice(), dst, b"different domain", &[42; 256]] {
                let actual = G2Point::hash_to_curve(message, domain);
                let mut point = blst_p2::default();
                let mut expected = blst_p2_affine::default();
                unsafe {
                    blst_hash_to_g2(
                        &mut point,
                        message.as_ptr(),
                        message.len(),
                        domain.as_ptr(),
                        domain.len(),
                        ptr::null(),
                        0,
                    );
                    blst_p2_to_affine(&mut expected, &point);
                }
                assert_eq!(actual.into_blst(), expected);
                assert!(unsafe { blst_p2_affine_in_g2(actual.as_blst()) });
                assert!(G2Point::from_blst(actual.into_blst()).is_some());
            }
        }
        assert_ne!(
            G2Point::hash_to_curve(b"a", dst).into_blst(),
            G2Point::hash_to_curve(b"b", dst).into_blst()
        );
        assert_ne!(
            G2Point::hash_to_curve(b"a", dst).into_blst(),
            G2Point::hash_to_curve(b"a", b"different domain").into_blst()
        );
    }

    #[test]
    fn weighted_sums_match_blst() {
        let generator = G2Point::from_blst(unsafe { *blst_p2_affine_generator() }).unwrap();
        let infinity = G2Point::from_blst(blst_p2_affine::default()).unwrap();
        let fixtures = [generator, G2Point::hash_to_curve(b"weighted sum", b"test"), infinity];
        let weights = [0u64, 1, u64::MAX, 0x0102_0304_0506_0708];
        assert_eq!(G2Point::weighted_sum(&[], &[]).into_blst(), infinity.into_blst());
        for count in [1, 2, 3, 31, 32, 33] {
            let points = (0..count).map(|i| fixtures[i % fixtures.len()]).collect::<Vec<_>>();
            let raw = points.iter().map(|p| p.into_blst()).collect::<Vec<_>>();
            for offset in 0..weights.len() {
                let scalars = (0..count)
                    .flat_map(|i| weights[(i + offset) % weights.len()].to_le_bytes())
                    .collect::<Vec<_>>();
                let actual = G2Point::weighted_sum(&points, &scalars);
                let mut expected = blst_p2_affine::default();
                unsafe { blst_p2_to_affine(&mut expected, &raw.mult(&scalars, 64)) };
                assert_eq!(actual.into_blst(), expected);

                let mut sum = blst_p2::default();
                for (point, scalar) in raw.iter().zip(scalars.chunks_exact(size_of::<u64>())) {
                    let mut projective = blst_p2::default();
                    let mut product = blst_p2::default();
                    unsafe {
                        blst_p2_from_affine(&mut projective, point);
                        blst_p2_mult(
                            &mut product,
                            &projective,
                            scalar.as_ptr(),
                            u64::BITS as usize,
                        );
                        blst_p2_add_or_double(&mut sum, &sum, &product);
                    }
                }
                let mut expected_fold = blst_p2_affine::default();
                unsafe { blst_p2_to_affine(&mut expected_fold, &sum) };
                assert_eq!(
                    actual.into_blst(),
                    expected_fold,
                    "independent sum for {count} points at scalar offset {offset}"
                );
                assert!(unsafe { blst_p2_affine_in_g2(actual.as_blst()) });
                assert!(G2Point::from_blst(actual.into_blst()).is_some());
            }
        }
        assert_eq!(
            G2Point::weighted_sum(&[generator], &1u64.to_le_bytes()).into_blst(),
            generator.into_blst()
        );
        assert_eq!(
            G2Point::weighted_sum(&[generator], &0u64.to_le_bytes()).into_blst(),
            infinity.into_blst()
        );
        let mut negative = blst_p2::default();
        let mut negative_affine = blst_p2_affine::default();
        unsafe {
            blst_p2_from_affine(&mut negative, generator.as_blst());
            blst_p2_cneg(&mut negative, true);
            blst_p2_to_affine(&mut negative_affine, &negative);
        }
        let negative = G2Point::from_blst(negative_affine).unwrap();
        let cancel = G2Point::weighted_sum(
            &[generator, negative],
            &[1u64.to_le_bytes(), 1u64.to_le_bytes()].concat(),
        );
        assert_eq!(cancel.into_blst(), infinity.into_blst());
    }

    #[test]
    fn weighted_sum_rejects_scalar_length_mismatch() {
        let point = G2Point::hash_to_curve(b"length", b"test");
        for bytes in [0, 7, 9, 16] {
            assert!(catch_unwind(|| G2Point::weighted_sum(&[point], &vec![0; bytes])).is_err());
        }
        assert!(catch_unwind(|| G2Point::weighted_sum(&[], &[0; 8])).is_err());
    }
}
