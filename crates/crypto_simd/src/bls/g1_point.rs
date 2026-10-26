use core::slice;

use blst::{
    MultiPoint, blst_fp_cneg, blst_p1_affine, blst_p1_affine_generator, blst_p1_affine_in_g1,
    blst_p1_affine_on_curve, blst_p1_to_affine,
};

use super::encoding::less_than_p;

/// An on-curve G1 subgroup point in canonical blst Montgomery form.
/// Infinity is allowed; public-key admission must reject it separately.
///
/// ```compile_fail,E0624
/// use silver_crypto_simd::bls::G1Point;
/// G1Point::from_subgroup_unchecked(Default::default());
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct G1Point(blst_p1_affine);

impl G1Point {
    pub fn from_blst(point: blst_p1_affine) -> Option<Self> {
        if !less_than_p(&point.x.l) || !less_than_p(&point.y.l) {
            return None;
        }
        // SAFETY: the pointer refers to a complete affine point with reduced
        // coordinates.
        let valid = unsafe { blst_p1_affine_on_curve(&point) && blst_p1_affine_in_g1(&point) };
        valid.then_some(Self(point))
    }

    /// Trusts that the coordinates are canonical and the point is on-curve and
    /// in G1. Violating this contract can invalidate cryptographic
    /// verdicts, but does not cause undefined behavior.
    pub(crate) const fn from_subgroup_unchecked(point: blst_p1_affine) -> Self {
        Self(point)
    }

    pub fn negative_generator() -> Self {
        // SAFETY: blst supplies a static generator; negation preserves G1.
        let mut point = unsafe { *blst_p1_affine_generator() };
        unsafe { blst_fp_cneg(&mut point.y, &point.y, true) };
        Self::from_subgroup_unchecked(point)
    }

    /// Scalars are consecutive 64-bit little-endian integers, one per point.
    /// An empty sum is infinity.
    pub fn weighted_sum(points: &[Self], scalars: &[u8]) -> Self {
        assert_eq!(scalars.len(), points.len() * size_of::<u64>());
        let mut affine = blst_p1_affine::default();
        if !points.is_empty() {
            // SAFETY: repr(transparent) preserves the affine layout and alignment.
            // The borrowed view cannot mutate the checked points.
            let raw = unsafe { slice::from_raw_parts(points.as_ptr().cast(), points.len()) };
            let sum = <[blst_p1_affine]>::mult(raw, scalars, u64::BITS as usize);
            unsafe { blst_p1_to_affine(&mut affine, &sum) };
        }
        // Subgroup points are closed under scalar multiplication and addition.
        Self::from_subgroup_unchecked(affine)
    }

    pub const fn as_blst(&self) -> &blst_p1_affine {
        &self.0
    }

    pub const fn into_blst(self) -> blst_p1_affine {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use blst::{
        blst_fp_add, blst_fp_from_uint64, blst_p1, blst_p1_add_or_double_affine,
        blst_p1_from_affine, blst_p1_is_inf,
    };

    use super::*;
    use crate::bls::constants::P_U64;

    #[test]
    fn accepts_subgroup_points_and_infinity() {
        let generator = unsafe { *blst_p1_affine_generator() };
        for raw in [generator, blst_p1_affine::default()] {
            let point = G1Point::from_blst(raw).expect("subgroup point");
            assert_eq!(point.as_blst(), &raw);
            assert_eq!(point.into_blst(), raw);
        }
        let trusted = G1Point::from_subgroup_unchecked(generator);
        assert_eq!(trusted.into_blst(), generator);
    }

    #[test]
    fn rejects_off_curve_and_noncanonical_points() {
        let generator = unsafe { *blst_p1_affine_generator() };
        let checked = G1Point::from_blst(generator).unwrap();
        let mut changed = checked.into_blst();
        // Scaling (x, y) by (4, 8) preserves the subgroup relation on a different
        // curve.
        unsafe {
            for _ in 0..2 {
                blst_fp_add(&mut changed.x, &changed.x, &changed.x);
            }
            for _ in 0..3 {
                blst_fp_add(&mut changed.y, &changed.y, &changed.y);
            }
        }
        assert!(!unsafe { blst_p1_affine_on_curve(&changed) });
        assert!(unsafe { blst_p1_affine_in_g1(&changed) });
        assert!(G1Point::from_blst(changed).is_none());
        assert_eq!(checked.as_blst(), &generator);

        let mut noncanonical = generator;
        noncanonical.x.l = P_U64;
        assert!(G1Point::from_blst(noncanonical).is_none());
        noncanonical.x.l = [u64::MAX; 6];
        assert!(G1Point::from_blst(noncanonical).is_none());
    }

    #[test]
    fn rejects_curve_points_outside_subgroup() {
        let mut point = blst_p1_affine::default();
        unsafe { blst_fp_from_uint64(&mut point.y, [2, 0, 0, 0, 0, 0].as_ptr()) };
        assert!(unsafe { blst_p1_affine_on_curve(&point) });
        assert!(!unsafe { blst_p1_affine_in_g1(&point) });
        assert!(G1Point::from_blst(point).is_none());
    }

    #[test]
    fn negated_generator_cancels_generator() {
        let generator = unsafe { *blst_p1_affine_generator() };
        let negative = G1Point::negative_generator();
        let mut expected = generator;
        let mut sum = blst_p1::default();
        unsafe {
            blst_fp_cneg(&mut expected.y, &expected.y, true);
            blst_p1_from_affine(&mut sum, &generator);
            blst_p1_add_or_double_affine(&mut sum, &sum, negative.as_blst());
        }
        assert_eq!(negative.into_blst(), expected);
        assert!(unsafe { blst_p1_is_inf(&sum) });
        assert!(unsafe { blst_p1_affine_in_g1(negative.as_blst()) });
        assert!(G1Point::from_blst(negative.into_blst()).is_some());
    }

    #[test]
    fn weighted_sums_match_blst() {
        let generator = G1Point::from_blst(unsafe { *blst_p1_affine_generator() }).unwrap();
        let infinity = G1Point::from_blst(blst_p1_affine::default()).unwrap();
        let fixtures = [generator, G1Point::negative_generator(), infinity];
        let weights = [0u64, 1, u64::MAX, 0x0102_0304_0506_0708];
        assert_eq!(G1Point::weighted_sum(&[], &[]).into_blst(), infinity.into_blst());
        for count in [1, 2, 3, 31, 32, 33] {
            let points = (0..count).map(|i| fixtures[i % fixtures.len()]).collect::<Vec<_>>();
            let raw = points.iter().map(|p| p.into_blst()).collect::<Vec<_>>();
            for offset in 0..weights.len() {
                let scalars = (0..count)
                    .flat_map(|i| weights[(i + offset) % weights.len()].to_le_bytes())
                    .collect::<Vec<_>>();
                let actual = G1Point::weighted_sum(&points, &scalars);
                let mut expected = blst_p1_affine::default();
                unsafe { blst_p1_to_affine(&mut expected, &raw.mult(&scalars, 64)) };
                assert_eq!(actual.into_blst(), expected);
                assert!(unsafe { blst_p1_affine_in_g1(actual.as_blst()) });
                assert!(G1Point::from_blst(actual.into_blst()).is_some());
            }
        }
        assert_eq!(
            G1Point::weighted_sum(&[generator], &1u64.to_le_bytes()).into_blst(),
            generator.into_blst()
        );
        assert_eq!(
            G1Point::weighted_sum(&[generator], &0u64.to_le_bytes()).into_blst(),
            infinity.into_blst()
        );
        let cancel = G1Point::weighted_sum(
            &fixtures[..2],
            &[1u64.to_le_bytes(), 1u64.to_le_bytes()].concat(),
        );
        assert_eq!(cancel.into_blst(), infinity.into_blst());
    }

    #[test]
    fn weighted_sum_rejects_scalar_length_mismatch() {
        let point = G1Point::negative_generator();
        for bytes in [0, 7, 9, 16] {
            assert!(
                std::panic::catch_unwind(|| G1Point::weighted_sum(&[point], &vec![0; bytes]))
                    .is_err()
            );
        }
        assert!(std::panic::catch_unwind(|| G1Point::weighted_sum(&[], &[0; 8])).is_err());
    }
}
