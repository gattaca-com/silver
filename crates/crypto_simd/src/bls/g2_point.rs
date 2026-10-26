use blst::{blst_p2_affine, blst_p2_affine_in_g2, blst_p2_affine_on_curve};

use super::encoding::less_than_p;

/// An on-curve G2 subgroup point in canonical blst Montgomery form.
/// Infinity is allowed; public-key admission must reject it separately.
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
    pub const fn from_subgroup_unchecked(point: blst_p2_affine) -> Self {
        Self(point)
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
    use blst::{BLST_ERROR, blst_fp2_add, blst_p2_affine_generator, blst_p2_uncompress};

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
}
