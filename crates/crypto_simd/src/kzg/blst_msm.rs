//! Linear combinations of G1 points with little-endian byte scalars, through
//! blst.

use blst::{
    blst_fr, blst_p1, blst_p1_affine_is_inf, blst_p1_from_affine, blst_p1_mult,
    blst_p1s_mult_pippenger, blst_p1s_mult_pippenger_scratch_sizeof, blst_scalar,
    blst_scalar_from_fr, limb_t,
};

use crate::{bls::blst_p1_affine, kzg::blst_ops::g1_add};

const SCALAR_BITS: usize = 255;
/// blst's Pippenger is slower than one multiplication per point below this many
/// points.
const PIPPENGER_MIN_POINTS: usize = 8;

#[derive(Default)]
pub struct ByteLincomb {
    points: Vec<blst_p1_affine>,
    scalars: Vec<[u8; 32]>,
    pippenger: Vec<limb_t>,
}

impl ByteLincomb {
    /// Σ scalars[i]·points[i]; points at infinity contribute nothing.
    pub fn lincomb(&mut self, points: &[blst_p1_affine], scalars: &[[u8; 32]]) -> blst_p1 {
        assert!(points.len() == scalars.len(), "one scalar per point");
        self.points.clear();
        self.scalars.clear();
        for (point, scalar) in points.iter().zip(scalars) {
            // SAFETY: a valid pointer to a single value.
            if !unsafe { blst_p1_affine_is_inf(point) } {
                self.points.push(*point);
                self.scalars.push(*scalar);
            }
        }
        let n = self.points.len();
        let mut out = blst_p1::default();
        if n < PIPPENGER_MIN_POINTS {
            for i in 0..n {
                let mut base = blst_p1::default();
                // SAFETY: valid pointers to single values.
                unsafe { blst_p1_from_affine(&mut base, &self.points[i]) };
                out = g1_add(&out, &g1_mult(&base, &self.scalars[i]));
            }
            return out;
        }
        // SAFETY: a pure size query.
        let bytes = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(n) };
        self.pippenger.resize(bytes.div_ceil(size_of::<limb_t>()), 0);
        // A null second pointer tells blst that the first points at a contiguous array.
        let points_arg = [self.points.as_ptr(), std::ptr::null()];
        let scalars_arg = [self.scalars.as_ptr().cast::<u8>(), std::ptr::null()];
        // SAFETY: `points` and `scalars` hold `n` values each, and `pippenger` holds at
        // least the scratch size blst asked for.
        unsafe {
            blst_p1s_mult_pippenger(
                &mut out,
                points_arg.as_ptr(),
                n,
                scalars_arg.as_ptr(),
                SCALAR_BITS,
                self.pippenger.as_mut_ptr(),
            );
        }
        out
    }
}

/// `scalar`·`point` for a little-endian scalar below 2^255.
pub fn g1_mult(point: &blst_p1, scalar: &[u8; 32]) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: valid pointers; blst reads `SCALAR_BITS` bits of the 32-byte scalar.
    unsafe { blst_p1_mult(&mut out, point, scalar.as_ptr(), SCALAR_BITS) };
    out
}

/// The little-endian bytes of the value, the layout of `blst_scalar`.
pub fn scalar_bytes(fr: &blst_fr) -> [u8; 32] {
    let mut scalar = blst_scalar::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_scalar_from_fr(&mut scalar, fr) };
    scalar.b
}
