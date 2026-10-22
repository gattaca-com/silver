use std::arch::x86_64::{__m512i, __mmask8, _mm512_set_epi64, _mm512_setzero_si512};

use crate::bls::{
    blst_p1_affine,
    constants::{BETA_MONT, LIMBS, TWO_POW_448_MOD_P},
    fp8::{Fp8, lanes, transpose8},
    limbs::{LANES, Limbs, unpack52},
};

/// Affine points by index, coordinates in R' form: row 2i holds the limbs of
/// point i's x, row 2i + 1 those of its y.
pub struct PointStore {
    rows: Vec<Limbs>,
    len: usize,
}

impl Default for PointStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PointStore {
    pub fn new() -> Self {
        Self { rows: Vec::new(), len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.rows.len() / 2
    }

    /// Empties the store and makes room for `capacity` points, keeping what it
    /// has allocated.
    pub fn reset(&mut self, capacity: usize) {
        if self.rows.len() < 2 * capacity {
            self.rows.resize(2 * capacity, [0; LIMBS]);
        }
        self.len = 0;
    }

    /// The index of a new point, for `store_points` to write.
    pub fn allocate(&mut self) -> u32 {
        assert!(self.len < self.capacity(), "the store holds every point");
        self.len += 1;
        (self.len - 1) as u32
    }

    /// Appends the points, from blst's Montgomery form to R' form: σ(P) =
    /// (β·x, y) instead of P when `endomorphism`, and the negation of point k
    /// where `negated[k]`. The points must be finite.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn push_blst(&mut self, points: &[blst_p1_affine], negated: &[bool], endomorphism: bool) {
        assert!(negated.len() == points.len(), "one sign per point");
        assert!(self.len + points.len() <= self.capacity(), "the store holds the points");
        let from_blst = Fp8::splat_limbs(&TWO_POW_448_MOD_P);
        let beta = Fp8::splat_limbs(&BETA_MONT);
        let mut at = 0;
        while at < points.len() {
            let count = if points.len() - at < LANES { points.len() - at } else { LANES };
            let mut xs = [[0u64; LIMBS]; LANES];
            let mut ys = [[0u64; LIMBS]; LANES];
            let mut indices = [0u32; LANES];
            let mut negate: __mmask8 = 0;
            let mut lane = 0;
            while lane < LANES {
                // Lanes past the last point repeat it, so they store the same values.
                let k = if lane < count { at + lane } else { at + count - 1 };
                xs[lane] = unpack52(&points[k].x.l);
                ys[lane] = unpack52(&points[k].y.l);
                negate |= (negated[k] as u8) << lane;
                indices[lane] = (self.len + k - at) as u32;
                lane += 1;
            }
            let mut x = Fp8::load(&xs).mul(&from_blst);
            if endomorphism {
                x = x.mul(&beta);
            }
            let y = Fp8::load(&ys).mul(&from_blst);
            self.store_points(&indices, &x, &Fp8::select(negate, &y, &y.neg()));
            self.len += count;
            at += count;
        }
    }

    /// The points at `indices`, lane l the point at `indices[l]`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load_points(&self, indices: &[u32; LANES]) -> (Fp8, Fp8) {
        let mut xs = [_mm512_setzero_si512(); LANES];
        let mut ys = [_mm512_setzero_si512(); LANES];
        let mut lane = 0;
        while lane < LANES {
            let at = 2 * indices[lane] as usize;
            xs[lane] = row_vector(&self.rows[at]);
            ys[lane] = row_vector(&self.rows[at + 1]);
            lane += 1;
        }
        (Fp8(transpose8(&xs)), Fp8(transpose8(&ys)))
    }

    /// As `load_points`, with y negated in the lanes of `negated`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load_signed(&self, indices: &[u32; LANES], negated: __mmask8) -> (Fp8, Fp8) {
        let (x, y) = self.load_points(indices);
        (x, Fp8::select(negated, &y, &y.neg()))
    }

    /// The x coordinates of the points at `indices`, as `load_points`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load_x(&self, indices: &[u32; LANES]) -> Fp8 {
        let mut xs = [_mm512_setzero_si512(); LANES];
        let mut lane = 0;
        while lane < LANES {
            xs[lane] = row_vector(&self.rows[2 * indices[lane] as usize]);
            lane += 1;
        }
        Fp8(transpose8(&xs))
    }

    /// Lane l becomes the point at `indices[l]`; a repeated index takes the
    /// last of its lanes.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn store_points(&mut self, indices: &[u32; LANES], x: &Fp8, y: &Fp8) {
        let xs = transpose8(&x.0);
        let ys = transpose8(&y.0);
        let mut lane = 0;
        while lane < LANES {
            let at = 2 * indices[lane] as usize;
            self.rows[at] = lanes(xs[lane]);
            self.rows[at + 1] = lanes(ys[lane]);
            lane += 1;
        }
    }
}

/// Lane j takes limb j of `row`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn row_vector(row: &Limbs) -> __m512i {
    _mm512_set_epi64(
        row[7] as i64,
        row[6] as i64,
        row[5] as i64,
        row[4] as i64,
        row[3] as i64,
        row[2] as i64,
        row[1] as i64,
        row[0] as i64,
    )
}
