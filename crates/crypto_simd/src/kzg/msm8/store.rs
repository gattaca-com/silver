use std::arch::x86_64::{__m512i, _mm512_loadu_si512, _mm512_storeu_si512};

use blst::{blst_fp, blst_fp_from_uint64};

use crate::{
    bls::{
        blst_p1_affine,
        constants::{BETA_MONT, LIMBS},
        fp8::{Fp8, LANES, Limbs, unpack52},
        g1x8_lazy::Offsets,
    },
    kzg::fr8::transpose8,
};

const POINT_WORDS: usize = 2 * LIMBS;

/// Affine points in R' = 2^416 form, one per `POINT_WORDS` words: the eight x
/// limbs, then the eight y limbs.
pub struct PointStore {
    words: Vec<u64>,
    len: usize,
    /// 2^448 mod p. Multiplying blst's Montgomery limbs (R = 2^384) by it in R'
    /// form gives R' form: blst's Montgomery form of 2^64.
    from_blst: Limbs,
}

impl PointStore {
    pub fn new() -> Self {
        let mut two_pow_64 = blst_fp::default();
        // SAFETY: valid pointers; blst reads six words and writes one value.
        unsafe { blst_fp_from_uint64(&mut two_pow_64, [0, 1, 0, 0, 0, 0].as_ptr()) };
        Self { words: Vec::new(), len: 0, from_blst: unpack52(&two_pow_64.l) }
    }

    pub fn capacity(&self) -> usize {
        self.words.len() / POINT_WORDS
    }

    /// Empties the store and makes room for `capacity` points, keeping what it
    /// has allocated.
    pub fn reset(&mut self, capacity: usize) {
        self.words.resize(self.words.len().max(capacity * POINT_WORDS), 0);
        self.len = 0;
    }

    /// The index of the next point, which the caller then writes by
    /// `store_points`.
    pub fn allocate(&mut self) -> u32 {
        assert!(self.len < self.capacity(), "the store holds every point a round can add");
        self.len += 1;
        (self.len - 1) as u32
    }

    /// Appends the points, converted to R' form.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn push_blst(&mut self, points: &[blst_p1_affine]) {
        self.push_blst_signed(points, &[], false);
    }

    /// Appends ±points, or ±σ(points) = (β·x, y) when `endomorphism`,
    /// converted to R' form; `negated[i]` (false past its end) negates point i.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn push_blst_signed(
        &mut self,
        points: &[blst_p1_affine],
        negated: &[bool],
        endomorphism: bool,
    ) {
        assert!(self.len + points.len() <= self.capacity(), "the store holds the points");
        let from_blst = Fp8::splat_limbs(&self.from_blst);
        let beta = Fp8::splat_limbs(&BETA_MONT);
        let c = Offsets::new();
        let mut xs = [[0u64; LIMBS]; LANES];
        let mut ys = [[0u64; LIMBS]; LANES];
        for (k, chunk) in points.chunks(LANES).enumerate() {
            let mut negate: u8 = 0;
            for (lane, point) in chunk.iter().enumerate() {
                xs[lane] = unpack52(&point.x.l);
                ys[lane] = unpack52(&point.y.l);
                negate |= u8::from(negated.get(k * LANES + lane).copied().unwrap_or(false)) << lane;
            }
            let x = Fp8::load(&xs).mul(&from_blst);
            let x = if endomorphism { x.mul(&beta) } else { x };
            let y = Fp8::load(&ys).mul(&from_blst);
            let y = Fp8::select(negate, &y, &c.neg(&y));
            for j in 0..LIMBS {
                let (x_limbs, y_limbs) = (lanes(x.0[j]), lanes(y.0[j]));
                for lane in 0..chunk.len() {
                    let at = (self.len + lane) * POINT_WORDS;
                    self.words[at + j] = x_limbs[lane];
                    self.words[at + LIMBS + j] = y_limbs[lane];
                }
            }
            self.len += chunk.len();
        }
    }

    /// The points of the blst Montgomery limbs, in R' form.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn fp8_from_blst(&self, values: &[[u64; 6]; LANES]) -> Fp8 {
        let limbs: [Limbs; LANES] = std::array::from_fn(|lane| unpack52(&values[lane]));
        Fp8::load(&limbs).mul(&Fp8::splat_limbs(&self.from_blst))
    }

    /// The x and y of the eight points, by one contiguous load per coordinate
    /// and an 8×8 transpose: a gather costs 13 cycles per limb row here.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load_points(&self, indices: __m512i) -> (Fp8, Fp8) {
        let at = lanes(indices);
        let mut xs = [Fp8::zero().0[0]; LANES];
        let mut ys = xs;
        for lane in 0..LANES {
            // SAFETY: the indices name allocated points, each `POINT_WORDS` words
            // inside `words`.
            unsafe {
                let point = self.words.as_ptr().add(at[lane] as usize * POINT_WORDS);
                xs[lane] = _mm512_loadu_si512(point.cast());
                ys[lane] = _mm512_loadu_si512(point.add(LIMBS).cast());
            }
        }
        transpose8(&mut xs);
        transpose8(&mut ys);
        (Fp8(xs), Fp8(ys))
    }

    /// The x of the eight points, as `load_points`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load_x(&self, indices: __m512i) -> Fp8 {
        let at = lanes(indices);
        let mut xs = [Fp8::zero().0[0]; LANES];
        for lane in 0..LANES {
            // SAFETY: as in `load_points`.
            unsafe {
                let point = self.words.as_ptr().add(at[lane] as usize * POINT_WORDS);
                xs[lane] = _mm512_loadu_si512(point.cast());
            }
        }
        transpose8(&mut xs);
        Fp8(xs)
    }

    /// The inverse of `load_points`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn store_points(&mut self, indices: __m512i, x: &Fp8, y: &Fp8) {
        let at = lanes(indices);
        let (mut xs, mut ys) = (x.0, y.0);
        transpose8(&mut xs);
        transpose8(&mut ys);
        for lane in 0..LANES {
            // SAFETY: as in `load_points`.
            unsafe {
                let point = self.words.as_mut_ptr().add(at[lane] as usize * POINT_WORDS);
                _mm512_storeu_si512(point.cast(), xs[lane]);
                _mm512_storeu_si512(point.add(LIMBS).cast(), ys[lane]);
            }
        }
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub fn lanes(v: __m512i) -> [u64; LANES] {
    let mut out = [0u64; LANES];
    // SAFETY: an unaligned store of the 64 bytes of `out`.
    unsafe { _mm512_storeu_si512(out.as_mut_ptr().cast(), v) };
    out
}
