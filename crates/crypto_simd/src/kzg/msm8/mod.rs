//! Multi-scalar multiplication on G1 by Pippenger's buckets, with the bucket
//! additions batched eight at a time on `Fp8`: affine additions sharing one
//! inversion per round, then the bucket sums of eight windows at once.
//!
//! The vector formulas cannot add a point to itself or its negation. A pair
//! that needs it makes `Msm8::msm` return None, and the caller then uses blst.

mod buckets;
mod fixed_base8;
mod glv;
mod pairs;
mod reduce;
mod store;
#[cfg(test)]
mod tests;

use blst::{blst_p1, blst_p1_affine_is_inf};
pub use fixed_base8::FixedBase8;

use crate::{
    bls::{blst_p1_affine, simd_available},
    kzg::{
        blst_msm::ByteLincomb,
        msm8::{
            buckets::Buckets,
            glv::{HALF_SCALAR_BITS, decompose},
            pairs::BatchedAdds,
            reduce::WindowSums,
            store::PointStore,
        },
    },
};

/// Below this many points blst's own multiplication is as fast.
const MIN_POINTS: usize = 4;

pub struct Msm8 {
    store: PointStore,
    buckets: Buckets,
    adds: BatchedAdds,
    window_sums: WindowSums,
    finite_points: Vec<blst_p1_affine>,
    finite_scalars: Vec<[u8; 32]>,
    halves: Vec<[u8; 32]>,
    negated: Vec<bool>,
    fallback: ByteLincomb,
}

impl Msm8 {
    /// None without AVX-512 IFMA.
    pub fn new() -> Option<Self> {
        simd_available().then(|| Self {
            store: PointStore::new(),
            buckets: Buckets::new(),
            adds: BatchedAdds::default(),
            window_sums: WindowSums::default(),
            finite_points: Vec::new(),
            finite_scalars: Vec::new(),
            halves: Vec::new(),
            negated: Vec::new(),
            fallback: ByteLincomb::default(),
        })
    }

    /// `msm`, or blst's Pippenger when that is None.
    pub fn lincomb(&mut self, points: &[blst_p1_affine], scalars: &[[u8; 32]]) -> blst_p1 {
        match self.msm(points, scalars) {
            Some(sum) => sum,
            None => self.fallback.lincomb(points, scalars),
        }
    }

    /// Σ scalars[i]·points[i] for little-endian scalars below 2^255; points at
    /// infinity contribute nothing. None when the vector formulas met an
    /// exceptional addition.
    pub fn msm(&mut self, points: &[blst_p1_affine], scalars: &[[u8; 32]]) -> Option<blst_p1> {
        assert!(points.len() == scalars.len(), "one scalar per point");
        // SAFETY: valid pointers to single values.
        if points.iter().any(|point| unsafe { blst_p1_affine_is_inf(point) }) {
            let mut finite_points = std::mem::take(&mut self.finite_points);
            let mut finite_scalars = std::mem::take(&mut self.finite_scalars);
            finite_points.clear();
            finite_scalars.clear();
            for (point, scalar) in points.iter().zip(scalars) {
                // SAFETY: a valid pointer to a single value.
                if !unsafe { blst_p1_affine_is_inf(point) } {
                    finite_points.push(*point);
                    finite_scalars.push(*scalar);
                }
            }
            let sum = self.msm_finite(&finite_points, &finite_scalars);
            self.finite_points = finite_points;
            self.finite_scalars = finite_scalars;
            return sum;
        }
        self.msm_finite(points, scalars)
    }

    fn msm_finite(&mut self, points: &[blst_p1_affine], scalars: &[[u8; 32]]) -> Option<blst_p1> {
        let n = points.len();
        if n < MIN_POINTS {
            return Some(self.fallback.lincomb(points, scalars));
        }
        let window_bits = if n < 64 {
            4
        } else if n < 512 {
            6
        } else {
            8
        };
        // SAFETY: `new` checked avx512f and avx512ifma.
        unsafe { self.msm_vectors(points, scalars, window_bits) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn msm_vectors(
        &mut self,
        points: &[blst_p1_affine],
        scalars: &[[u8; 32]],
        window_bits: usize,
    ) -> Option<blst_p1> {
        self.halves.clear();
        self.halves.resize(2 * scalars.len(), [0; 32]);
        self.negated.clear();
        self.negated.resize(2 * scalars.len(), false);
        for (i, scalar) in scalars.iter().enumerate() {
            let (k1, k2) = decompose(scalar);
            self.halves[i] = k1.magnitude;
            self.negated[i] = k1.negative;
            self.halves[scalars.len() + i] = k2.magnitude;
            self.negated[scalars.len() + i] = k2.negative;
        }
        let n = 2 * points.len();
        let windows = Buckets::windows_for(window_bits, HALF_SCALAR_BITS);
        self.store.reset(n + windows * n.div_ceil(2));
        self.store.push_blst_signed(points, &self.negated[..points.len()], false);
        self.store.push_blst_signed(points, &self.negated[points.len()..], true);
        self.buckets.fill(&self.halves, window_bits, HALF_SCALAR_BITS);
        loop {
            self.adds.clear();
            self.buckets.queue_round(&mut self.adds, &mut self.store, n);
            if self.adds.is_empty() {
                break;
            }
            if !self.adds.run(&mut self.store) {
                return None;
            }
        }
        if !self.window_sums.compute(&self.buckets, &self.store) {
            return None;
        }
        Some(self.window_sums.combine(window_bits))
    }
}
