//! Multi-scalar multiplication on G1 by Pippenger's signed-digit buckets, on
//! `Fp8` lanes. Rounds of batched affine additions shorten every bucket to at
//! most one point; the window sums then run eight windows at a time, one per
//! lane. A round that meets two points with equal x gives up, and the
//! refilled buckets are summed point by point with complete additions.
pub mod buckets;
pub mod pairs;
pub mod store;
#[cfg(test)]
mod tests;

use blst::{blst_fp, blst_p1};

use crate::bls::{
    blst_p1_affine,
    g1x8::G1x8,
    msm8::{buckets::Buckets, pairs::BatchedAdds, store::PointStore},
};

#[derive(Default)]
pub struct Msm8 {
    store: PointStore,
    buckets: Buckets,
    adds: BatchedAdds,
    finite_points: Vec<blst_p1_affine>,
    finite_scalars: Vec<[u64; 4]>,
    unsigned: Vec<bool>,
}

impl Msm8 {
    /// Σ scalars[i]·points[i] for little-endian scalars below 2^255. Points at
    /// infinity, which blst encodes as all-zero coordinates, contribute
    /// nothing.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn msm(&mut self, points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> blst_p1 {
        assert!(points.len() == scalars.len(), "one scalar per point");
        self.finite_points.clear();
        self.finite_scalars.clear();
        let mut i = 0;
        while i < points.len() {
            self.keep_if_finite(&points[i], &scalars[i]);
            i += 1;
        }
        let n = self.finite_points.len();
        if n == 0 {
            return lane_zero_in_blst(&G1x8::infinity());
        }

        self.buckets.fill(&self.finite_scalars);
        // A window's first round takes a new slot per pair of its n points at
        // most; later rounds overwrite sums.
        self.store.reset(n + self.buckets.windows() * (n / 2));
        self.unsigned.clear();
        self.unsigned.resize(n, false);
        self.store.push_blst(&self.finite_points, &self.unsigned, false);
        if !self.pair_rounds(n) {
            self.buckets.fill(&self.finite_scalars);
        }
        lane_zero_in_blst(&self.buckets.sum(&self.store))
    }

    fn keep_if_finite(&mut self, point: &blst_p1_affine, scalar: &[u64; 4]) {
        assert!(scalar[3] >> 63 == 0, "scalars are below 2^255");
        if !is_infinity(point) {
            self.finite_points.push(*point);
            self.finite_scalars.push(*scalar);
        }
    }

    /// Batched rounds until every bucket holds at most one point. False when a
    /// round meets equal x, which leaves the buckets naming unwritten sums.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn pair_rounds(&mut self, originals: usize) -> bool {
        self.buckets.queue_round(&mut self.adds, &mut self.store, originals);
        while !self.adds.is_empty() && self.adds.run(&mut self.store) {
            self.buckets.queue_round(&mut self.adds, &mut self.store, originals);
        }
        self.adds.is_empty()
    }
}

fn is_infinity(point: &blst_p1_affine) -> bool {
    let mut k = 0;
    while k < 6 && point.x.l[k] == 0 && point.y.l[k] == 0 {
        k += 1;
    }
    k == 6
}

/// Lane 0 in blst's Jacobian form, where z = 0 is infinity.
#[target_feature(enable = "avx512f,avx512ifma")]
fn lane_zero_in_blst(point: &G1x8) -> blst_p1 {
    blst_p1 {
        x: blst_fp { l: point.x.to_blst_limbs()[0] },
        y: blst_fp { l: point.y.to_blst_limbs()[0] },
        z: blst_fp { l: point.z.to_blst_limbs()[0] },
    }
}
