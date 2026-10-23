//! Multi-scalar multiplication on G1 without blst: Msm8's design on the scalar
//! `Fp`. GLV splits each scalar into two halves of 127 bits, for P and σ(P).
//! Rounds of batched affine additions shorten every signed-digit bucket to at
//! most one point; the window sums then run one window at a time. A round
//! that meets two points with equal x gives up, and the refilled buckets are
//! summed point by point with complete additions. Long inputs go through a
//! chunk at a time, and complete additions sum the chunks.
pub mod buckets;
pub mod pairs;
pub mod store;
#[cfg(all(test, target_arch = "x86_64"))]
mod tests;

use blst::{blst_p1, blst_p1_affine};

use crate::{
    bls::glv::{HALF_SCALAR_BITS, decompose},
    portable::{
        g1::G1,
        msm::{buckets::Buckets, pairs::BatchedAdds, store::PointStore},
    },
};

/// Points per bucket fill, as Msm8's.
const CHUNK: usize = 4096;

#[derive(Default)]
pub struct Msm {
    store: PointStore,
    buckets: Buckets,
    adds: BatchedAdds,
    finite_points: Vec<blst_p1_affine>,
    finite_scalars: Vec<[u64; 4]>,
    halves: Vec<[u64; 4]>,
    first_signs: Vec<bool>,
    second_signs: Vec<bool>,
}

impl Msm {
    /// Σ scalars[i]·points[i] for little-endian scalars below r and points of
    /// G1. Points at infinity, which blst encodes as all-zero coordinates,
    /// contribute nothing. Points with equal x force the complete-addition
    /// fallback, at most about twice the batched cost while the digits spread
    /// over the buckets. Scalars no caller can steer spread them; chosen ones
    /// can crowd a window into one bucket and cost several times more.
    pub fn msm(&mut self, points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> blst_p1 {
        assert!(points.len() == scalars.len(), "one scalar per point");
        let mut total = G1::INFINITY;
        let mut start = 0;
        while start < points.len() {
            let end = if points.len() - start < CHUNK { points.len() } else { start + CHUNK };
            let sum = self.chunk_sum(&points[start..end], &scalars[start..end]);
            total = total.add_complete(&sum);
            start = end;
        }
        total.to_blst()
    }

    /// `msm`'s sum for at most `CHUNK` points.
    fn chunk_sum(&mut self, points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> G1 {
        self.finite_points.clear();
        self.finite_scalars.clear();
        let mut i = 0;
        while i < points.len() {
            self.keep_if_finite(&points[i], &scalars[i]);
            i += 1;
        }
        let n = self.finite_points.len();
        if n == 0 {
            return G1::INFINITY;
        }

        self.split_scalars();
        self.buckets.fill(&self.halves, HALF_SCALAR_BITS);
        // A window's first round takes a new slot per pair of its 2n points at
        // most; later rounds overwrite sums.
        self.store.reset(2 * n + self.buckets.windows() * n);
        self.store.push_blst(&self.finite_points, &self.first_signs, false);
        self.store.push_blst(&self.finite_points, &self.second_signs, true);
        if !self.pair_rounds(2 * n) {
            self.buckets.fill(&self.halves, HALF_SCALAR_BITS);
        }
        self.buckets.sum(&self.store)
    }

    /// Scalar i's GLV halves k₁ and k₂ into `halves[i]` and `halves[n + i]`,
    /// for P_i and σ(P_i), with their signs.
    fn split_scalars(&mut self) {
        let n = self.finite_scalars.len();
        self.halves.clear();
        self.halves.resize(2 * n, [0; 4]);
        self.first_signs.clear();
        self.second_signs.clear();
        let mut i = 0;
        while i < n {
            let (first, second) = decompose(&self.finite_scalars[i]);
            self.halves[i] = first.magnitude;
            self.halves[n + i] = second.magnitude;
            self.first_signs.push(first.negative);
            self.second_signs.push(second.negative);
            i += 1;
        }
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
