//! Multi-scalar multiplication on G1 by Pippenger's signed-digit buckets, on
//! `Fp8` lanes. GLV splits each scalar into two halves of 127 bits, for P and
//! σ(P). Rounds of batched affine additions shorten every bucket to at most
//! one point; the window sums then run eight windows at a time, one per lane.
//! A round that meets two points with equal x gives up, and the refilled
//! buckets are summed point by point with complete additions. Long inputs go
//! through a chunk at a time, and complete additions sum the chunks.
pub mod buckets;
pub mod glv;
pub mod pairs;
pub mod store;
#[cfg(test)]
mod tests;

use blst::{blst_fp, blst_p1};

use crate::bls::{
    blst_p1_affine,
    g1x8::G1x8,
    msm8::{
        buckets::{Buckets, NARROWEST_WINDOW_BITS},
        glv::{HALF_SCALAR_BITS, decompose},
        pairs::{BatchedAdds, NEGATED},
        store::PointStore,
    },
};

/// Points per bucket fill. A full fill's buffers take about 20 MB, and their
/// growth slack can keep about 30 MB allocated. Each further chunk costs one
/// more pass of window sums.
const CHUNK: usize = 4096;
/// A fill's windows at most: halves cut into the narrowest windows.
const MOST_WINDOWS: usize = HALF_SCALAR_BITS / NARROWEST_WINDOW_BITS + 1;
// A fill of n ≤ CHUNK points keeps every u32 count, offset and store index
// below the sign bit:
// - each of the 2n halves has at most one reference per window, so the
//   reference total, each list's count and each offset are at most
//   2·MOST_WINDOWS·n; a round's pairs, at most half the references, fit too,
//   with the padding of their last group;
// - the store holds the 2n originals and at most one sum per first-round pair,
//   so at most (2 + MOST_WINDOWS)·n slots.
const _: () = assert!(2 * MOST_WINDOWS * CHUNK < NEGATED as usize);
const _: () = assert!((2 + MOST_WINDOWS) * CHUNK < NEGATED as usize);

#[derive(Default)]
pub struct Msm8 {
    store: PointStore,
    buckets: Buckets,
    adds: BatchedAdds,
    finite_points: Vec<blst_p1_affine>,
    finite_scalars: Vec<[u64; 4]>,
    halves: Vec<[u64; 4]>,
    first_signs: Vec<bool>,
    second_signs: Vec<bool>,
}

impl Msm8 {
    /// Σ scalars[i]·points[i] for little-endian scalars below r and points of
    /// G1. Points at infinity, which blst encodes as all-zero coordinates,
    /// contribute nothing.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn msm(&mut self, points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> blst_p1 {
        assert!(points.len() == scalars.len(), "one scalar per point");
        let mut total = G1x8::infinity();
        let mut start = 0;
        while start < points.len() {
            let end = if points.len() - start < CHUNK { points.len() } else { start + CHUNK };
            let sum = self.chunk_sum(&points[start..end], &scalars[start..end]);
            total = total.add_complete(&sum);
            start = end;
        }
        lane_zero_in_blst(&total)
    }

    /// `msm`'s sum in lane 0, for at most `CHUNK` points.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn chunk_sum(&mut self, points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> G1x8 {
        self.finite_points.clear();
        self.finite_scalars.clear();
        let mut i = 0;
        while i < points.len() {
            self.keep_if_finite(&points[i], &scalars[i]);
            i += 1;
        }
        let n = self.finite_points.len();
        if n == 0 {
            return G1x8::infinity();
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
