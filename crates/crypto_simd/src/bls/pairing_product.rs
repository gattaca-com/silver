#[cfg(test)]
use std::cell::Cell;
use std::ptr;

use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop_n, blst_p1_affine,
    blst_p2_affine,
};

use crate::bls::{G1Point, G2Point, limbs::LANES};
#[cfg(target_arch = "x86_64")]
use crate::{
    bls::{fp12::Fp12, lane_pairs::LanePairs},
    ifma_available,
};

pub(super) const BLST_LIMBS: usize = 6;

#[cfg(test)]
thread_local! {
    pub(super) static BLST_PAIR_COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

#[derive(Default)]
pub struct PairingProduct {
    pairs: Vec<AffinePair>,
}

impl PairingProduct {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { pairs: Vec::with_capacity(capacity) }
    }

    pub fn clear(&mut self) {
        self.pairs.clear();
    }

    pub fn push(&mut self, p: &G1Point, q: &G2Point) {
        let pair = AffinePair::new(p, q);
        if !pair.is_infinite() {
            self.pairs.push(pair);
        }
    }

    pub fn is_one(&self) -> bool {
        PairingInputs { pairs: &self.pairs }.check()
    }

    pub fn two_pairs_are_one(first: (&G1Point, &G2Point), second: (&G1Point, &G2Point)) -> bool {
        let mut pairs = [AffinePair::new(first.0, first.1), AffinePair::new(second.0, second.1)];
        let mut count = 0;
        for index in 0..2 {
            if !pairs[index].is_infinite() {
                pairs[count] = pairs[index];
                count += 1;
            }
        }
        PairingInputs { pairs: &pairs[..count] }.check()
    }
}

#[derive(Clone, Copy)]
pub(super) struct AffinePair {
    pub p: blst_p1_affine,
    pub q: blst_p2_affine,
}

impl AffinePair {
    fn new(p: &G1Point, q: &G2Point) -> Self {
        Self { p: p.into_blst(), q: q.into_blst() }
    }

    fn is_infinite(&self) -> bool {
        let mut p_bits = 0;
        let mut q_bits = 0;
        for limb in 0..BLST_LIMBS {
            p_bits |= self.p.x.l[limb] | self.p.y.l[limb];
            for component in 0..2 {
                q_bits |= self.q.x.fp[component].l[limb] | self.q.y.fp[component].l[limb];
            }
        }
        p_bits == 0 || q_bits == 0
    }
}

// Consuming the view avoids nested shared borrows in Aeneas.
struct PairingInputs<'a> {
    pairs: &'a [AffinePair],
}

impl PairingInputs<'_> {
    fn check(self) -> bool {
        if self.pairs.is_empty() {
            return true;
        }
        #[cfg(target_arch = "x86_64")]
        if ifma_available() {
            // SAFETY: the dispatch confirmed AVX-512F and AVX-512 IFMA.
            return unsafe { self.lane_is_one() };
        }
        self.blst_is_one()
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn lane_is_one(self) -> bool {
        let mut product = Fp12::one();
        let mut degenerate = 0;
        let mut start = 0;
        while start < self.pairs.len() {
            let remaining = self.pairs.len() - start;
            let len = if remaining < LANES { remaining } else { LANES };
            let result = LanePairs::new(&self.pairs[start..start + len]).miller_loop();
            product = product.mul(&result.value);
            degenerate |= result.degenerate;
            start += len;
        }
        if degenerate != 0 {
            return self.blst_is_one();
        }
        product.final_exponentiation().is_one()
    }

    fn blst_is_one(self) -> bool {
        #[cfg(test)]
        BLST_PAIR_COUNT.set(Some(self.pairs.len()));
        let mut product = blst_fp12::default();
        let mut start = 0;
        while start < self.pairs.len() {
            let remaining = self.pairs.len() - start;
            let len = if remaining < LANES { remaining } else { LANES };
            let mut ps = [ptr::null(); LANES];
            let mut qs = [ptr::null(); LANES];
            for lane in 0..len {
                ps[lane] = &self.pairs[start + lane].p;
                qs[lane] = &self.pairs[start + lane].q;
            }
            let mut value = blst_fp12::default();
            // SAFETY: the first `len` pointers refer to live, finite affine points.
            unsafe {
                blst_miller_loop_n(&mut value, qs.as_ptr(), ps.as_ptr(), len);
                blst_fp12_mul(&mut product, &product, &value);
            }
            start += len;
        }
        let mut value = blst_fp12::default();
        // SAFETY: the pointers refer to initialized Fp12 values.
        unsafe {
            blst_final_exp(&mut value, &product);
            blst_fp12_is_one(&value)
        }
    }
}
