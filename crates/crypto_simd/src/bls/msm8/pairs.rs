use std::arch::x86_64::__mmask8;

use crate::bls::{
    fp8::{Fp8, LANES},
    g1x8::Offsets,
    msm8::store::PointStore,
};

/// Set on a reference to the negation of the point it names.
pub const NEGATED: u32 = 1 << 31;
/// Independent prefix-product chains: the core overlaps the multiplications of
/// different chains, which keeps the chain off the critical path.
const CHAINS: usize = 4;
/// Groups finished together, step by step, so that every multiplication has an
/// independent sibling in flight.
const PAIR: usize = 2;

/// Pending affine additions `out = a + b` of points in a `PointStore`, where
/// `NEGATED` on a reference to `a` or `b` negates its point. One inversion
/// serves them all: Montgomery's trick over groups of eight lanes.
#[derive(Default)]
pub struct BatchedAdds {
    a: Vec<u32>,
    b: Vec<u32>,
    out: Vec<u32>,
    dx: Vec<Fp8>,
    prefix: Vec<Fp8>,
}

impl BatchedAdds {
    pub fn clear(&mut self) {
        self.a.clear();
        self.b.clear();
        self.out.clear();
    }

    pub fn push(&mut self, a: u32, b: u32, out: u32) {
        self.a.push(a);
        self.b.push(b);
        self.out.push(out);
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    /// Writes every sum to its `out`. False, with nothing written, when some
    /// pair has equal x coordinates: its points are equal or opposite, and the
    /// slope would divide by zero.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn run(&mut self, store: &mut PointStore) -> bool {
        assert!(!self.a.is_empty(), "a pair to add");
        let groups = ((self.a.len() - 1) / (PAIR * LANES) + 1) * PAIR;
        let last = self.a.len() - 1;
        let (a, b, out) = (self.a[last], self.b[last], self.out[last]);
        self.a.resize(groups * LANES, a);
        self.b.resize(groups * LANES, b);
        self.out.resize(groups * LANES, out);
        self.dx.resize(groups, Fp8::zero());
        self.prefix.resize(groups, Fp8::zero());

        let mut products = [Fp8::one(); CHAINS];
        let mut g = 0;
        while g < groups && self.extend_chain(store, g, &mut products) {
            g += 1;
        }
        if g < groups {
            return false;
        }
        let mut inverses = batch_inverse(&products);
        while g > 0 {
            g -= PAIR;
            let dx_inverses = self.unwind_chains(g, &mut inverses);
            self.finish_pair(store, g, &dx_inverses);
        }
        true
    }

    /// Multiplies group g's x differences into chain g % CHAINS. False when one
    /// of them is zero.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn extend_chain(&mut self, store: &PointStore, g: usize, products: &mut [Fp8; CHAINS]) -> bool {
        let xa = store.load_x(&references(&self.a, g).0);
        let xb = store.load_x(&references(&self.b, g).0);
        let dx = xb.sub(&xa);
        if dx.is_zero_mask() != 0 {
            return false;
        }
        let k = g % CHAINS;
        products[k] = products[k].mul(&dx);
        self.dx[g] = dx;
        self.prefix[g] = products[k];
        true
    }

    /// The inverses of the x differences of groups g and g + 1, each taken off
    /// the top of its chain, whose inverse then drops that group.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn unwind_chains(&self, g: usize, inverses: &mut [Fp8; CHAINS]) -> [Fp8; PAIR] {
        let mut dx_inverses = [Fp8::zero(); PAIR];
        let mut s = 0;
        while s < PAIR {
            let group = g + s;
            let k = group % CHAINS;
            dx_inverses[s] = if group < CHAINS {
                inverses[k]
            } else {
                inverses[k].mul(&self.prefix[group - CHAINS])
            };
            inverses[k] = inverses[k].mul(&self.dx[group]);
            s += 1;
        }
        dx_inverses
    }

    /// The sums of groups g and g + 1, step by step in lockstep.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn finish_pair(&self, store: &mut PointStore, g: usize, dx_inverses: &[Fp8; PAIR]) {
        let o = Offsets::new();
        let mut xa = [Fp8::zero(); PAIR];
        let mut ya = [Fp8::zero(); PAIR];
        let mut xb = [Fp8::zero(); PAIR];
        let mut yb = [Fp8::zero(); PAIR];
        let mut s = 0;
        while s < PAIR {
            let (indices, negated) = references(&self.a, g + s);
            let (x, y) = store.load_signed(&indices, negated);
            xa[s] = x;
            ya[s] = y;
            let (indices, negated) = references(&self.b, g + s);
            let (x, y) = store.load_signed(&indices, negated);
            xb[s] = x;
            yb[s] = y;
            s += 1;
        }
        let mut slope = [Fp8::zero(); PAIR];
        s = 0;
        while s < PAIR {
            // yb − ya below 4p, then 4p · 2p.
            let dy = yb[s].sub_raw(&ya[s], &o.two_p).normalise();
            slope[s] = dy.mul(&dx_inverses[s]);
            s += 1;
        }
        let mut squared = [Fp8::zero(); PAIR];
        s = 0;
        while s < PAIR {
            squared[s] = slope[s].square();
            s += 1;
        }
        let mut x3 = [Fp8::zero(); PAIR];
        s = 0;
        while s < PAIR {
            x3[s] =
                o.reduced_from_8p(&squared[s].sub_raw(&xa[s], &o.two_p).sub_raw(&xb[s], &o.two_p));
            s += 1;
        }
        let mut product = [Fp8::zero(); PAIR];
        s = 0;
        while s < PAIR {
            // xa − x3 below 4p, then 2p · 4p.
            product[s] = slope[s].mul(&xa[s].sub_raw(&x3[s], &o.two_p).normalise());
            s += 1;
        }
        s = 0;
        while s < PAIR {
            let y3 = o.reduced_from_4p(&product[s].sub_raw(&ya[s], &o.two_p));
            store.store_points(&references(&self.out, g + s).0, &x3[s], &y3);
            s += 1;
        }
    }
}

/// The inverses of `values` by Montgomery's trick: one inversion and
/// 3·(CHAINS − 1) multiplications.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn batch_inverse(values: &[Fp8; CHAINS]) -> [Fp8; CHAINS] {
    let mut prefix = *values;
    let mut k = 1;
    while k < CHAINS {
        prefix[k] = prefix[k - 1].mul(&values[k]);
        k += 1;
    }
    let mut inverse = prefix[CHAINS - 1].inverse();
    let mut out = [Fp8::zero(); CHAINS];
    k = CHAINS - 1;
    while k > 0 {
        out[k] = inverse.mul(&prefix[k - 1]);
        inverse = inverse.mul(&values[k]);
        k -= 1;
    }
    out[0] = inverse;
    out
}

/// The indices of group g's references, and the lanes they negate.
fn references(refs: &[u32], g: usize) -> ([u32; LANES], __mmask8) {
    let mut indices = [0u32; LANES];
    let mut negated: __mmask8 = 0;
    let mut lane = 0;
    while lane < LANES {
        let reference = refs[g * LANES + lane];
        indices[lane] = reference & !NEGATED;
        negated |= ((reference >> 31) as u8) << lane;
        lane += 1;
    }
    (indices, negated)
}
