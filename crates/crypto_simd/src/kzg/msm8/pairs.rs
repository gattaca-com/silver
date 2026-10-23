use std::arch::x86_64::{
    __m256i, __m512i, __mmask8, _mm256_loadu_si256, _mm512_and_si512, _mm512_cvtepu32_epi64,
    _mm512_load_si512, _mm512_set1_epi64, _mm512_store_si512, _mm512_test_epi64_mask,
};

use crate::{
    bls::{
        constants::LIMBS,
        fp8::{Fp8, LANES},
        g1x8_lazy::Offsets,
    },
    kzg::msm8::{buckets::NEGATED, store::PointStore},
};

/// Independent prefix-product chains: the out-of-order core overlaps two
/// `Fp8` multiplications in flight, and four keep the chain off the critical
/// path.
const CHAINS: usize = 4;
/// Groups finished together, so their dependent slope → square → product
/// chains overlap.
const PAIR: usize = 2;

/// An `Fp8` in memory.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct Fp8Memory([[u64; LANES]; LIMBS]);

impl Fp8Memory {
    const ZERO: Self = Self([[0; LANES]; LIMBS]);

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn of(value: &Fp8) -> Self {
        let mut memory = Self::ZERO;
        for j in 0..LIMBS {
            // SAFETY: each limb row is 64 bytes and `Fp8Memory` is 64-aligned.
            unsafe { _mm512_store_si512(memory.0[j].as_mut_ptr().cast(), value.0[j]) };
        }
        memory
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn load(&self) -> Fp8 {
        let mut value = Fp8::zero();
        for j in 0..LIMBS {
            // SAFETY: as in `of`.
            value.0[j] = unsafe { _mm512_load_si512(self.0[j].as_ptr().cast()) };
        }
        value
    }
}

/// Pending affine additions `out = a + b`, where `NEGATED` on a reference to
/// `a` or `b` negates the point. One inversion serves all of them, by prefix
/// products over groups of eight.
#[derive(Default)]
pub struct BatchedAdds {
    a: Vec<u32>,
    b: Vec<u32>,
    out: Vec<u32>,
    dx: Vec<Fp8Memory>,
    prefix: Vec<Fp8Memory>,
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

    /// Executes the additions. False when some pair has equal x coordinates,
    /// which the addition formula cannot take.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn run(&mut self, store: &mut PointStore) -> bool {
        debug_assert!(!self.a.is_empty(), "`queue_round` found a pair");
        let groups = self.a.len().div_ceil(PAIR * LANES) * PAIR;
        let last = self.a.len() - 1;
        let padded = groups * LANES;
        self.a.resize(padded, self.a[last]);
        self.b.resize(padded, self.b[last]);
        self.out.resize(padded, self.out[last]);
        self.dx.resize(groups, Fp8Memory::ZERO);
        self.prefix.resize(groups, Fp8Memory::ZERO);

        let c = Offsets::new();
        let mut product = [Fp8::one(); CHAINS];
        for g in 0..groups {
            let xa = store.load_x(self.indices(&self.a, g));
            let xb = store.load_x(self.indices(&self.b, g));
            let dx = xb.sub(&xa);
            if dx.is_zero_mask() != 0 {
                return false;
            }
            let k = g % CHAINS;
            product[k] = product[k].mul(&dx);
            self.dx[g] = Fp8Memory::of(&dx);
            self.prefix[g] = Fp8Memory::of(&product[k]);
        }

        let mut inverse = batch_inverse(&product);
        let mut g = groups;
        while g > 0 {
            g -= PAIR;
            let dx_inverse: [Fp8; PAIR] = std::array::from_fn(|s| {
                let gg = g + s;
                let k = gg % CHAINS;
                let dx_inverse = if gg < CHAINS {
                    inverse[k]
                } else {
                    inverse[k].mul(&self.prefix[gg - CHAINS].load())
                };
                inverse[k] = inverse[k].mul(&self.dx[gg].load());
                dx_inverse
            });
            self.finish_pair(g, &dx_inverse, store, &c);
        }
        true
    }

    /// Groups `g` and `g + 1`, step by step in lockstep so that every
    /// multiplication has an independent sibling in flight.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn finish_pair(&self, g: usize, dx_inverse: &[Fp8; PAIR], store: &mut PointStore, c: &Offsets) {
        let a: [(Fp8, Fp8); PAIR] = std::array::from_fn(|s| {
            let (x, y) = store.load_points(self.indices(&self.a, g + s));
            (x, Fp8::select(self.negated(&self.a, g + s), &y, &c.neg(&y)))
        });
        let b: [(Fp8, Fp8); PAIR] = std::array::from_fn(|s| {
            let (x, y) = store.load_points(self.indices(&self.b, g + s));
            (x, Fp8::select(self.negated(&self.b, g + s), &y, &c.neg(&y)))
        });
        let xa: [Fp8; PAIR] = std::array::from_fn(|s| a[s].0);
        let xb: [Fp8; PAIR] = std::array::from_fn(|s| b[s].0);
        let dy: [Fp8; PAIR] =
            std::array::from_fn(|s| b[s].1.sub_raw(&a[s].1, &c.two_p).normalise());
        let slope: [Fp8; PAIR] = std::array::from_fn(|s| dy[s].mul(&dx_inverse[s])); // 4p · 2p
        let sq: [Fp8; PAIR] = std::array::from_fn(|s| slope[s].square());
        let x3: [Fp8; PAIR] = std::array::from_fn(|s| {
            c.below_2p_from_8p(&sq[s].sub_raw(&xa[s], &c.two_p).sub_raw(&xb[s], &c.two_p))
        });
        let xax3: [Fp8; PAIR] =
            std::array::from_fn(|s| xa[s].sub_raw(&x3[s], &c.two_p).normalise()); // < 4p
        let y3: [Fp8; PAIR] = std::array::from_fn(|s| {
            c.below_2p_from_4p(&slope[s].mul(&xax3[s]).sub_raw(&a[s].1, &c.two_p))
        });
        for s in 0..PAIR {
            store.store_points(self.indices(&self.out, g + s), &x3[s], &y3[s]);
        }
    }

    /// The references of group `g`, without their sign.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn indices(&self, references: &[u32], g: usize) -> __m512i {
        let widened = widen(references, g);
        _mm512_and_si512(widened, _mm512_set1_epi64(i64::from(!NEGATED)))
    }

    /// The lanes of group `g` whose reference is negated.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn negated(&self, references: &[u32], g: usize) -> __mmask8 {
        let widened = widen(references, g);
        _mm512_test_epi64_mask(widened, _mm512_set1_epi64(i64::from(NEGATED)))
    }
}

/// The inverses of `values` by Montgomery's trick: one inversion and
/// 3·(CHAINS − 1) multiplications.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn batch_inverse(values: &[Fp8; CHAINS]) -> [Fp8; CHAINS] {
    let mut prefix = *values;
    for k in 1..CHAINS {
        prefix[k] = prefix[k - 1].mul(&values[k]);
    }
    let mut inverse = prefix[CHAINS - 1].inverse();
    let mut out = [Fp8::zero(); CHAINS];
    for k in (1..CHAINS).rev() {
        out[k] = inverse.mul(&prefix[k - 1]);
        inverse = inverse.mul(&values[k]);
    }
    out[0] = inverse;
    out
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn widen(references: &[u32], g: usize) -> __m512i {
    let group = &references[g * LANES..(g + 1) * LANES];
    // SAFETY: an unaligned load of the 32 bytes of `group`.
    let narrow = unsafe { _mm256_loadu_si256(group.as_ptr().cast::<__m256i>()) };
    _mm512_cvtepu32_epi64(narrow)
}
