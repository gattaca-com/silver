//! `Fp2x8::mul` and `Fp2x8::square` against the exact Karatsuba and complex
//! squaring formulas, on components up to the products' bounds: the same
//! values modulo p, with reduced components out. Also the lazy steps against
//! `add` and `sub`.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Fp2x8;
use crate::{
    bls::{
        constants::{LIMBS, MASK52},
        fp8::{
            Fp8, LANES, Limbs,
            tests::{below, near_multiple_of_p, plus_multiple_of_p},
        },
    },
    kernels_run,
};

impl Fp2x8 {
    /// For the reference formulas, which double where the kernels add lazily.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }

    /// The products' formulas with exact sums, for reduced components.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn mul_reference(&self, rhs: &Self) -> Self {
        let v0 = self.c0.mul(&rhs.c0);
        let v1 = self.c1.mul(&rhs.c1);
        let s = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1));
        Self { c0: v0.sub(&v1), c1: s.sub(&v0).sub(&v1) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn square_reference(&self) -> Self {
        let c0 = self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1));
        let c1 = self.c0.mul(&self.c1).double();
        Self { c0, c1 }
    }
}

/// Every lane of both components normalised and below 2p.
pub(crate) fn assert_reduced(v: &Fp2x8, what: &str) {
    let two_p = near_multiple_of_p(2, 0);
    for component in [&v.c0, &v.c1] {
        for limbs in component.store() {
            let normalised = limbs.iter().all(|&limb| limb <= MASK52);
            let below_two_p = limbs.iter().rev().lt(two_p.iter().rev());
            assert!(normalised && below_two_p, "{what}: {limbs:x?} not reduced");
        }
    }
}

/// The same values modulo p, for reduced `got` and `want`.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn assert_same_value(got: &Fp2x8, want: &Fp2x8, what: &str) {
    assert!(got.c0.canonical().store() == want.c0.canonical().store(), "{what}: c0");
    assert!(got.c1.canonical().store() == want.c1.canonical().store(), "{what}: c1");
}

/// One component's lanes: residues below p, and representatives of them in
/// [0, bound·p) that the code under test receives.
struct LazyLanes {
    residues: [Limbs; LANES],
    representatives: [Limbs; LANES],
}

#[derive(Clone, Copy)]
enum Draw {
    /// bound·p − 1, the largest representative.
    Largest,
    /// (bound − 1)·p, the largest multiple of p.
    LargestZero,
    Zero,
    Random,
}

impl LazyLanes {
    fn draw(rng: &mut ChaCha8Rng, bound: u64, draw: Draw) -> Self {
        let p = near_multiple_of_p(1, 0);
        let mut residues = [[0u64; LIMBS]; LANES];
        let mut representatives = [[0u64; LIMBS]; LANES];
        for lane in 0..LANES {
            let (residue, multiple) = match draw {
                Draw::Largest => (near_multiple_of_p(1, -1), bound - 1),
                Draw::LargestZero => ([0; LIMBS], bound - 1),
                Draw::Zero => ([0; LIMBS], 0),
                Draw::Random => (below(rng, &p), rng.gen_range(0..bound)),
            };
            residues[lane] = residue;
            representatives[lane] = plus_multiple_of_p(&residue, multiple);
        }
        Self { residues, representatives }
    }
}

/// Every combination of the four draws for `components` components, then
/// random draws.
fn draws(components: usize) -> Vec<Vec<Draw>> {
    let kinds = [Draw::Largest, Draw::LargestZero, Draw::Zero, Draw::Random];
    let mut out = Vec::new();
    for n in 0..kinds.len().pow(components as u32) {
        out.push(
            (0..components).map(|k| kinds[n / kinds.len().pow(k as u32) % kinds.len()]).collect(),
        );
    }
    for _ in 0..64 {
        out.push(vec![Draw::Random; components]);
    }
    out
}

/// The residues and the representatives of one Fp2 value.
#[target_feature(enable = "avx512f,avx512ifma")]
fn fp2_pair(c0: &LazyLanes, c1: &LazyLanes) -> (Fp2x8, Fp2x8) {
    (Fp2x8 { c0: Fp8::load(&c0.residues), c1: Fp8::load(&c1.residues) }, Fp2x8 {
        c0: Fp8::load(&c0.representatives),
        c1: Fp8::load(&c1.representatives),
    })
}

#[test]
fn mul_matches_the_reference_on_components_below_16p() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0xf2a);
    for (case, draw) in draws(4).iter().enumerate() {
        let c: Vec<_> = draw.iter().map(|&d| LazyLanes::draw(&mut rng, 16, d)).collect();
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe {
            let (a, lazy_a) = fp2_pair(&c[0], &c[1]);
            let (b, lazy_b) = fp2_pair(&c[2], &c[3]);
            let got = lazy_a.mul(&lazy_b);
            assert_reduced(&got, &format!("mul, case {case}"));
            assert_same_value(&got, &a.mul_reference(&b), &format!("mul, case {case}"));
        }
    }
}

#[test]
fn square_matches_the_reference_on_components_below_8p() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x5f2);
    for (case, draw) in draws(2).iter().enumerate() {
        let c: Vec<_> = draw.iter().map(|&d| LazyLanes::draw(&mut rng, 8, d)).collect();
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe {
            let (a, lazy_a) = fp2_pair(&c[0], &c[1]);
            let got = lazy_a.square();
            assert_reduced(&got, &format!("square, case {case}"));
            assert_same_value(&got, &a.square_reference(), &format!("square, case {case}"));
        }
    }
}

/// On reduced components, the lazy steps reach the limbs of `add` and `sub`.
#[test]
fn lazy_steps_match_add_and_sub() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x2a27);
    let two_p_limbs = near_multiple_of_p(2, 0);
    for case in 0..64 {
        let mut components = [[[0u64; LIMBS]; LANES]; 4];
        for component in &mut components {
            for lane in 0..LANES {
                component[lane] = match (case + lane) % 4 {
                    0 => near_multiple_of_p(2, -1),
                    1 => [0; LIMBS],
                    _ => below(&mut rng, &two_p_limbs),
                };
            }
        }
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe {
            let [a0, a1, b0, b1] = components.map(|c| Fp8::load(&c));
            let (a, b) = (Fp2x8 { c0: a0, c1: a1 }, Fp2x8 { c0: b0, c1: b1 });
            let two_p = Fp8::multiple_of_p(2);
            let sum = a.add_raw(&b).normalise().cond_sub(&two_p);
            let exact_sum = a.add(&b);
            let difference = a.sub_raw(&b, &two_p).normalise().cond_sub(&two_p);
            let exact_difference = a.sub(&b);
            for (got, want, what) in [
                (&sum.c0, &exact_sum.c0, "sum c0"),
                (&sum.c1, &exact_sum.c1, "sum c1"),
                (&difference.c0, &exact_difference.c0, "difference c0"),
                (&difference.c1, &exact_difference.c1, "difference c1"),
            ] {
                assert!(got.store() == want.store(), "{what}, case {case}");
            }
        }
    }
}
