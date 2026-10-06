use blst::{
    BLST_ERROR, blst_fp, blst_fp_add, blst_fp_from_uint64, blst_fp_mul, blst_fp_sub,
    blst_hash_to_g2, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_affine_in_g2,
    blst_p2_from_affine, blst_p2_is_inf, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::*;
use crate::fp8::{Fp8, LANES, Limbs, pack64, unpack52};

const R_LIMBS: [u64; 4] =
    [0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48];
/// h2 = 13² · 23² · 2713 · 11953 · 262069 · H2_LARGE, as (prime, exponent).
const H2_SMALL_PRIMES: [(u64, u32); 5] = [(13, 2), (23, 2), (2713, 1), (11953, 1), (262069, 1)];
const H2_LARGE_LIMBS: [u64; 7] = [
    0x826d177200c0d3b1,
    0x77d87384d026cd73,
    0xfab9c0da5cf222c3,
    0xa9d75bb98b95878a,
    0xe0490c5afca1eeb2,
    0x423572788bea4d6a,
    0x8d9f503deeeb5d5c,
];

fn times<const N: usize>(p: &blst_p2, scalar: &[u64; N]) -> blst_p2 {
    let mut out = blst_p2::default();
    // SAFETY: x86_64 is little-endian, so the limbs are the scalar's bytes.
    unsafe { blst_p2_mult(&mut out, p, scalar.as_ptr().cast(), 64 * N) };
    out
}

fn in_g2(p: &blst_p2_affine) -> bool {
    unsafe { blst_p2_affine_in_g2(p) }
}

fn affine(p: &blst_p2) -> blst_p2_affine {
    let mut out = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut out, p) };
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum G2Kind {
    Member,
    OutsideG2,
    Torsion,
    MemberPlusTorsion,
    Infinity,
}

/// Seeded G2 test points. Every draw comes from one ChaCha8 stream in a
/// fixed order, and retries consult blst only, so a seed always yields the
/// same cases whatever implementation is under test.
struct G2Cases(ChaCha8Rng);

impl G2Cases {
    fn curve_point(&mut self) -> blst_p2 {
        loop {
            let mut bytes = [0u8; 96];
            self.0.fill(&mut bytes[..]);
            bytes[0] = 0x80 | (bytes[0] & 0x3f);
            bytes[48] &= 0x1f;
            let mut a = blst_p2_affine::default();
            if unsafe { blst_p2_uncompress(&mut a, bytes.as_ptr()) } == BLST_ERROR::BLST_SUCCESS {
                let mut p = blst_p2::default();
                unsafe { blst_p2_from_affine(&mut p, &a) };
                return p;
            }
        }
    }

    fn member(&mut self) -> blst_p2 {
        let mut msg = [0u8; 32];
        self.0.fill(&mut msg[..]);
        let mut p = blst_p2::default();
        unsafe {
            blst_hash_to_g2(&mut p, msg.as_ptr(), 32, b"G2".as_ptr(), 2, std::ptr::null(), 0)
        };
        p
    }

    /// A point of small prime order ℓ: clear every other factor of r · h2,
    /// then multiply by ℓ for as long as that leaves a non-zero point.
    fn torsion(&mut self) -> blst_p2 {
        let skip = self.0.gen_range(0..H2_SMALL_PRIMES.len());
        let order = H2_SMALL_PRIMES[skip].0;
        loop {
            let mut t = times(&times(&self.curve_point(), &R_LIMBS), &H2_LARGE_LIMBS);
            for (i, (prime, exponent)) in H2_SMALL_PRIMES.iter().enumerate() {
                if i != skip {
                    t = times(&t, &[prime.pow(*exponent)]);
                }
            }
            let mut next = times(&t, &[order]);
            while unsafe { !blst_p2_is_inf(&next) } {
                t = next;
                next = times(&t, &[order]);
            }
            if unsafe { !blst_p2_is_inf(&t) } {
                return t;
            }
        }
    }

    fn point(&mut self) -> (G2Kind, blst_p2_affine) {
        let kind = match self.0.gen_range(0..5) {
            0 => G2Kind::Member,
            1 => G2Kind::OutsideG2,
            2 => G2Kind::Torsion,
            3 => G2Kind::MemberPlusTorsion,
            _ => G2Kind::Infinity,
        };
        let point = match kind {
            G2Kind::Member => affine(&self.member()),
            G2Kind::OutsideG2 => affine(&self.curve_point()),
            G2Kind::Torsion => affine(&self.torsion()),
            G2Kind::MemberPlusTorsion => {
                let (m, t) = (self.member(), self.torsion());
                let mut sum = blst_p2::default();
                unsafe { blst_p2_add_or_double(&mut sum, &m, &t) };
                affine(&sum)
            }
            G2Kind::Infinity => blst_p2_affine::default(),
        };
        let member = matches!(kind, G2Kind::Member | G2Kind::Infinity);
        assert_eq!(in_g2(&point), member, "{kind:?} point");
        (kind, point)
    }

    fn batch(&mut self) -> Vec<(G2Kind, blst_p2_affine)> {
        let len = self.0.gen_range(0..=2 * LANES + 1);
        (0..len).map(|_| self.point()).collect()
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect(name))
}

/// Runs `SILVER_G2_CASES` seeded batches through `check` and compares every
/// lane with blst. Returns how many points of each kind it ran.
fn assert_in_g2_matches_blst(check: impl Fn(&[blst_p2_affine]) -> Vec<bool>) -> [usize; 5] {
    let seed = env_u64("SILVER_G2_SEED", 1);
    let cases = env_u64("SILVER_G2_CASES", 64);
    let mut cases_gen = G2Cases(ChaCha8Rng::seed_from_u64(seed));
    let mut kinds = [0; 5];
    for case in 0..cases {
        let batch = cases_gen.batch();
        let points: Vec<_> = batch.iter().map(|(_, p)| *p).collect();
        let want: Vec<_> = points.iter().map(in_g2).collect();
        assert_eq!(check(&points), want, "seed {seed}, case {case}");
        for (kind, _) in &batch {
            kinds[*kind as usize] += 1;
        }
    }
    kinds
}

#[test]
fn g2_cases_cover_every_kind() {
    let kinds = assert_in_g2_matches_blst(|points| points.iter().map(in_g2).collect());
    assert!(kinds.iter().all(|&n| n > 0), "{kinds:?}");
}

/// Plain value below p, as blst's six limbs: 47 random bytes under a zero
/// byte.
fn random_fp_limbs(rng: &mut StdRng) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    rng.fill(&mut limbs[..]);
    limbs[5] &= 0x00ff_ffff_ffff_ffff;
    limbs
}

fn fp_from(limbs: &[u64; 6]) -> blst_fp {
    let mut fp = blst_fp::default();
    unsafe { blst_fp_from_uint64(&mut fp, limbs.as_ptr()) };
    fp
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn field_ops(a: &[Limbs; LANES], b: &[Limbs; LANES]) -> [[[u64; 6]; LANES]; 4] {
    let a = Fp8::from_plain(a);
    let b = Fp8::from_plain(b);
    [
        a.mul(&b).to_blst_limbs(),
        a.add(&b).to_blst_limbs(),
        a.sub(&b).to_blst_limbs(),
        a.neg().to_blst_limbs(),
    ]
}

#[test]
fn field_ops_match_blst() {
    if !simd_available() {
        return;
    }
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..50 {
        let mut a = [[0u64; 6]; LANES];
        let mut b = [[0u64; 6]; LANES];
        for lane in 0..LANES {
            a[lane] = random_fp_limbs(&mut rng);
            b[lane] = random_fp_limbs(&mut rng);
        }
        let a52 = a.map(|l| unpack52(&l));
        let b52 = b.map(|l| unpack52(&l));
        for lane in 0..LANES {
            assert_eq!(pack64(&a52[lane]), a[lane], "limb repacking round-trips");
        }
        let [mul, add, sub, neg] = unsafe { field_ops(&a52, &b52) };
        for lane in 0..LANES {
            let (fa, fb) = (fp_from(&a[lane]), fp_from(&b[lane]));
            let mut want = blst_fp::default();
            unsafe { blst_fp_mul(&mut want, &fa, &fb) };
            assert_eq!(mul[lane], want.l, "mul lane {lane}");
            unsafe { blst_fp_add(&mut want, &fa, &fb) };
            assert_eq!(add[lane], want.l, "add lane {lane}");
            unsafe { blst_fp_sub(&mut want, &fa, &fb) };
            assert_eq!(sub[lane], want.l, "sub lane {lane}");
            unsafe { blst_fp_sub(&mut want, &blst_fp::default(), &fa) };
            assert_eq!(neg[lane], want.l, "neg lane {lane}");
        }
    }
}
