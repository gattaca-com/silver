use blst::{blst_fp, blst_fp_add, blst_fp_from_uint64, blst_fp_mul, blst_fp_sub};
use rand::{Rng, SeedableRng, rngs::StdRng};

use super::*;
use crate::fp8::{Fp8, LANES, Limbs, pack64, unpack52};

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
