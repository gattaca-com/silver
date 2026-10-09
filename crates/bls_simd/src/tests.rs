mod g2_cases;

use std::time::{Duration, Instant};

use blst::{blst_fp, blst_fp_add, blst_fp_mul, blst_fp_sub};
use g2_cases::{
    G2_INFINITY, G2_KINDS, G2Cases, compress_g2, fp_from, plus_p, random_fp_limbs, uncompress_g2,
};
use rand::{SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::*;
use crate::{
    constants::P_U64,
    fp8::{Fp8, LANES, Limbs, pack64, unpack52},
};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect(name))
}

fn uncompress_all(inputs: &[[u8; G2_COMPRESSED_LEN]]) -> Vec<Option<blst_p2_affine>> {
    let mut out = Vec::new();
    uncompress_in_g2(inputs, |p| out.push(p));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Raw limbs, so a non-canonical representation cannot hide behind equal
/// field values.
fn g2_limbs(p: &Option<blst_p2_affine>) -> Option<[[u64; 6]; 4]> {
    p.map(|p| [p.x.fp[0].l, p.x.fp[1].l, p.y.fp[0].l, p.y.fp[1].l])
}

/// Lanes whose decoding by the kernel differs from blst's, members of G2 or
/// not, as (lane, kernel, blst). Infinity lanes, which the kernel leaves to
/// blst, are skipped. Empty without IFMA.
fn decoding_divergences(
    chunk: &[[u8; G2_COMPRESSED_LEN]; LANES],
) -> Vec<(usize, Option<blst_p2_affine>, Option<blst_p2_affine>)> {
    if !simd_available() {
        return Vec::new();
    }
    let batch = unsafe { decompress_g2::decompress(chunk) };
    (0..LANES)
        .filter(|lane| (batch.on_curve | !batch.undecided) & (1 << lane) != 0)
        .map(|lane| {
            let got = (batch.on_curve & (1 << lane) != 0).then_some(batch.points[lane]);
            (lane, got, uncompress_g2(&chunk[lane]))
        })
        .filter(|(_, got, want)| g2_limbs(got) != g2_limbs(want))
        .collect()
}

/// Lanes that blst accepts as non-identity members of G2, each with whether
/// the kernel marked it undecided. Members never meet an exceptional case, and
/// the blst fallback would hide one that did, so verdicts alone cannot catch
/// it. Empty without IFMA.
fn member_lanes_undecided(chunk: &[[u8; G2_COMPRESSED_LEN]; LANES]) -> Vec<(usize, bool)> {
    if !simd_available() {
        return Vec::new();
    }
    let batch = unsafe { decompress_g2::decompress(chunk) };
    (0..LANES)
        .filter(|&lane| chunk[lane] != G2_INFINITY && uncompress_in_g2_blst(&chunk[lane]).is_some())
        .map(|lane| (lane, batch.undecided & (1 << lane) != 0))
        .collect()
}

/// Runs `SILVER_G2_CASES` seeded batches through `check` (default 64;
/// `forever` runs until interrupted, reporting progress every 10 s) and
/// compares every lane with blst, as well as the kernel's decoding of every
/// full chunk. Each divergence is printed with the seed and case that replay
/// it. Returns how many encodings of each kind it ran.
fn assert_uncompress_in_g2_matches_blst(
    check: impl Fn(&[[u8; G2_COMPRESSED_LEN]]) -> Vec<Option<blst_p2_affine>>,
) -> [usize; G2_KINDS.len()] {
    let seed = env_u64("SILVER_G2_SEED", 1);
    let cases = match std::env::var("SILVER_G2_CASES").as_deref() {
        Ok("forever") => u64::MAX,
        Ok(n) => n.parse().expect("SILVER_G2_CASES"),
        Err(_) => 64,
    };
    let mut cases_gen = G2Cases(ChaCha8Rng::seed_from_u64(seed));
    let mut kinds = [0; G2_KINDS.len()];
    let mut divergences = 0;
    let mut kernel_members = 0;
    let mut undecided_members = 0;
    let started = Instant::now();
    let mut last_report = started;
    for case in 0..cases {
        let batch = cases_gen.batch();
        let inputs: Vec<_> = batch.iter().map(|(_, bytes)| *bytes).collect();
        let got = check(&inputs);
        assert_eq!(got.len(), inputs.len(), "seed {seed}, case {case}");
        for (lane, ((kind, bytes), got)) in batch.iter().zip(got).enumerate() {
            let want = uncompress_in_g2_blst(bytes);
            if g2_limbs(&got) != g2_limbs(&want) {
                divergences += 1;
                eprintln!(
                    "DIVERGENCE seed {seed} case {case} lane {lane} of {}: {kind:?}, \
                     check {:?}, blst {:?}, encoding {}",
                    batch.len(),
                    g2_limbs(&got),
                    g2_limbs(&want),
                    hex(bytes)
                );
            }
            kinds[*kind as usize] += 1;
        }
        for (chunk_index, chunk) in inputs.chunks_exact(LANES).enumerate() {
            for (lane, got, want) in decoding_divergences(chunk.try_into().unwrap()) {
                divergences += 1;
                eprintln!(
                    "DECODE DIVERGENCE seed {seed} case {case} lane {}: kernel {:?}, blst {:?}, \
                     encoding {}",
                    chunk_index * LANES + lane,
                    g2_limbs(&got),
                    g2_limbs(&want),
                    hex(&chunk[lane])
                );
            }
            for (lane, undecided) in member_lanes_undecided(chunk.try_into().unwrap()) {
                kernel_members += 1;
                if undecided {
                    undecided_members += 1;
                    eprintln!(
                        "UNDECIDED MEMBER seed {seed} case {case} lane {}: encoding {}",
                        chunk_index * LANES + lane,
                        hex(&chunk[lane])
                    );
                }
            }
        }
        if last_report.elapsed() >= Duration::from_secs(10) {
            last_report = Instant::now();
            let encodings: usize = kinds.iter().sum();
            eprintln!(
                "seed {seed}: {} cases, {encodings} encodings ({:.0}/s), {divergences} divergences",
                case + 1,
                encodings as f64 / started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(divergences, 0, "seed {seed}: divergences from blst");
    assert_eq!(undecided_members, 0, "seed {seed}: G2 members marked undecided");
    assert!(kernel_members > 0 || !simd_available(), "seed {seed}: no member reached the kernel");
    kinds
}

#[test]
fn uncompress_in_g2_matches_blst_on_every_kind() {
    assert!(
        simd_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    let kinds = assert_uncompress_in_g2_matches_blst(uncompress_all);
    assert!(kinds.iter().all(|&n| n > 0), "{kinds:?}");
}

#[test]
fn kernel_decodes_both_rare_square_root_branches_like_blst() {
    if !simd_available() {
        return;
    }
    let mut cases = G2Cases(ChaCha8Rng::seed_from_u64(1));
    let (mut real, mut imaginary) = (0, 0);
    for _ in 0..4 {
        let chunk = std::array::from_fn(|_| cases.zero_component());
        assert!(decoding_divergences(&chunk).is_empty());
        for bytes in &chunk {
            let y = uncompress_g2(bytes).expect("on the curve").y;
            real += (y.fp[1].l == [0; 6]) as usize;
            imaginary += (y.fp[0].l == [0; 6]) as usize;
        }
    }
    assert!(real > 0 && imaginary > 0, "{real} real and {imaginary} imaginary roots");
}

/// Fixed chunks: one with no decodable lane, one with no lane on the curve,
/// and one with a member beside them. Infinity must survive every return.
#[test]
fn kernel_early_returns_leave_infinity_to_blst() {
    if !simd_available() {
        return;
    }
    let with_flags = |flags: u8| {
        let mut bytes = [0u8; G2_COMPRESSED_LEN];
        bytes[0] = flags;
        bytes
    };
    let p = plus_p(&[0; 48]);
    let mut x1_is_p = with_flags(0);
    x1_is_p[..48].copy_from_slice(&p);
    x1_is_p[0] |= 0x80;
    let mut x0_is_p = with_flags(0x80);
    x0_is_p[48..].copy_from_slice(&p);
    let member = compress_g2(&G2Cases(ChaCha8Rng::seed_from_u64(1)).member());
    let mut uncompressed = member;
    uncompressed[0] &= 0x7f;

    let undecodable = [
        G2_INFINITY,
        with_flags(0xe0),
        with_flags(0x40),
        with_flags(0x20),
        uncompressed,
        x1_is_p,
        x0_is_p,
        with_flags(0),
    ];
    // x = 0 is off the curve: 4 + 4i has norm 32, a non-residue mod p.
    let mut off_curve = undecodable;
    off_curve[6] = with_flags(0x80);
    off_curve[7] = with_flags(0xa0);
    let mut beside_member = off_curve;
    beside_member[7] = member;

    for chunk in [undecodable, off_curve, beside_member] {
        let got = uncompress_all(&chunk);
        for (lane, bytes) in chunk.iter().enumerate() {
            assert_eq!(g2_limbs(&got[lane]), g2_limbs(&uncompress_in_g2_blst(bytes)), "{lane}");
        }
        assert!(decoding_divergences(&chunk).is_empty());
    }
    assert!(uncompress_in_g2_blst(&G2_INFINITY).is_some(), "infinity is in G2");
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
