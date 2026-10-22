mod g2_cases;

use std::time::{Duration, Instant};

use blst::{
    blst_fp, blst_fp_add, blst_fp_mul, blst_fp_sqr, blst_fp_sqrt, blst_fp_sub, blst_fp2,
    blst_hash_to_g1, blst_p1, blst_p1_add_or_double, blst_p1_affine_compress, blst_p1_affine_in_g1,
    blst_p1_affine_serialize, blst_p1_from_affine, blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine,
    blst_p1_uncompress,
};
use g2_cases::{
    G2_INFINITY, G2_KINDS, G2Cases, R_LIMBS, compress_g2, fp_from, plus_p, random_fp_limbs,
    uncompress_g2,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::*;
use crate::bls::{
    constants::P_U64,
    fp8::{Fp8, LANES, Limbs, pack64, unpack52},
};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect(name))
}

/// Limbs above p, which no verdict can hold, so a skipped write shows.
const G2_SENTINEL: blst_p2_affine = {
    let fp2 = blst_fp2 { fp: [blst_fp { l: [u64::MAX; 6] }; 2] };
    blst_p2_affine { x: fp2, y: fp2 }
};

fn uncompress_all(inputs: &[[u8; G2_COMPRESSED_LEN]]) -> Vec<Option<blst_p2_affine>> {
    let mut out = vec![Some(G2_SENTINEL); inputs.len()];
    uncompress_in_g2(inputs, &mut out);
    out
}

fn uncompress_all_g1(inputs: &[[u8; COMPRESSED_LEN]]) -> Vec<Option<blst_p1_affine>> {
    let mut out = vec![None; inputs.len()];
    uncompress_in_g1(inputs, &mut out);
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

/// Every length from empty to two full chunks and a tail, so each split
/// around `MIN_KERNEL_LANES` and `LANES` is taken.
#[test]
fn uncompress_in_g2_matches_blst_at_every_length() {
    let mut cases = G2Cases(ChaCha8Rng::seed_from_u64(2));
    for len in 0..=2 * LANES + 1 {
        let inputs: Vec<_> = (0..len).map(|_| cases.encoding().1).collect();
        let got = uncompress_all(&inputs);
        assert_eq!(got.len(), len);
        for (lane, (bytes, got)) in inputs.iter().zip(&got).enumerate() {
            assert_eq!(
                g2_limbs(got),
                g2_limbs(&uncompress_in_g2_blst(bytes)),
                "len {len}, lane {lane}"
            );
        }
    }
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

pub(crate) fn serialized(p: &Option<blst_p1_affine>) -> Option<[u8; 96]> {
    p.map(|p| {
        let mut out = [0u8; 96];
        unsafe { blst_p1_affine_serialize(out.as_mut_ptr(), &p) };
        out
    })
}

pub(crate) fn compress(p: &blst_p1_affine) -> [u8; COMPRESSED_LEN] {
    let mut out = [0u8; COMPRESSED_LEN];
    unsafe { blst_p1_affine_compress(out.as_mut_ptr(), p) };
    out
}

pub(crate) fn g1_points(n: usize) -> Vec<[u8; COMPRESSED_LEN]> {
    (0..n)
        .map(|i| {
            let msg = format!("point {i}");
            let mut p = blst_p1::default();
            let mut a = blst_p1_affine::default();
            unsafe {
                blst_hash_to_g1(
                    &mut p,
                    msg.as_ptr(),
                    msg.len(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                );
                blst_p1_to_affine(&mut a, &p);
            }
            compress(&a)
        })
        .collect()
}

/// Points on the curve but, with overwhelming probability, not in G1.
pub(crate) fn curve_points_outside_g1(rng: &mut StdRng, n: usize) -> Vec<[u8; COMPRESSED_LEN]> {
    let four = fp_from(&[4, 0, 0, 0, 0, 0]);
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let x = fp_from(&random_fp_limbs(rng));
        let mut rhs = blst_fp::default();
        let mut y = blst_fp::default();
        let has_root = unsafe {
            blst_fp_sqr(&mut rhs, &x);
            blst_fp_mul(&mut rhs, &rhs, &x);
            blst_fp_add(&mut rhs, &rhs, &four);
            blst_fp_sqrt(&mut y, &rhs)
        };
        if !has_root {
            continue;
        }
        let point = blst_p1_affine { x, y };
        assert!(!unsafe { blst_p1_affine_in_g1(&point) });
        out.push(compress(&point));
    }
    out
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

#[test]
fn verdicts_match_blst_on_members_non_members_and_garbage() {
    if !simd_available() {
        return;
    }
    let mut rng = StdRng::seed_from_u64(11);
    let mut inputs = g1_points(40);
    inputs.extend(curve_points_outside_g1(&mut rng, 20));
    for i in 0..12 {
        let mut bad = inputs[i];
        match i % 4 {
            0 => bad[20] ^= 0x01,
            1 => bad[0] &= 0x7f,
            2 => bad[0] ^= 0x20,
            _ => {
                bad[0] |= 0x1f;
                bad[1..].fill(0xff);
            }
        }
        inputs.push(bad);
    }
    let mut infinity = [0u8; COMPRESSED_LEN];
    infinity[0] = 0xc0;
    inputs.push(infinity);
    for i in (1..inputs.len()).rev() {
        let j = rng.gen_range(0..=i);
        inputs.swap(i, j);
    }

    let got = uncompress_all_g1(&inputs);
    assert_eq!(got.len(), inputs.len());
    let mut members = 0;
    for (i, input) in inputs.iter().enumerate() {
        let want = uncompress_in_g1_blst(input);
        assert_eq!(serialized(&got[i]), serialized(&want), "input {i}");
        members += want.is_some() as usize;
    }
    assert_eq!(
        members, 44,
        "40 G1 points, infinity, and the 3 sign flips that only negate a member"
    );
}

/// h1 = 3 · 11² · 10177² · 859267² · 52437899², as (prime, exponent).
pub(crate) const H1_PRIMES: [(u64, u32); 5] =
    [(3, 1), (11, 2), (10177, 2), (859267, 2), (52437899, 2)];

fn g1_times<const N: usize>(p: &blst_p1, scalar: &[u64; N]) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: x86_64 is little-endian, so the limbs are the scalar's bytes.
    unsafe { blst_p1_mult(&mut out, p, scalar.as_ptr().cast(), 64 * N) };
    out
}

pub(crate) fn g1_affine(p: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut out, p) };
    out
}

/// Seeded G1 points of small prime order, built like `G2Cases::torsion`.
pub(crate) struct G1Torsion(pub(crate) ChaCha8Rng);

impl G1Torsion {
    fn curve_point(&mut self) -> blst_p1 {
        loop {
            let mut bytes = [0u8; COMPRESSED_LEN];
            self.0.fill(&mut bytes[..]);
            bytes[0] = 0x80 | (bytes[0] & 0x3f);
            let mut a = blst_p1_affine::default();
            if unsafe { blst_p1_uncompress(&mut a, bytes.as_ptr()) } == BLST_ERROR::BLST_SUCCESS {
                let mut p = blst_p1::default();
                unsafe { blst_p1_from_affine(&mut p, &a) };
                return p;
            }
        }
    }

    pub(crate) fn of_order(&mut self, prime_index: usize) -> blst_p1 {
        let order = H1_PRIMES[prime_index].0;
        loop {
            let mut t = g1_times(&self.curve_point(), &R_LIMBS);
            for (i, (prime, exponent)) in H1_PRIMES.iter().enumerate() {
                if i != prime_index {
                    t = g1_times(&t, &[prime.pow(*exponent)]);
                }
            }
            let mut next = g1_times(&t, &[order]);
            while unsafe { !blst_p1_is_inf(&next) } {
                t = next;
                next = g1_times(&t, &[order]);
            }
            if unsafe { !blst_p1_is_inf(&t) } {
                return t;
            }
        }
    }
}

#[test]
fn verdicts_match_blst_on_small_order_components() {
    if !simd_available() {
        return;
    }
    let mut torsion = G1Torsion(ChaCha8Rng::seed_from_u64(13));
    let mut inputs = g1_points(LANES);
    for prime_index in 0..H1_PRIMES.len() {
        let member = uncompress_in_g1_blst(&inputs[prime_index]).expect("a G1 member");
        let mut m = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut m, &member) };
        for _ in 0..4 {
            let t = torsion.of_order(prime_index);
            let mut sum = blst_p1::default();
            unsafe { blst_p1_add_or_double(&mut sum, &m, &t) };
            inputs.push(compress(&g1_affine(&t)));
            inputs.push(compress(&g1_affine(&sum)));
        }
    }
    for i in (1..inputs.len()).rev() {
        let j = torsion.0.gen_range(0..=i);
        inputs.swap(i, j);
    }
    assert_eq!(inputs.len() % LANES, 0, "every input goes through the vector path");

    let got = uncompress_all_g1(&inputs);
    for (i, input) in inputs.iter().enumerate() {
        assert_eq!(serialized(&got[i]), serialized(&uncompress_in_g1_blst(input)), "input {i}");
    }
    assert_eq!(got.iter().flatten().count(), LANES, "only the members are in G1");
}
