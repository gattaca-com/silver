use std::time::{Duration, Instant};

use blst::{
    blst_bendian_from_fp, blst_fp, blst_fp_add, blst_fp_from_uint64, blst_fp_inverse, blst_fp_mul,
    blst_fp_sqr, blst_fp_sqrt, blst_fp_sub, blst_hash_to_g2, blst_p2, blst_p2_add_or_double,
    blst_p2_compress, blst_p2_from_affine, blst_p2_is_inf, blst_p2_mult, blst_p2_uncompress,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::*;
use crate::{
    constants::P_U64,
    fp8::{Fp8, LANES, Limbs, pack64, unpack52},
};

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

/// blst's decompression alone, members of G2 or not.
fn uncompress_g2(bytes: &[u8; G2_COMPRESSED_LEN]) -> Option<blst_p2_affine> {
    let mut point = blst_p2_affine::default();
    let ok = unsafe { blst_p2_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS };
    ok.then_some(point)
}

fn compress_g2(p: &blst_p2) -> [u8; G2_COMPRESSED_LEN] {
    let mut out = [0u8; G2_COMPRESSED_LEN];
    unsafe { blst_p2_compress(out.as_mut_ptr(), p) };
    out
}

const G2_INFINITY: [u8; G2_COMPRESSED_LEN] = {
    let mut bytes = [0u8; G2_COMPRESSED_LEN];
    bytes[0] = 0xc0;
    bytes
};

/// `be + p` for a 48-byte big-endian coordinate below p, so no carry leaves
/// the top byte.
fn plus_p(be: &[u8]) -> [u8; 48] {
    let p: Vec<u8> = P_U64.iter().rev().flat_map(|w| w.to_be_bytes()).collect();
    let mut out = [0u8; 48];
    let mut carry = 0;
    for i in (0..48).rev() {
        let sum = be[i] as u16 + p[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum G2Kind {
    Member,
    OutsideG2,
    Torsion,
    MemberPlusTorsion,
    Infinity,
    /// Random coordinates, each at or above p about a fifth of the time.
    RandomX,
    /// A member's or infinity's encoding with random flag bits.
    Flags,
    /// A member's encoding with a coordinate made non-canonical.
    NonCanonical,
    /// x with one component of x³ + 4(1 + i) zero.
    ZeroComponent,
}

const G2_KINDS: [G2Kind; 9] = [
    G2Kind::Member,
    G2Kind::OutsideG2,
    G2Kind::Torsion,
    G2Kind::MemberPlusTorsion,
    G2Kind::Infinity,
    G2Kind::RandomX,
    G2Kind::Flags,
    G2Kind::NonCanonical,
    G2Kind::ZeroComponent,
];

/// Seeded G2 test encodings. Every draw comes from one ChaCha8 stream in a
/// fixed order, and retries consult blst only, so a seed always yields the
/// same cases whatever implementation is under test.
struct G2Cases(ChaCha8Rng);

impl G2Cases {
    fn random_x(&mut self) -> [u8; G2_COMPRESSED_LEN] {
        let mut bytes = [0u8; G2_COMPRESSED_LEN];
        self.0.fill(&mut bytes[..]);
        bytes[0] = 0x80 | (bytes[0] & 0x3f);
        bytes[48] &= 0x1f;
        bytes
    }

    fn curve_point(&mut self) -> blst_p2 {
        loop {
            if let Some(a) = uncompress_g2(&self.random_x()) {
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

    /// blst must reject the result. It adds p to x0, which always fits its
    /// 48 bytes, or to x1 where that fits under the flag bits. Or it sets high
    /// bits of x0, which only coordinate data can hold.
    fn non_canonical(&mut self) -> [u8; G2_COMPRESSED_LEN] {
        let mut bytes = compress_g2(&self.member());
        let flags = bytes[0] & 0xe0;
        bytes[0] &= 0x1f;
        let x1_plus_p = plus_p(&bytes[..48]);
        match self.0.gen_range(0..3) {
            0 if x1_plus_p[0] < 0x20 => bytes[..48].copy_from_slice(&x1_plus_p),
            1 => bytes[48] |= self.0.gen_range(1..8u8) << 5,
            _ => {
                let x0_plus_p = plus_p(&bytes[48..]);
                bytes[48..].copy_from_slice(&x0_plus_p);
            }
        }
        bytes[0] |= flags;
        bytes
    }

    /// x = u + v·i with one component of x³ + 4(1 + i) zero. Every element
    /// of Fp is a square in Fp2, and so is i times one, so x is on the curve.
    /// A zero imaginary part makes blst's root take its a + n = 0 select or
    /// come out real.
    fn zero_component(&mut self) -> [u8; G2_COMPRESSED_LEN] {
        let (four, three) = (fp_from(&[4, 0, 0, 0, 0, 0]), fp_from(&[3, 0, 0, 0, 0, 0]));
        loop {
            let s = fp_from(&random_fp_limbs(&mut self.0));
            let imaginary_zero: bool = self.0.r#gen();
            let negate: bool = self.0.r#gen();
            let larger: bool = self.0.r#gen();
            let (mut w, mut den, mut root) =
                (blst_fp::default(), blst_fp::default(), blst_fp::default());
            // Imaginary part 3u²v - v³ + 4 = 0 at v = s: u² = (s³ - 4) / 3s.
            // Real part u³ - 3uv² + 4 = 0 at u = s: v² = (s³ + 4) / 3s.
            let has_root = unsafe {
                blst_fp_sqr(&mut w, &s);
                blst_fp_mul(&mut w, &w, &s);
                if imaginary_zero {
                    blst_fp_sub(&mut w, &w, &four);
                } else {
                    blst_fp_add(&mut w, &w, &four);
                }
                blst_fp_mul(&mut den, &three, &s);
                blst_fp_inverse(&mut den, &den);
                blst_fp_mul(&mut w, &w, &den);
                blst_fp_sqrt(&mut root, &w)
            };
            if !has_root {
                continue;
            }
            if negate {
                unsafe { blst_fp_sub(&mut root, &blst_fp::default(), &root) };
            }
            let (u, v) = if imaginary_zero { (root, s) } else { (s, root) };
            let mut bytes = [0u8; G2_COMPRESSED_LEN];
            unsafe {
                blst_bendian_from_fp(bytes.as_mut_ptr(), &v);
                blst_bendian_from_fp(bytes[48..].as_mut_ptr(), &u);
            }
            bytes[0] |= 0x80 | if larger { 0x20 } else { 0 };
            return bytes;
        }
    }

    fn encoding(&mut self) -> (G2Kind, [u8; G2_COMPRESSED_LEN]) {
        let kind = G2_KINDS[self.0.gen_range(0..G2_KINDS.len())];
        let bytes = match kind {
            G2Kind::Member => compress_g2(&self.member()),
            G2Kind::OutsideG2 => compress_g2(&self.curve_point()),
            G2Kind::Torsion => compress_g2(&self.torsion()),
            G2Kind::MemberPlusTorsion => {
                let (m, t) = (self.member(), self.torsion());
                let mut sum = blst_p2::default();
                unsafe { blst_p2_add_or_double(&mut sum, &m, &t) };
                compress_g2(&sum)
            }
            G2Kind::Infinity => G2_INFINITY,
            G2Kind::RandomX => self.random_x(),
            G2Kind::Flags => {
                let mut bytes =
                    if self.0.r#gen() { compress_g2(&self.member()) } else { G2_INFINITY };
                bytes[0] = (bytes[0] & 0x1f) | (self.0.r#gen::<u8>() & 0xe0);
                bytes
            }
            G2Kind::NonCanonical => self.non_canonical(),
            G2Kind::ZeroComponent => self.zero_component(),
        };
        let member = uncompress_in_g2_blst(&bytes).is_some();
        match kind {
            G2Kind::Member | G2Kind::Infinity => assert!(member, "{kind:?}"),
            G2Kind::OutsideG2 |
            G2Kind::Torsion |
            G2Kind::MemberPlusTorsion |
            G2Kind::NonCanonical => assert!(!member, "{kind:?}"),
            G2Kind::ZeroComponent => assert!(uncompress_g2(&bytes).is_some(), "{kind:?}"),
            G2Kind::RandomX | G2Kind::Flags => {}
        }
        (kind, bytes)
    }

    fn batch(&mut self) -> Vec<(G2Kind, [u8; G2_COMPRESSED_LEN])> {
        let len = self.0.gen_range(0..=2 * LANES + 1);
        (0..len).map(|_| self.encoding()).collect()
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect(name))
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
    let kinds = assert_uncompress_in_g2_matches_blst(uncompress_in_g2);
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
        let got = uncompress_in_g2(&chunk);
        for (lane, bytes) in chunk.iter().enumerate() {
            assert_eq!(g2_limbs(&got[lane]), g2_limbs(&uncompress_in_g2_blst(bytes)), "{lane}");
        }
        assert!(decoding_divergences(&chunk).is_empty());
    }
    assert!(uncompress_in_g2_blst(&G2_INFINITY).is_some(), "infinity is in G2");
}

/// Plain value below p, as blst's six limbs: 47 random bytes under a zero
/// byte.
fn random_fp_limbs(rng: &mut impl Rng) -> [u64; 6] {
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
