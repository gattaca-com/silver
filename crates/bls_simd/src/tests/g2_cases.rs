//! Seeded G2 encodings, shared by the crate's unit tests and by
//! `proof/vectors.rs`, which includes this file by path. Each includer
//! provides `G2_COMPRESSED_LEN`, `LANES`, `P_U64` and `uncompress_in_g2_blst`.

use blst::{
    BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_fp_add, blst_fp_from_uint64, blst_fp_inverse,
    blst_fp_mul, blst_fp_sqr, blst_fp_sqrt, blst_fp_sub, blst_hash_to_g2, blst_p2,
    blst_p2_add_or_double, blst_p2_affine, blst_p2_compress, blst_p2_from_affine, blst_p2_is_inf,
    blst_p2_mult, blst_p2_uncompress,
};
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use super::{G2_COMPRESSED_LEN, LANES, P_U64, uncompress_in_g2_blst};

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
pub(super) fn uncompress_g2(bytes: &[u8; G2_COMPRESSED_LEN]) -> Option<blst_p2_affine> {
    let mut point = blst_p2_affine::default();
    let ok = unsafe { blst_p2_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS };
    ok.then_some(point)
}

pub(super) fn compress_g2(p: &blst_p2) -> [u8; G2_COMPRESSED_LEN] {
    let mut out = [0u8; G2_COMPRESSED_LEN];
    unsafe { blst_p2_compress(out.as_mut_ptr(), p) };
    out
}

pub(super) const G2_INFINITY: [u8; G2_COMPRESSED_LEN] = {
    let mut bytes = [0u8; G2_COMPRESSED_LEN];
    bytes[0] = 0xc0;
    bytes
};

/// `be + p` for a 48-byte big-endian coordinate below p, so no carry leaves
/// the top byte.
pub(super) fn plus_p(be: &[u8]) -> [u8; 48] {
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
pub(super) enum G2Kind {
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

pub(super) const G2_KINDS: [G2Kind; 9] = [
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
pub(super) struct G2Cases(pub(super) ChaCha8Rng);

impl G2Cases {
    pub(super) fn random_x(&mut self) -> [u8; G2_COMPRESSED_LEN] {
        let mut bytes = [0u8; G2_COMPRESSED_LEN];
        self.0.fill(&mut bytes[..]);
        bytes[0] = 0x80 | (bytes[0] & 0x3f);
        bytes[48] &= 0x1f;
        bytes
    }

    pub(super) fn curve_point(&mut self) -> blst_p2 {
        loop {
            if let Some(a) = uncompress_g2(&self.random_x()) {
                let mut p = blst_p2::default();
                unsafe { blst_p2_from_affine(&mut p, &a) };
                return p;
            }
        }
    }

    pub(super) fn member(&mut self) -> blst_p2 {
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
    pub(super) fn torsion(&mut self) -> blst_p2 {
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
    pub(super) fn zero_component(&mut self) -> [u8; G2_COMPRESSED_LEN] {
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

    pub(super) fn encoding(&mut self) -> (G2Kind, [u8; G2_COMPRESSED_LEN]) {
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

    pub(super) fn batch(&mut self) -> Vec<(G2Kind, [u8; G2_COMPRESSED_LEN])> {
        let len = self.0.gen_range(0..=2 * LANES + 1);
        (0..len).map(|_| self.encoding()).collect()
    }
}

/// Plain value below p, as blst's six limbs: 47 random bytes under a zero
/// byte.
pub(super) fn random_fp_limbs(rng: &mut impl Rng) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    rng.fill(&mut limbs[..]);
    limbs[5] &= 0x00ff_ffff_ffff_ffff;
    limbs
}

pub(super) fn fp_from(limbs: &[u64; 6]) -> blst_fp {
    let mut fp = blst_fp::default();
    unsafe { blst_fp_from_uint64(&mut fp, limbs.as_ptr()) };
    fp
}
