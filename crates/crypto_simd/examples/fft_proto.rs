//! Prototype for the SIMD `compute_cells` design evaluation. Not production
//! code.
//!
//!   cargo run --release -p silver_crypto_simd --example fft_proto
//!
//! Sections:
//!   1. phase breakdown of the current scalar pipeline (copied from `kzg/`);
//!   2. ns per Fr multiplication: blst FFI, inline CIOS u128, AVX-512 IFMA x8;
//!   3. a scalar iterative DIT/DIF pipeline with precomputed twiddles (blst
//!      mul);
//!   4. the AVX-512 IFMA Fr8 pipeline, checked against c-kzg on random blobs.

use std::{
    arch::x86_64::{
        __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
        _mm512_cmpgt_epu64_mask, _mm512_loadu_si512, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64,
        _mm512_mask_blend_epi64, _mm512_mask_sub_epi64, _mm512_permutexvar_epi64,
        _mm512_set1_epi64, _mm512_setr_epi64, _mm512_setzero_si512, _mm512_shuffle_i64x2,
        _mm512_srai_epi64, _mm512_srli_epi64, _mm512_storeu_si512, _mm512_sub_epi64,
        _mm512_unpackhi_epi64, _mm512_unpacklo_epi64,
    },
    hint::black_box,
    time::{Duration, Instant},
};

use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_eucl_inverse, blst_fr_from_scalar,
    blst_fr_from_uint64, blst_fr_mul, blst_fr_sub, blst_scalar, blst_scalar_fr_check,
    blst_scalar_from_bendian, blst_scalar_from_fr,
};
use c_kzg::{Blob, ethereum_kzg_settings};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

const N: usize = 4096;
const LOG_N: u32 = 12;
const EXT: usize = 8192;
const LOG_EXT: u32 = 13;
const CELL: usize = 64;
const BYTES_PER_BLOB: usize = N * 32;
const BYTES_PER_CELL: usize = CELL * 32;
const CELLS: usize = 128;
/// r, big-endian.
const MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

// ───────────────────────── blst scalar ops (as kzg/blst_ops.rs)
// ─────────────────────────

fn fr_from_u64(a: u64) -> blst_fr {
    let limbs = [a, 0, 0, 0];
    let mut fr = blst_fr::default();
    unsafe { blst_fr_from_uint64(&mut fr, limbs.as_ptr()) };
    fr
}
#[inline(always)]
fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe { blst_fr_mul(&mut out, a, b) };
    out
}
#[inline(always)]
fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe { blst_fr_add(&mut out, a, b) };
    out
}
#[inline(always)]
fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe { blst_fr_sub(&mut out, a, b) };
    out
}
fn fr_inverse(a: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe { blst_fr_eucl_inverse(&mut out, a) };
    out
}
fn fr_from_bytes(bytes: &[u8; 32]) -> Option<blst_fr> {
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    unsafe {
        blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        if !blst_scalar_fr_check(&scalar) {
            return None;
        }
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    Some(fr)
}
fn fr_to_bytes(a: &blst_fr) -> [u8; 32] {
    let mut scalar = blst_scalar::default();
    let mut bytes = [0u8; 32];
    unsafe {
        blst_scalar_from_fr(&mut scalar, a);
        blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
    }
    bytes
}

const R_MINUS_ONE: [u64; 4] =
    [0xffff_ffff_0000_0000, 0x53bd_a402_fffe_5bfe, 0x3339_d808_09a1_d805, 0x73ed_a753_299d_7d48];

fn primitive_root(log_order: u32) -> blst_fr {
    let base = fr_from_u64(7);
    let mut root = fr_from_u64(1);
    let mut bit = 256;
    while bit > log_order {
        bit -= 1;
        root = fr_mul(&root, &root);
        if (R_MINUS_ONE[(bit / 64) as usize] >> (bit % 64)) & 1 == 1 {
            root = fr_mul(&root, &base);
        }
    }
    root
}
fn roots_of_unity(log_order: u32) -> Vec<blst_fr> {
    let order = 1usize << log_order;
    let root = primitive_root(log_order);
    let mut roots = Vec::with_capacity(order);
    let mut power = fr_from_u64(1);
    for _ in 0..order {
        roots.push(power);
        power = fr_mul(&power, &root);
    }
    roots
}
fn inverse_roots(roots: &[blst_fr]) -> Vec<blst_fr> {
    let n = roots.len();
    let mut inverse = Vec::with_capacity(n);
    inverse.push(roots[0]);
    for i in 1..n {
        inverse.push(roots[n - i]);
    }
    inverse
}
fn reverse_bits(index: usize, bits: u32) -> usize {
    index.reverse_bits() >> (usize::BITS - bits)
}

// ───────────────────────── section 1: current scalar pipeline
// ─────────────────────────

fn transform(
    out: &mut [blst_fr],
    input: &[blst_fr],
    start: usize,
    stride: usize,
    roots: &[blst_fr],
    roots_stride: usize,
) {
    let n = out.len();
    if n == 1 {
        out[0] = input[start];
        return;
    }
    let half = n / 2;
    transform(&mut out[..half], input, start, 2 * stride, roots, 2 * roots_stride);
    transform(&mut out[half..], input, start + stride, 2 * stride, roots, 2 * roots_stride);
    for i in 0..half {
        let odd = fr_mul(&out[half + i], &roots[i * roots_stride]);
        out[half + i] = fr_sub(&out[i], &odd);
        out[i] = fr_add(&out[i], &odd);
    }
}
fn fft_rec(out: &mut [blst_fr], input: &[blst_fr], roots: &[blst_fr]) {
    let n = out.len();
    transform(out, input, 0, 1, roots, roots.len() / n);
}

struct Current {
    roots: Vec<blst_fr>,
    inverse_roots: Vec<blst_fr>,
    inverse_size: blst_fr,
    shift_powers: Vec<blst_fr>,
    evaluations: Vec<blst_fr>,
    coefficients: Vec<blst_fr>,
    t_decode: Duration,
    t_ifft: Duration,
    t_shift: Duration,
    t_fft: Duration,
    t_write: Duration,
}

impl Current {
    fn new() -> Self {
        let roots = roots_of_unity(LOG_N);
        let mut shift_powers = roots_of_unity(LOG_EXT);
        shift_powers.truncate(N);
        Self {
            inverse_roots: inverse_roots(&roots),
            roots,
            inverse_size: fr_inverse(&fr_from_u64(N as u64)),
            shift_powers,
            evaluations: vec![blst_fr::default(); N],
            coefficients: vec![blst_fr::default(); N],
            t_decode: Duration::ZERO,
            t_ifft: Duration::ZERO,
            t_shift: Duration::ZERO,
            t_fft: Duration::ZERO,
            t_write: Duration::ZERO,
        }
    }

    fn compute(&mut self, blob: &[u8; BYTES_PER_BLOB], cells: &mut [[u8; BYTES_PER_CELL]; CELLS]) {
        let t = Instant::now();
        for i in 0..N {
            let bytes: &[u8; 32] = blob[i * 32..(i + 1) * 32].try_into().unwrap();
            self.evaluations[reverse_bits(i, LOG_N)] = fr_from_bytes(bytes).unwrap();
        }
        for k in 0..CELLS / 2 {
            cells[k].copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
        }
        self.t_decode += t.elapsed();

        let t = Instant::now();
        fft_rec(&mut self.coefficients, &self.evaluations, &self.inverse_roots);
        for i in 0..N {
            self.coefficients[i] = fr_mul(&self.coefficients[i], &self.inverse_size);
        }
        self.t_ifft += t.elapsed();

        let t = Instant::now();
        for k in 0..N {
            self.coefficients[k] = fr_mul(&self.coefficients[k], &self.shift_powers[k]);
        }
        self.t_shift += t.elapsed();

        let t = Instant::now();
        fft_rec(&mut self.evaluations, &self.coefficients, &self.roots);
        self.t_fft += t.elapsed();

        let t = Instant::now();
        for j in 0..N {
            let bytes = fr_to_bytes(&self.evaluations[reverse_bits(j, LOG_N)]);
            let cell = CELLS / 2 + j / CELL;
            let at = j % CELL * 32;
            cells[cell][at..at + 32].copy_from_slice(&bytes);
        }
        self.t_write += t.elapsed();
    }
}

// ───────────────────────── section 3: scalar iterative DIT/DIF
// ─────────────────────────

/// DIT: bit-reversed input, natural output; DIF: natural input, bit-reversed
/// output. Per-stage contiguous twiddles. No permutation anywhere.
struct ScalarIter {
    /// Stage s (len = 2^(s+1)) twiddles: inverse roots of order len, len/2 of
    /// them.
    dit_twiddles: Vec<Vec<blst_fr>>,
    dif_twiddles: Vec<Vec<blst_fr>>,
    /// ω8192^k / 4096, natural k.
    pointwise: Vec<blst_fr>,
    buf: Vec<blst_fr>,
}

impl ScalarIter {
    fn new() -> Self {
        let roots = roots_of_unity(LOG_N);
        let inv = inverse_roots(&roots);
        let mut dit_twiddles = Vec::new();
        let mut dif_twiddles = Vec::new();
        for s in 0..LOG_N {
            let len = 1usize << (s + 1);
            let step = N / len;
            dit_twiddles.push((0..len / 2).map(|j| inv[j * step]).collect());
            dif_twiddles.push((0..len / 2).map(|j| roots[j * step]).collect());
        }
        let inv_n = fr_inverse(&fr_from_u64(N as u64));
        let ext = roots_of_unity(LOG_EXT);
        let pointwise = (0..N).map(|k| fr_mul(&ext[k], &inv_n)).collect();
        Self { dit_twiddles, dif_twiddles, pointwise, buf: vec![blst_fr::default(); N] }
    }

    fn compute(&mut self, blob: &[u8; BYTES_PER_BLOB], cells: &mut [[u8; BYTES_PER_CELL]; CELLS]) {
        for i in 0..N {
            let bytes: &[u8; 32] = blob[i * 32..(i + 1) * 32].try_into().unwrap();
            self.buf[i] = fr_from_bytes(bytes).unwrap();
        }
        for k in 0..CELLS / 2 {
            cells[k].copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
        }
        let a = &mut self.buf;
        for s in 0..LOG_N as usize {
            let half = 1usize << s;
            let tw = &self.dit_twiddles[s];
            let mut i = 0;
            while i < N {
                for j in 0..half {
                    let m = fr_mul(&a[i + j + half], &tw[j]);
                    let u = a[i + j];
                    a[i + j] = fr_add(&u, &m);
                    a[i + j + half] = fr_sub(&u, &m);
                }
                i += 2 * half;
            }
        }
        for k in 0..N {
            a[k] = fr_mul(&a[k], &self.pointwise[k]);
        }
        for s in (0..LOG_N as usize).rev() {
            let half = 1usize << s;
            let tw = &self.dif_twiddles[s];
            let mut i = 0;
            while i < N {
                for j in 0..half {
                    let u = a[i + j];
                    let v = a[i + j + half];
                    a[i + j] = fr_add(&u, &v);
                    a[i + j + half] = fr_mul(&fr_sub(&u, &v), &tw[j]);
                }
                i += 2 * half;
            }
        }
        for j in 0..N {
            let bytes = fr_to_bytes(&a[j]);
            let cell = CELLS / 2 + j / CELL;
            let at = j % CELL * 32;
            cells[cell][at..at + 32].copy_from_slice(&bytes);
        }
    }
}

// ───────────────────────── section 2: inline CIOS Montgomery (4 x 64)
// ─────────────────────────

const R64: [u64; 4] =
    [0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48];
const R_INV64: u64 = 0xfffffffeffffffff;

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + (b as u128) * (c as u128) + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// Montgomery product with R = 2^256, result in [0, r) given inputs in [0, r).
#[inline(always)]
fn cios_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    for i in 0..4 {
        let mut c = 0;
        for j in 0..4 {
            (t[j], c) = mac(t[j], a[j], b[i], c);
        }
        let (s, c2) = t[4].overflowing_add(c);
        t[4] = s;
        t[5] = c2 as u64;
        let m = t[0].wrapping_mul(R_INV64);
        let (_, mut c) = mac(t[0], m, R64[0], 0);
        for j in 1..4 {
            (t[j - 1], c) = mac(t[j], m, R64[j], c);
        }
        let (s, c2) = t[4].overflowing_add(c);
        t[3] = s;
        t[4] = t[5] + c2 as u64;
    }
    let mut out = [t[0], t[1], t[2], t[3]];
    // conditional subtraction
    let mut d = [0u64; 4];
    let mut borrow = 0u64;
    for j in 0..4 {
        let (s1, b1) = out[j].overflowing_sub(R64[j]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        d[j] = s2;
        borrow = (b1 | b2) as u64;
    }
    if borrow == 0 && t[4] == 0 || t[4] != 0 {
        out = d;
    }
    out
}

// ───────────────────────── section 2/4: AVX-512 IFMA Fr x 8
// ─────────────────────────

const LIMBS: usize = 5;
const MASK52: u64 = (1 << 52) - 1;
/// r as 52-bit limbs.
const R52: [u64; LIMBS] =
    [0xfffff00000001, 0x2fffe5bfefff, 0x9a1d80553bda4, 0x7d483339d8080, 0x73eda753299d];
const TWO_R52: [u64; LIMBS] =
    [0xffffe00000002, 0x5fffcb7fdfff, 0x343b00aa77b48, 0xfa906673b0101, 0xe7db4ea6533a];
const THREE_R52: [u64; LIMBS] =
    [0xffffd00000003, 0x8fffb13fcfff, 0xce5880ffb38ec, 0x77d899ad88181, 0x15bc8f5f97cd8];
const FOUR_R52: [u64; LIMBS] =
    [0xffffc00000004, 0xbfff96ffbfff, 0x68760154ef690, 0xf520cce760202, 0x1cfb69d4ca675];
/// −r⁻¹ mod 2^52.
const R_INV52: u64 = 0xffffeffffffff;
/// blst form of 16: multiplying a blst-form value by this gives the value
/// times 2^260 mod r, which is its R' = 2^260 Montgomery form.
const SIXTEEN_BLST: [u64; 4] =
    [0x22ffffffdd, 0x8d12939700396c23, 0xff1776e6aedf7745, 0x26821fa14f77df20];

#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct Fr8([__m512i; LIMBS]);

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn splat(x: u64) -> __m512i {
    _mm512_set1_epi64(x as i64)
}
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn zero() -> __m512i {
    _mm512_setzero_si512()
}
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn splat_limbs(l: &[u64; LIMBS]) -> Fr8 {
    Fr8([splat(l[0]), splat(l[1]), splat(l[2]), splat(l[3]), splat(l[4])])
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn muladd_row(t: &mut [__m512i; 2 * LIMBS + 1], a: &[__m512i; LIMBS], b_i: __m512i, i: usize) {
    for j in 0..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[j], b_i);
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[j], b_i);
    }
}
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn reduce_row(t: &mut [__m512i; 2 * LIMBS + 1], p: &[__m512i; LIMBS], pinv: __m512i, i: usize) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], pinv);
    muladd_row(t, p, q, i);
    t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
}

impl Fr8 {
    /// Montgomery product, R' = 2^260. Inputs: normalised 52-bit limbs; `a`
    /// below 32r, `b` below 2r. Output normalised, below 2r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        let p = splat_limbs(&R52).0;
        let pinv = splat(R_INV52);
        let mut t = [zero(); 2 * LIMBS + 1];
        muladd_row(&mut t, &self.0, rhs.0[0], 0);
        muladd_row(&mut t, &self.0, rhs.0[1], 1);
        muladd_row(&mut t, &self.0, rhs.0[2], 2);
        muladd_row(&mut t, &self.0, rhs.0[3], 3);
        muladd_row(&mut t, &self.0, rhs.0[4], 4);
        reduce_row(&mut t, &p, pinv, 0);
        reduce_row(&mut t, &p, pinv, 1);
        reduce_row(&mut t, &p, pinv, 2);
        reduce_row(&mut t, &p, pinv, 3);
        reduce_row(&mut t, &p, pinv, 4);
        let mask = splat(MASK52);
        let mut r = [zero(); LIMBS];
        r[0] = t[LIMBS];
        for j in 0..LIMBS - 1 {
            r[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(r[j]));
            r[j] = _mm512_and_si512(r[j], mask);
        }
        Self(r)
    }

    /// Limb-wise `a + b`, no carries.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn add_raw(&self, rhs: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_add_epi64(self.0[j], rhs.0[j]);
        }
        Self(s)
    }
    /// Limb-wise `a + c − b`, no carries; limbs may go negative.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn sub_raw(&self, rhs: &Self, c: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_sub_epi64(_mm512_add_epi64(self.0[j], c.0[j]), rhs.0[j]);
        }
        Self(s)
    }
    /// Signed carry propagation into 52-bit limbs; the value must be in [0,
    /// 2^260).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn normalise(&self) -> Self {
        let mask = splat(MASK52);
        let mut s = self.0;
        for j in 0..LIMBS - 1 {
            let carry = _mm512_srai_epi64::<52>(s[j]);
            s[j] = _mm512_and_si512(s[j], mask);
            s[j + 1] = _mm512_add_epi64(s[j + 1], carry);
        }
        Self(s)
    }
    /// `self − c` with borrow; (difference normalised, borrow lanes where self
    /// < c).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn sub_borrow(&self, c: &Self) -> (Self, __mmask8) {
        let mask = splat(MASK52);
        let mut d = [zero(); LIMBS];
        let mut borrow = zero();
        for j in 0..LIMBS {
            let s = _mm512_add_epi64(_mm512_sub_epi64(self.0[j], c.0[j]), borrow);
            borrow = _mm512_srai_epi64::<63>(s);
            d[j] = _mm512_and_si512(s, mask);
        }
        (Self(d), _mm512_cmpeq_epi64_mask(borrow, splat(u64::MAX)))
    }
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn blend(k: __mmask8, a: &Self, b: &Self) -> Self {
        let mut r = [zero(); LIMBS];
        for j in 0..LIMBS {
            r[j] = _mm512_mask_blend_epi64(k, a.0[j], b.0[j]);
        }
        Self(r)
    }
    /// `self` normalised and below 2c: subtract c where self ≥ c.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn cond_sub(&self, c: &Self) -> Self {
        let (d, borrow) = self.sub_borrow(c);
        Self::blend(borrow, &d, self)
    }
    /// `self + rhs`, minus `c` on lanes whose un-normalised top limb exceeds
    /// `c`'s top limb; the result is below 2c + 2^209-ish slack. Normalised.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn add_approx_reduce(&self, rhs: &Self, c: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_add_epi64(self.0[j], rhs.0[j]);
        }
        let k = _mm512_cmpgt_epu64_mask(s[LIMBS - 1], c.0[LIMBS - 1]);
        for j in 0..LIMBS {
            s[j] = _mm512_mask_sub_epi64(s[j], k, s[j], c.0[j]);
        }
        Self(s).normalise()
    }
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn permute(&self, idx: __m512i) -> Self {
        let mut r = [zero(); LIMBS];
        for j in 0..LIMBS {
            r[j] = _mm512_permutexvar_epi64(idx, self.0[j]);
        }
        Self(r)
    }
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn load(src: &[[u64; 8]; LIMBS]) -> Self {
        let mut r = [zero(); LIMBS];
        for j in 0..LIMBS {
            r[j] = unsafe { _mm512_loadu_si512(src[j].as_ptr().cast()) };
        }
        Self(r)
    }
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn store(&self, dst: &mut [[u64; 8]; LIMBS]) {
        for j in 0..LIMBS {
            unsafe { _mm512_storeu_si512(dst[j].as_mut_ptr().cast(), self.0[j]) };
        }
    }
}

/// 4 x 64-bit little-endian limbs (256-bit) to 5 x 52-bit limbs.
#[inline(always)]
fn unpack52(x: &[u64; 4]) -> [u64; LIMBS] {
    [
        x[0] & MASK52,
        ((x[0] >> 52) | (x[1] << 12)) & MASK52,
        ((x[1] >> 40) | (x[2] << 24)) & MASK52,
        ((x[2] >> 28) | (x[3] << 36)) & MASK52,
        x[3] >> 16,
    ]
}
#[inline(always)]
fn pack64(l: &[u64; LIMBS]) -> [u64; 4] {
    [
        l[0] | (l[1] << 52),
        (l[1] >> 12) | (l[2] << 40),
        (l[2] >> 24) | (l[3] << 28),
        (l[3] >> 36) | (l[4] << 16),
    ]
}

/// blst-form value → R' = 2^260 Montgomery form as 52-bit limbs.
fn to_r260(a: &blst_fr) -> [u64; LIMBS] {
    let sixteen = blst_fr { l: SIXTEEN_BLST };
    let m = fr_mul(a, &sixteen);
    unpack52(&m.l)
}

/// Eight consecutive elements, SoA.
type Soa = [[u64; 8]; LIMBS];

fn soa_from_frs(values: &[blst_fr]) -> Soa {
    let mut out = [[0u64; 8]; LIMBS];
    for lane in 0..8 {
        let l = to_r260(&values[lane]);
        for j in 0..LIMBS {
            out[j][lane] = l[j];
        }
    }
    out
}

struct Simd {
    /// Stage s ≥ 3 (len = 2^(s+1)): len/16 twiddle vectors, lanes j..j+7.
    dit_twiddles: Vec<Vec<Soa>>,
    dif_twiddles: Vec<Vec<Soa>>,
    /// In-register twiddle vectors for len = 4 and len = 8.
    dit_w4: Soa,
    dit_w8: Soa,
    dif_w4: Soa,
    dif_w8: Soa,
    pointwise: Vec<Soa>,
    buf: Vec<Soa>,
    phase: [Duration; 5],
}

impl Simd {
    fn new() -> Self {
        let roots = roots_of_unity(LOG_N);
        let inv = inverse_roots(&roots);
        let one = fr_from_u64(1);
        let table = |rs: &[blst_fr]| -> Vec<Vec<Soa>> {
            (0..LOG_N as usize)
                .map(|s| {
                    let len = 1usize << (s + 1);
                    let step = N / len;
                    if len < 16 {
                        return (0..len / 2).map(|j| soa_from_frs(&[rs[j * step]; 8])).collect();
                    }
                    (0..len / 16)
                        .map(|v| {
                            let eight: Vec<blst_fr> =
                                (0..8).map(|l| rs[(8 * v + l) * step]).collect();
                            soa_from_frs(&eight)
                        })
                        .collect()
                })
                .collect()
        };
        // len = 4: pairs (0,2),(1,3): lane l uses w^(l mod 2) of order 4.
        let w4 = |rs: &[blst_fr]| {
            let w = rs[N / 4];
            soa_from_frs(&[one, w, one, w, one, w, one, w])
        };
        // len = 8: pairs (l, l+4): lane l uses w^(l mod 4) of order 8.
        let w8 = |rs: &[blst_fr]| {
            let w = rs[N / 8];
            let w2 = fr_mul(&w, &w);
            let w3 = fr_mul(&w2, &w);
            soa_from_frs(&[one, w, w2, w3, one, w, w2, w3])
        };
        let inv_n = fr_inverse(&fr_from_u64(N as u64));
        let ext = roots_of_unity(LOG_EXT);
        let pointwise = (0..N / 8)
            .map(|v| {
                let eight: Vec<blst_fr> = (0..8).map(|l| fr_mul(&ext[8 * v + l], &inv_n)).collect();
                soa_from_frs(&eight)
            })
            .collect();
        Self {
            dit_twiddles: table(&inv),
            dif_twiddles: table(&roots),
            dit_w4: w4(&inv),
            dit_w8: w8(&inv),
            dif_w4: w4(&roots),
            dif_w8: w8(&roots),
            pointwise,
            buf: vec![[[0u64; 8]; LIMBS]; N / 8],
            phase: [Duration::ZERO; 5],
        }
    }

    /// Element i lives at vector (i/64)*8 + i%8, lane (i/8)%8.
    fn decode_t(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> bool {
        let mut ok = true;
        for i in 0..N {
            let e = &blob[i * 32..(i + 1) * 32];
            let x = [
                u64::from_be_bytes(e[24..32].try_into().unwrap()),
                u64::from_be_bytes(e[16..24].try_into().unwrap()),
                u64::from_be_bytes(e[8..16].try_into().unwrap()),
                u64::from_be_bytes(e[0..8].try_into().unwrap()),
            ];
            let mut less = false;
            for j in (0..4).rev() {
                if x[j] != R64[j] {
                    less = x[j] < R64[j];
                    break;
                }
            }
            ok &= less;
            let l = unpack52(&x);
            let (v, lane) = ((i / 64) * 8 + i % 8, (i / 8) % 8);
            for j in 0..LIMBS {
                self.buf[v][j][lane] = l[j];
            }
        }
        ok
    }

    fn encode_t(&self, cells: &mut [[u8; BYTES_PER_CELL]; CELLS]) {
        for i in 0..N {
            let (v, lane) = ((i / 64) * 8 + i % 8, (i / 8) % 8);
            let mut l = [0u64; LIMBS];
            for j in 0..LIMBS {
                l[j] = self.buf[v][j][lane];
            }
            let x = pack64(&l);
            let cell = CELLS / 2 + i / CELL;
            let at = i % CELL * 32;
            let out = &mut cells[cell][at..at + 32];
            out[0..8].copy_from_slice(&x[3].to_be_bytes());
            out[8..16].copy_from_slice(&x[2].to_be_bytes());
            out[16..24].copy_from_slice(&x[1].to_be_bytes());
            out[24..32].copy_from_slice(&x[0].to_be_bytes());
        }
    }

    fn compute_t(
        &mut self,
        blob: &[u8; BYTES_PER_BLOB],
        cells: &mut [[u8; BYTES_PER_CELL]; CELLS],
    ) -> bool {
        if !self.decode_t(blob) {
            return false;
        }
        for k in 0..CELLS / 2 {
            cells[k].copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
        }
        unsafe { self.transform_t() };
        self.encode_t(cells);
        true
    }

    /// All 24 stage passes lane-aligned. Stages len 2..8 run per block of eight
    /// vectors in the transposed layout; a block transpose switches layouts.
    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn transform_t(&mut self) {
        let two_r = splat_limbs(&TWO_R52);
        let three_r = splat_limbs(&THREE_R52);
        let r = splat_limbs(&R52);
        let buf = &mut self.buf;
        let vectors = N / 8;
        let mut t = Instant::now();

        dit_stage_no_mul(buf, 1, &r);
        for s in 1..3 {
            let mut b = 0;
            while b < vectors {
                dit_stage::<false, true>(&mut buf[b..b + 8], &self.dit_twiddles[s], 1 << s, &two_r);
                b += 8;
            }
        }
        transpose_blocks(buf);
        self.phase[0] += t.elapsed();
        t = Instant::now();
        for s in 3..LOG_N as usize {
            dit_stage::<false, true>(buf, &self.dit_twiddles[s], 1usize << (s - 3), &two_r);
        }
        self.phase[1] += t.elapsed();
        t = Instant::now();
        for v in 0..vectors {
            let a = Fr8::load(&buf[v]).normalise();
            a.mul(&Fr8::load(&self.pointwise[v])).store(&mut buf[v]);
        }
        self.phase[2] += t.elapsed();
        t = Instant::now();
        for s in (3..LOG_N as usize).rev() {
            dif_stage::<0, false>(buf, &self.dif_twiddles[s], 1usize << (s - 3), &two_r, &three_r);
        }
        self.phase[3] += t.elapsed();
        t = Instant::now();
        transpose_blocks(buf);
        for s in (1..3).rev() {
            let mut b = 0;
            while b < vectors {
                dif_stage::<0, false>(
                    &mut buf[b..b + 8],
                    &self.dif_twiddles[s],
                    1 << s,
                    &two_r,
                    &three_r,
                );
                b += 8;
            }
        }
        dif_stage_no_mul_canonical(buf, 1, &two_r, &r);
        self.phase[4] += t.elapsed();
    }

    /// False when some element is not below r.
    fn decode(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> bool {
        let mut ok = true;
        for v in 0..N / 8 {
            for lane in 0..8 {
                let i = 8 * v + lane;
                let e = &blob[i * 32..(i + 1) * 32];
                let x = [
                    u64::from_be_bytes(e[24..32].try_into().unwrap()),
                    u64::from_be_bytes(e[16..24].try_into().unwrap()),
                    u64::from_be_bytes(e[8..16].try_into().unwrap()),
                    u64::from_be_bytes(e[0..8].try_into().unwrap()),
                ];
                // x < r ?
                let mut less = false;
                for j in (0..4).rev() {
                    if x[j] != R64[j] {
                        less = x[j] < R64[j];
                        break;
                    }
                }
                ok &= less;
                let l = unpack52(&x);
                for j in 0..LIMBS {
                    self.buf[v][j][lane] = l[j];
                }
            }
        }
        ok
    }

    fn encode(&self, cells: &mut [[u8; BYTES_PER_CELL]; CELLS]) {
        for v in 0..N / 8 {
            for lane in 0..8 {
                let i = 8 * v + lane;
                let mut l = [0u64; LIMBS];
                for j in 0..LIMBS {
                    l[j] = self.buf[v][j][lane];
                }
                let x = pack64(&l);
                let cell = CELLS / 2 + i / CELL;
                let at = i % CELL * 32;
                let out = &mut cells[cell][at..at + 32];
                out[0..8].copy_from_slice(&x[3].to_be_bytes());
                out[8..16].copy_from_slice(&x[2].to_be_bytes());
                out[16..24].copy_from_slice(&x[1].to_be_bytes());
                out[24..32].copy_from_slice(&x[0].to_be_bytes());
            }
        }
    }

    fn compute<const MODE: u8, const UNROLL: bool, const LAZY: bool, const K: usize>(
        &mut self,
        blob: &[u8; BYTES_PER_BLOB],
        cells: &mut [[u8; BYTES_PER_CELL]; CELLS],
    ) -> bool {
        if !self.decode(blob) {
            return false;
        }
        for k in 0..CELLS / 2 {
            cells[k].copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
        }
        unsafe { self.transform::<MODE, UNROLL, LAZY, K>() };
        self.encode(cells);
        true
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn transform<const MODE: u8, const UNROLL: bool, const LAZY: bool, const K: usize>(
        &mut self,
    ) {
        let two_r = splat_limbs(&TWO_R52);
        let three_r = splat_limbs(&THREE_R52);
        let r = splat_limbs(&R52);
        let swap1 = _mm512_setr_epi64(1, 0, 3, 2, 5, 4, 7, 6);
        let swap2 = _mm512_setr_epi64(2, 3, 0, 1, 6, 7, 4, 5);
        let swap4 = _mm512_setr_epi64(4, 5, 6, 7, 0, 1, 2, 3);
        let dit_w4 = Fr8::load(&self.dit_w4);
        let dit_w8 = Fr8::load(&self.dit_w8);
        let dif_w4 = Fr8::load(&self.dif_w4);
        let dif_w8 = Fr8::load(&self.dif_w8);
        let buf = &mut self.buf;
        let vectors = N / 8;
        let mut t = Instant::now();

        // ── DIT inverse: in-register stages len = 2, 4, 8, K vectors interleaved.
        // Bounds: input < r; len 2 → < 2r; len 4 → < 4r; len 8 → < 6r.
        let mut v = 0;
        while v < vectors {
            let mut xs = [Fr8::load(&buf[v]); K];
            for k in 1..K {
                xs[k] = Fr8::load(&buf[v + k]);
            }
            dit_in_register::<K>(&mut xs, swap1, 0xAA, None, &r);
            dit_in_register::<K>(&mut xs, swap2, 0xCC, Some(&dit_w4), &two_r);
            dit_in_register::<K>(&mut xs, swap4, 0xF0, Some(&dit_w8), &two_r);
            for k in 0..K {
                xs[k].store(&mut buf[v + k]);
            }
            v += K;
        }
        self.phase[0] += t.elapsed();
        t = Instant::now();
        // ── DIT stages len = 16..4096: lane-aligned. Bound grows by 2r per stage:
        // after 9 stages < 24r < 32r.
        for s in 3..LOG_N as usize {
            dit_stage::<UNROLL, LAZY>(buf, &self.dit_twiddles[s], 1usize << (s - 3), &two_r);
        }
        self.phase[1] += t.elapsed();
        t = Instant::now();
        // ── pointwise ω8192^k / n: resets the bound to < 2r.
        for v in 0..vectors {
            let a = Fr8::load(&buf[v]);
            let a = if LAZY { a.normalise() } else { a };
            a.mul(&Fr8::load(&self.pointwise[v])).store(&mut buf[v]);
        }
        self.phase[2] += t.elapsed();
        t = Instant::now();
        // ── DIF forward, lane-aligned stages len = 4096..16. Invariant < 2r:
        // a' = A + B cond-sub 2r; b' = (A + 2r − B)·w < 2r.
        for s in (3..LOG_N as usize).rev() {
            dif_stage::<MODE, UNROLL>(
                buf,
                &self.dif_twiddles[s],
                1usize << (s - 3),
                &two_r,
                &three_r,
            );
        }
        self.phase[3] += t.elapsed();
        t = Instant::now();
        // ── DIF in-register stages len = 8, 4, 2, then canonicalise. K vectors
        // interleaved.
        let four_r = splat_limbs(&FOUR_R52);
        let mut v = 0;
        while v < vectors {
            let mut xs = [Fr8::load(&buf[v]); K];
            for k in 1..K {
                xs[k] = Fr8::load(&buf[v + k]);
            }
            dif_in_register::<K, MODE>(&mut xs, swap4, 0xF0, Some(&dif_w8), &two_r, &three_r);
            dif_in_register::<K, MODE>(&mut xs, swap2, 0xCC, Some(&dif_w4), &two_r, &three_r);
            dif_in_register::<K, MODE>(&mut xs, swap1, 0xAA, None, &two_r, &three_r);
            for k in 0..K {
                let x = if MODE == 1 { xs[k].cond_sub(&four_r) } else { xs[k] };
                x.cond_sub(&two_r).cond_sub(&r).store(&mut buf[v + k]);
            }
            v += K;
        }
        self.phase[4] += t.elapsed();
    }
}

/// One in-register DIT stage on K independent vectors: lanes of `mask` are the
/// upper butterfly halves, `idx` swaps each lane with its partner. `w` is the
/// per-lane twiddle (None: all ones). `c` is the multiple of r added before
/// subtracting.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dit_in_register<const K: usize>(
    xs: &mut [Fr8; K],
    idx: __m512i,
    mask: __mmask8,
    w: Option<&Fr8>,
    c: &Fr8,
) {
    let mut a = [xs[0]; K];
    let mut b = [xs[0]; K];
    for k in 0..K {
        let u = xs[k].permute(idx);
        a[k] = Fr8::blend(mask, &xs[k], &u);
        b[k] = Fr8::blend(mask, &u, &xs[k]);
    }
    if let Some(w) = w {
        for k in 0..K {
            b[k] = b[k].mul(w);
        }
    }
    for k in 0..K {
        xs[k] = Fr8::blend(mask, &a[k].add_raw(&b[k]), &a[k].sub_raw(&b[k], c)).normalise();
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dif_in_register<const K: usize, const MODE: u8>(
    xs: &mut [Fr8; K],
    idx: __m512i,
    mask: __mmask8,
    w: Option<&Fr8>,
    two_r: &Fr8,
    three_r: &Fr8,
) {
    let c = if MODE == 1 { three_r } else { two_r };
    let mut sum = [xs[0]; K];
    let mut dif = [xs[0]; K];
    for k in 0..K {
        let u = xs[k].permute(idx);
        let a = Fr8::blend(mask, &xs[k], &u);
        let b = Fr8::blend(mask, &u, &xs[k]);
        sum[k] = match MODE {
            0 => a.add_raw(&b).normalise().cond_sub(two_r),
            1 => a.add_approx_reduce(&b, two_r),
            _ => a.add_raw(&b).normalise(),
        };
        dif[k] = a.sub_raw(&b, c).normalise();
    }
    if let Some(w) = w {
        for k in 0..K {
            dif[k] = dif[k].mul(w);
        }
    }
    for k in 0..K {
        xs[k] = Fr8::blend(mask, &sum[k], &dif[k]);
    }
}

/// 8×8 transpose of one limb across eight vectors.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn transpose8(r: &mut [__m512i; 8]) {
    let t0 = _mm512_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm512_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm512_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm512_unpackhi_epi64(r[2], r[3]);
    let t4 = _mm512_unpacklo_epi64(r[4], r[5]);
    let t5 = _mm512_unpackhi_epi64(r[4], r[5]);
    let t6 = _mm512_unpacklo_epi64(r[6], r[7]);
    let t7 = _mm512_unpackhi_epi64(r[6], r[7]);
    let u0 = _mm512_shuffle_i64x2::<0x88>(t0, t2);
    let u1 = _mm512_shuffle_i64x2::<0xDD>(t0, t2);
    let u2 = _mm512_shuffle_i64x2::<0x88>(t1, t3);
    let u3 = _mm512_shuffle_i64x2::<0xDD>(t1, t3);
    let u4 = _mm512_shuffle_i64x2::<0x88>(t4, t6);
    let u5 = _mm512_shuffle_i64x2::<0xDD>(t4, t6);
    let u6 = _mm512_shuffle_i64x2::<0x88>(t5, t7);
    let u7 = _mm512_shuffle_i64x2::<0xDD>(t5, t7);
    r[0] = _mm512_shuffle_i64x2::<0x88>(u0, u4);
    r[4] = _mm512_shuffle_i64x2::<0xDD>(u0, u4);
    r[1] = _mm512_shuffle_i64x2::<0x88>(u2, u6);
    r[5] = _mm512_shuffle_i64x2::<0xDD>(u2, u6);
    r[2] = _mm512_shuffle_i64x2::<0x88>(u1, u5);
    r[6] = _mm512_shuffle_i64x2::<0xDD>(u1, u5);
    r[3] = _mm512_shuffle_i64x2::<0x88>(u3, u7);
    r[7] = _mm512_shuffle_i64x2::<0xDD>(u3, u7);
}

/// Transposes every block of eight vectors: lane u of vector l becomes lane l
/// of vector u.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn transpose_blocks(buf: &mut [Soa]) {
    let mut b = 0;
    while b < buf.len() {
        let mut xs = [Fr8::load(&buf[b]); 8];
        for k in 1..8 {
            xs[k] = Fr8::load(&buf[b + k]);
        }
        for j in 0..LIMBS {
            let mut limb = [
                xs[0].0[j], xs[1].0[j], xs[2].0[j], xs[3].0[j], xs[4].0[j], xs[5].0[j], xs[6].0[j],
                xs[7].0[j],
            ];
            transpose8(&mut limb);
            for k in 0..8 {
                xs[k].0[j] = limb[k];
            }
        }
        for k in 0..8 {
            xs[k].store(&mut buf[b + k]);
        }
        b += 8;
    }
}

/// DIT stage without twiddles (len = 2): input < r, output < 2r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dit_stage_no_mul(buf: &mut [Soa], half_v: usize, r: &Fr8) {
    let mut i = 0;
    while i < buf.len() {
        for j in 0..half_v {
            let a = Fr8::load(&buf[i + j]);
            let b = Fr8::load(&buf[i + j + half_v]);
            a.add_raw(&b).store(&mut buf[i + j]);
            a.sub_raw(&b, r).store(&mut buf[i + j + half_v]);
        }
        i += 2 * half_v;
    }
}

/// DIF stage without twiddles (len = 2), then canonicalisation: input < 2r,
/// output < r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dif_stage_no_mul_canonical(buf: &mut [Soa], half_v: usize, two_r: &Fr8, r: &Fr8) {
    let mut i = 0;
    while i < buf.len() {
        for j in 0..half_v {
            let a = Fr8::load(&buf[i + j]);
            let b = Fr8::load(&buf[i + j + half_v]);
            a.add_raw(&b).normalise().cond_sub(two_r).cond_sub(r).store(&mut buf[i + j]);
            a.sub_raw(&b, two_r)
                .normalise()
                .cond_sub(two_r)
                .cond_sub(r)
                .store(&mut buf[i + j + half_v]);
        }
        i += 2 * half_v;
    }
}

/// MODE 0: exact cond-sub 2r on the sum. MODE 1: top-limb approximate
/// reduction (values stay below 2r + 2^221). MODE 2: no reduction, timing only
/// (wrong output).
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dif_butterfly<const MODE: u8>(
    a: &Fr8,
    b: &Fr8,
    w: &Fr8,
    two_r: &Fr8,
    three_r: &Fr8,
) -> (Fr8, Fr8) {
    let sum = match MODE {
        0 => a.add_raw(b).normalise().cond_sub(two_r),
        1 => a.add_approx_reduce(b, two_r),
        _ => a.add_raw(b).normalise(),
    };
    let c = if MODE == 1 { three_r } else { two_r };
    (sum, a.sub_raw(b, c).normalise().mul(w))
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dif_stage<const MODE: u8, const UNROLL: bool>(
    buf: &mut [Soa],
    tw: &[Soa],
    half_v: usize,
    two_r: &Fr8,
    three_r: &Fr8,
) {
    let vectors = buf.len();
    let mut i = 0;
    while i < vectors {
        let mut j = 0;
        if UNROLL && half_v >= 2 {
            while j < half_v {
                let a0 = Fr8::load(&buf[i + j]);
                let b0 = Fr8::load(&buf[i + j + half_v]);
                let a1 = Fr8::load(&buf[i + j + 1]);
                let b1 = Fr8::load(&buf[i + j + 1 + half_v]);
                let (s0, d0) = dif_butterfly::<MODE>(&a0, &b0, &Fr8::load(&tw[j]), two_r, three_r);
                let (s1, d1) =
                    dif_butterfly::<MODE>(&a1, &b1, &Fr8::load(&tw[j + 1]), two_r, three_r);
                s0.store(&mut buf[i + j]);
                d0.store(&mut buf[i + j + half_v]);
                s1.store(&mut buf[i + j + 1]);
                d1.store(&mut buf[i + j + 1 + half_v]);
                j += 2;
            }
        } else {
            while j < half_v {
                let a = Fr8::load(&buf[i + j]);
                let b = Fr8::load(&buf[i + j + half_v]);
                let (s, d) = dif_butterfly::<MODE>(&a, &b, &Fr8::load(&tw[j]), two_r, three_r);
                s.store(&mut buf[i + j]);
                d.store(&mut buf[i + j + half_v]);
                j += 1;
            }
        }
        i += 2 * half_v;
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dit_butterfly<const LAZY: bool>(a: &Fr8, b: &Fr8, w: &Fr8, two_r: &Fr8) -> (Fr8, Fr8) {
    if LAZY {
        let m = b.normalise().mul(w);
        (a.add_raw(&m), a.sub_raw(&m, two_r))
    } else {
        let m = b.mul(w);
        (a.add_raw(&m).normalise(), a.sub_raw(&m, two_r).normalise())
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dit_stage<const UNROLL: bool, const LAZY: bool>(
    buf: &mut [Soa],
    tw: &[Soa],
    half_v: usize,
    two_r: &Fr8,
) {
    let vectors = buf.len();
    let mut i = 0;
    while i < vectors {
        let mut j = 0;
        if UNROLL && half_v >= 2 {
            while j < half_v {
                let a0 = Fr8::load(&buf[i + j]);
                let b0 = Fr8::load(&buf[i + j + half_v]);
                let a1 = Fr8::load(&buf[i + j + 1]);
                let b1 = Fr8::load(&buf[i + j + 1 + half_v]);
                let (s0, d0) = dit_butterfly::<LAZY>(&a0, &b0, &Fr8::load(&tw[j]), two_r);
                let (s1, d1) = dit_butterfly::<LAZY>(&a1, &b1, &Fr8::load(&tw[j + 1]), two_r);
                s0.store(&mut buf[i + j]);
                d0.store(&mut buf[i + j + half_v]);
                s1.store(&mut buf[i + j + 1]);
                d1.store(&mut buf[i + j + 1 + half_v]);
                j += 2;
            }
        } else {
            while j < half_v {
                let a = Fr8::load(&buf[i + j]);
                let b = Fr8::load(&buf[i + j + half_v]);
                let (s, d) = dit_butterfly::<LAZY>(&a, &b, &Fr8::load(&tw[j]), two_r);
                s.store(&mut buf[i + j]);
                d.store(&mut buf[i + j + half_v]);
                j += 1;
            }
        }
        i += 2 * half_v;
    }
}

// ───────────────────────── harness ─────────────────────────

fn best_of<R>(reps: usize, mut f: impl FnMut() -> R) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        black_box(f());
        best = best.min(t.elapsed());
    }
    best
}

fn random_blob(rng: &mut ChaCha8Rng) -> Box<[u8; BYTES_PER_BLOB]> {
    let mut bytes = Box::new([0u8; BYTES_PER_BLOB]);
    rng.fill(&mut bytes[..]);
    for element in bytes.chunks_exact_mut(32) {
        element[0] = 0;
    }
    bytes
}

fn ckzg_cells(blob: &[u8; BYTES_PER_BLOB]) -> Vec<[u8; BYTES_PER_CELL]> {
    let (cells, _) =
        ethereum_kzg_settings(0).compute_cells_and_kzg_proofs(&Blob::new(*blob)).unwrap();
    cells.iter().map(|c| c.to_bytes()).collect()
}

fn new_cells() -> Box<[[u8; BYTES_PER_CELL]; CELLS]> {
    vec![[0u8; BYTES_PER_CELL]; CELLS]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

fn us(d: Duration, per: usize) -> f64 {
    d.as_secs_f64() * 1e6 / per as f64
}

fn mul_microbench() {
    const ITERS: usize = 200_000;
    const CHAINS: usize = 8;
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let seed: Vec<blst_fr> = (0..CHAINS)
        .map(|_| fr_from_bytes(&random_blob(&mut rng)[..32].try_into().unwrap()).unwrap())
        .collect();
    let w = fr_from_u64(12345);

    // blst FFI, 8 independent chains (throughput).
    let t = best_of(5, || {
        let mut c = seed.clone();
        for _ in 0..ITERS {
            for k in 0..CHAINS {
                c[k] = fr_mul(&c[k], &w);
            }
        }
        c
    });
    println!(
        "mul: blst_fr_mul (FFI, 8 chains)       {:.2} ns/mul",
        t.as_secs_f64() * 1e9 / (ITERS * CHAINS) as f64
    );

    // inline CIOS u128.
    let w64 = w.l;
    let t = best_of(5, || {
        let mut c: Vec<[u64; 4]> = seed.iter().map(|f| f.l).collect();
        for _ in 0..ITERS {
            for k in 0..CHAINS {
                c[k] = cios_mul(&c[k], &w64);
            }
        }
        c
    });
    println!(
        "mul: inline CIOS u128 (8 chains)        {:.2} ns/mul",
        t.as_secs_f64() * 1e9 / (ITERS * CHAINS) as f64
    );
    // check CIOS == blst
    let mut c = seed[0].l;
    let mut d = seed[0];
    for _ in 0..1000 {
        c = cios_mul(&c, &w64);
        d = fr_mul(&d, &w);
    }
    assert_eq!(c, d.l, "CIOS agrees with blst");

    // IFMA x8, 4 independent vector chains.
    let soa = soa_from_frs(&seed);
    let w_soa = soa_from_frs(&[w; 8]);
    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn run(soa: &Soa, w: &Soa, iters: usize) -> [Soa; 4] {
        let w = Fr8::load(w);
        let mut c = [Fr8::load(soa); 4];
        for _ in 0..iters {
            c[0] = c[0].mul(&w);
            c[1] = c[1].mul(&w);
            c[2] = c[2].mul(&w);
            c[3] = c[3].mul(&w);
        }
        let mut out = [[[0u64; 8]; LIMBS]; 4];
        for k in 0..4 {
            c[k].store(&mut out[k]);
        }
        out
    }
    let t = best_of(5, || unsafe { run(&soa, &w_soa, ITERS) });
    println!(
        "mul: IFMA Fr8 (4 vector chains)         {:.2} ns/mul-lane ({:.1} ns per 8-lane mul)",
        t.as_secs_f64() * 1e9 / (ITERS * 32) as f64,
        t.as_secs_f64() * 1e9 / (ITERS * 4) as f64
    );
    // check: IFMA x^(ITERS) lane 0 == blst
    let out = unsafe { run(&soa, &w_soa, 1000) };
    let mut d = seed[0];
    for _ in 0..1000 {
        d = fr_mul(&d, &w);
    }
    // canonicalise lane 0 (value may be in [0, 2r)).
    let mut l = [0u64; LIMBS];
    for j in 0..LIMBS {
        l[j] = out[0][j][0];
    }
    let mut x = pack64(&l);
    let mut ge = true;
    for j in (0..4).rev() {
        if x[j] != R64[j] {
            ge = x[j] > R64[j];
            break;
        }
    }
    if ge {
        let mut borrow = 0u64;
        for j in 0..4 {
            let (s1, b1) = x[j].overflowing_sub(R64[j]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            x[j] = s2;
            borrow = (b1 | b2) as u64;
        }
    }
    assert_eq!(x, pack64(&to_r260(&d)), "IFMA agrees with blst");
}

fn main() {
    assert!(is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma"));
    let mut rng = ChaCha8Rng::seed_from_u64(0x6b7a_6763_656c_6c73);
    const BLOBS: usize = 16;
    let blobs: Vec<_> = (0..BLOBS).map(|_| random_blob(&mut rng)).collect();
    let expected: Vec<_> = blobs.iter().map(|b| ckzg_cells(b)).collect();
    let mut cells = new_cells();

    println!("== section 2: ns per Fr multiplication");
    mul_microbench();

    println!(
        "== section 1: current scalar pipeline breakdown ({BLOBS} random blobs, best of 5 per phase sum)"
    );
    let mut current = Current::new();
    for (b, blob) in blobs.iter().enumerate() {
        current.compute(blob, &mut cells);
        assert!(cells.iter().zip(&expected[b]).all(|(c, e)| c == e), "current == c-kzg");
    }
    let total = best_of(5, || {
        current.t_decode = Duration::ZERO;
        current.t_ifft = Duration::ZERO;
        current.t_shift = Duration::ZERO;
        current.t_fft = Duration::ZERO;
        current.t_write = Duration::ZERO;
        for blob in &blobs {
            current.compute(blob, &mut cells);
        }
    });
    println!("current total          {:>8.1} us/blob", us(total, BLOBS));
    println!("  decode (+copy half)  {:>8.1} us/blob", us(current.t_decode, BLOBS));
    println!("  ifft recursive + 1/n {:>8.1} us/blob", us(current.t_ifft, BLOBS));
    println!("  shift mul            {:>8.1} us/blob", us(current.t_shift, BLOBS));
    println!("  fft recursive        {:>8.1} us/blob", us(current.t_fft, BLOBS));
    println!("  write (to_bytes)     {:>8.1} us/blob", us(current.t_write, BLOBS));

    println!(
        "== section 3: scalar iterative DIT/DIF, precomputed twiddles, blst mul, no permutations"
    );
    let mut iter = ScalarIter::new();
    for (b, blob) in blobs.iter().enumerate() {
        iter.compute(blob, &mut cells);
        assert!(
            cells.iter().zip(&expected[b]).all(|(c, e)| c == e),
            "scalar iterative == c-kzg (blob {b})"
        );
    }
    let t = best_of(5, || {
        for blob in &blobs {
            iter.compute(blob, &mut cells);
        }
    });
    println!("scalar iterative total {:>8.1} us/blob", us(t, BLOBS));

    println!("== section 4: AVX-512 IFMA Fr8 pipeline");
    let mut simd = Simd::new();
    // Stress blobs for the lazy bounds: every element r − 1; alternating r − 1 and
    // 0; full-range values below r.
    let mut stress: Vec<Box<[u8; BYTES_PER_BLOB]>> = Vec::new();
    let mut r_minus_1 = MODULUS;
    r_minus_1[31] = 0;
    let mut all_max = Box::new([0u8; BYTES_PER_BLOB]);
    for e in all_max.chunks_exact_mut(32) {
        e.copy_from_slice(&r_minus_1);
    }
    stress.push(all_max);
    let mut alt = Box::new([0u8; BYTES_PER_BLOB]);
    for (i, e) in alt.chunks_exact_mut(32).enumerate() {
        if i % 2 == 0 {
            e.copy_from_slice(&r_minus_1);
        }
    }
    stress.push(alt);
    for _ in 0..4 {
        let mut full = Box::new([0u8; BYTES_PER_BLOB]);
        for e in full.chunks_exact_mut(32) {
            loop {
                rng.fill(e);
                if e[..] < MODULUS[..] {
                    break;
                }
            }
        }
        stress.push(full);
    }
    let stress_expected: Vec<_> = stress.iter().map(|b| ckzg_cells(b)).collect();
    fn check<const MODE: u8, const UNROLL: bool, const LAZY: bool, const K: usize>(
        simd: &mut Simd,
        cells: &mut [[u8; BYTES_PER_CELL]; CELLS],
        blobs: &[Box<[u8; BYTES_PER_BLOB]>],
        expected: &[Vec<[u8; BYTES_PER_CELL]>],
        what: &str,
    ) {
        for (b, blob) in blobs.iter().enumerate() {
            assert!(simd.compute::<MODE, UNROLL, LAZY, K>(blob, cells));
            for (k, (c, e)) in cells.iter().zip(&expected[b]).enumerate() {
                assert!(
                    c == e,
                    "{what}: simd<{MODE},{UNROLL},{LAZY},{K}> == c-kzg (blob {b}, cell {k})"
                );
            }
        }
    }
    check::<0, false, false, 1>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<0, false, false, 1>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    check::<1, false, false, 1>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<1, false, false, 1>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    check::<0, false, true, 1>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<0, false, true, 1>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    check::<0, false, true, 2>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<0, false, true, 2>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    check::<0, false, true, 4>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<0, false, true, 4>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    check::<0, true, true, 4>(&mut simd, &mut cells, &blobs, &expected, "random");
    check::<0, true, true, 4>(&mut simd, &mut cells, &stress, &stress_expected, "stress");
    for (b, blob) in blobs.iter().chain(&stress).enumerate() {
        assert!(simd.compute_t(blob, &mut cells));
        let e = if b < blobs.len() { &expected[b] } else { &stress_expected[b - blobs.len()] };
        for (k, (c, e)) in cells.iter().zip(e).enumerate() {
            assert!(c == e, "transposed-ends: simd == c-kzg (blob {b}, cell {k})");
        }
    }
    println!(
        "all variants byte-identical to c-kzg on {} random + {} stress blobs",
        blobs.len(),
        stress.len()
    );
    // rejection
    let mut bad = blobs[0].clone();
    bad[..32].copy_from_slice(&MODULUS);
    assert!(!simd.compute::<0, false, false, 1>(&bad, &mut cells), "element == r rejected");
    bad[31] = 0;
    assert!(simd.compute::<0, false, false, 1>(&bad, &mut cells), "element == r - 1 accepted");

    macro_rules! time_variant {
        ($mode:literal, $unroll:literal, $lazy:literal, $k:literal, $label:literal) => {{
            let t = best_of(7, || {
                for blob in &blobs {
                    simd.compute::<$mode, $unroll, $lazy, $k>(blob, &mut cells);
                }
            });
            simd.phase = [Duration::ZERO; 5];
            let tr = best_of(7, || {
                simd.phase = [Duration::ZERO; 5];
                for _ in 0..BLOBS {
                    unsafe { simd.transform::<$mode, $unroll, $lazy, $k>() };
                }
            });
            println!(
                "simd {:<40} total {:>6.1} us/blob, transform {:>6.1} = dit-reg {:.1} + dit {:.1} + pw {:.1} + dif {:.1} + dif-reg {:.1}",
                $label,
                us(t, BLOBS),
                us(tr, BLOBS),
                us(simd.phase[0], BLOBS),
                us(simd.phase[1], BLOBS),
                us(simd.phase[2], BLOBS),
                us(simd.phase[3], BLOBS),
                us(simd.phase[4], BLOBS)
            );
        }};
    }
    time_variant!(0, false, false, 1, "exact, K=1");
    time_variant!(1, false, false, 1, "approx reduce, K=1");
    time_variant!(0, false, true, 1, "exact, lazy DIT, K=1");
    time_variant!(0, false, true, 2, "exact, lazy DIT, K=2");
    time_variant!(0, false, true, 4, "exact, lazy DIT, K=4");
    time_variant!(0, true, true, 4, "exact, lazy DIT, K=4, unroll x2");
    time_variant!(1, false, true, 4, "approx reduce, lazy DIT, K=4");
    {
        let t = best_of(7, || {
            for blob in &blobs {
                simd.compute_t(blob, &mut cells);
            }
        });
        let tr = best_of(7, || {
            simd.phase = [Duration::ZERO; 5];
            for _ in 0..BLOBS {
                unsafe { simd.transform_t() };
            }
        });
        println!(
            "simd {:<40} total {:>6.1} us/blob, transform {:>6.1} = dit-lo+T {:.1} + dit {:.1} + pw {:.1} + dif {:.1} + T+dif-lo {:.1}",
            "transposed ends, exact, lazy DIT",
            us(t, BLOBS),
            us(tr, BLOBS),
            us(simd.phase[0], BLOBS),
            us(simd.phase[1], BLOBS),
            us(simd.phase[2], BLOBS),
            us(simd.phase[3], BLOBS),
            us(simd.phase[4], BLOBS)
        );
        let td = best_of(7, || {
            for blob in &blobs {
                black_box(simd.decode_t(blob));
            }
        });
        let te = best_of(7, || {
            for _ in 0..BLOBS {
                simd.encode_t(&mut cells);
            }
        });
        println!("  decode_t {:.1} us/blob, encode_t {:.1} us/blob", us(td, BLOBS), us(te, BLOBS));
    }
    let t_dec = best_of(7, || {
        for blob in &blobs {
            black_box(simd.decode(blob));
        }
    });
    println!("  decode               {:>8.1} us/blob", us(t_dec, BLOBS));
    let t_tr = best_of(7, || {
        for _ in 0..BLOBS {
            unsafe { simd.transform::<0, false, true, 4>() };
        }
    });
    println!("  transform (DIT+pw+DIF) {:>6.1} us/blob", us(t_tr, BLOBS));
    let t_enc = best_of(7, || {
        for _ in 0..BLOBS {
            simd.encode(&mut cells);
        }
    });
    println!("  encode               {:>8.1} us/blob", us(t_enc, BLOBS));
}
