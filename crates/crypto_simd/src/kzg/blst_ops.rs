//! Every call into blst. Charon treats this module as opaque: the Lean proof
//! states what each function returns in terms of the specification, and trusts
//! blst to return it.

#[cfg(test)]
use blst::{
    blst_bendian_from_scalar, blst_fr_add, blst_fr_eucl_inverse, blst_fr_from_uint64, blst_fr_mul,
    blst_fr_sub, blst_p2, blst_p2_cneg, blst_p2_from_affine, blst_p2_to_affine,
    blst_scalar_fr_check,
};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fr, blst_fr_from_scalar, blst_miller_loop_n,
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_is_inf, blst_p1_cneg,
    blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_p2_affine, blst_p2_affine_is_inf, blst_scalar,
    blst_scalar_from_bendian, blst_scalar_from_fr, blst_sha256, limb_t,
};

const SCALAR_BITS: usize = 255;
/// blst's Pippenger is slower than one multiplication per point below this many
/// points.
const PIPPENGER_MIN_POINTS: usize = 8;

/// `None` unless the 32 big-endian bytes encode a value below r.
#[cfg(test)]
pub fn fr_from_bytes(bytes: &[u8; 32]) -> Option<blst_fr> {
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    // SAFETY: each pointer is valid for the 32 bytes or one value blst reads or
    // writes.
    unsafe {
        blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        if !blst_scalar_fr_check(&scalar) {
            return None;
        }
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    Some(fr)
}

/// 32 big-endian bytes, the inverse of `fr_from_bytes`.
#[cfg(test)]
pub fn fr_to_bytes(a: &blst_fr) -> [u8; 32] {
    let mut scalar = blst_scalar::default();
    let mut bytes = [0u8; 32];
    // SAFETY: blst reads one value and writes one value, then 32 bytes.
    unsafe {
        blst_scalar_from_fr(&mut scalar, a);
        blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
    }
    bytes
}

#[cfg(test)]
pub fn fr_from_u64(a: u64) -> blst_fr {
    let limbs = [a, 0, 0, 0];
    let mut fr = blst_fr::default();
    // SAFETY: blst reads four limbs and writes one value.
    unsafe { blst_fr_from_uint64(&mut fr, limbs.as_ptr()) };
    fr
}

#[cfg(test)]
pub fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_add(&mut out, a, b) };
    out
}

#[cfg(test)]
pub fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_sub(&mut out, a, b) };
    out
}

#[cfg(test)]
pub fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_mul(&mut out, a, b) };
    out
}

/// The inverse of a nonzero element; 0 for 0, as the spec's `Fr.inverse`.
#[cfg(test)]
pub fn fr_inverse(a: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_eucl_inverse(&mut out, a) };
    out
}

/// SHA-256 of `message`, read as a big-endian integer and reduced modulo r.
pub fn hash_to_fr(message: &[u8]) -> blst_fr {
    let mut digest = [0u8; 32];
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    // SAFETY: blst reads `message.len()` bytes and writes 32; the rest are single
    // values. `blst_fr_from_scalar` multiplies by R² in Montgomery form, which
    // reduces any 256-bit input modulo r.
    unsafe {
        blst_sha256(digest.as_mut_ptr(), message.as_ptr(), message.len());
        blst_scalar_from_bendian(&mut scalar, digest.as_ptr());
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    fr
}

/// The value of the 32 big-endian bytes modulo r.
#[cfg(all(test, target_arch = "x86_64"))]
pub fn fr_from_bytes_reduced(bytes: &[u8; 32]) -> blst_fr {
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    // SAFETY: blst reads 32 bytes and writes one value, then reads one and
    // writes one. `blst_fr_from_scalar` multiplies by R² in Montgomery form,
    // which reduces any 256-bit input modulo r.
    unsafe {
        blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    fr
}

pub fn g1_to_affine(a: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_to_affine(&mut out, a) };
    out
}

/// Complete addition, doubling included. `blst_p1_add` returns infinity for
/// equal operands.
pub fn g1_add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_add_or_double(&mut out, a, b) };
    out
}

pub fn g1_neg(a: &blst_p1) -> blst_p1 {
    let mut out = *a;
    // SAFETY: a valid pointer to a single value.
    unsafe { blst_p1_cneg(&mut out, true) };
    out
}

#[cfg(test)]
pub fn g2_neg(a: &blst_p2_affine) -> blst_p2_affine {
    let mut point = blst_p2::default();
    let mut out = blst_p2_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe {
        blst_p2_from_affine(&mut point, a);
        blst_p2_cneg(&mut point, true);
        blst_p2_to_affine(&mut out, &point);
    }
    out
}

/// Buffers for `g1_lincomb`, kept between calls.
pub struct LincombScratch {
    points: Vec<blst_p1_affine>,
    /// Little-endian scalars, the layout of `blst_scalar`.
    scalars: Vec<[u8; 32]>,
    pippenger: Vec<limb_t>,
}

impl LincombScratch {
    pub fn new() -> Self {
        Self { points: Vec::new(), scalars: Vec::new(), pippenger: Vec::new() }
    }
}

/// Σ scalars[i]·points[i]. Points at infinity contribute nothing and are left
/// out before blst sees them, as c-kzg does.
pub fn g1_lincomb(
    points: &[blst_p1_affine],
    scalars: &[blst_fr],
    scratch: &mut LincombScratch,
) -> blst_p1 {
    assert!(points.len() == scalars.len(), "one scalar per point");
    scratch.points.clear();
    scratch.scalars.clear();
    for (point, fr) in points.iter().zip(scalars) {
        // SAFETY: a valid pointer to a single value.
        if unsafe { blst_p1_affine_is_inf(point) } {
            continue;
        }
        let mut scalar = blst_scalar::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_scalar_from_fr(&mut scalar, fr) };
        scratch.points.push(*point);
        scratch.scalars.push(scalar.b);
    }
    let n = scratch.points.len();
    let mut out = blst_p1::default();
    if n < PIPPENGER_MIN_POINTS {
        for i in 0..n {
            let mut base = blst_p1::default();
            let mut term = blst_p1::default();
            // SAFETY: valid pointers; blst reads `SCALAR_BITS` bits of the 32-byte scalar.
            unsafe {
                blst_p1_from_affine(&mut base, &scratch.points[i]);
                blst_p1_mult(&mut term, &base, scratch.scalars[i].as_ptr(), SCALAR_BITS);
            }
            out = g1_add(&out, &term);
        }
        return out;
    }
    // SAFETY: a pure size query.
    let bytes = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(n) };
    scratch.pippenger.resize(bytes.div_ceil(size_of::<limb_t>()), 0);
    // A null second pointer tells blst that the first points at a contiguous array.
    let points_arg = [scratch.points.as_ptr(), std::ptr::null()];
    let scalars_arg = [scratch.scalars.as_ptr().cast::<u8>(), std::ptr::null()];
    // SAFETY: `points` and `scalars` hold `n` values each, and `pippenger` holds at
    // least the scratch size blst asked for.
    unsafe {
        blst_p1s_mult_pippenger(
            &mut out,
            points_arg.as_ptr(),
            n,
            scalars_arg.as_ptr(),
            SCALAR_BITS,
            scratch.pippenger.as_mut_ptr(),
        );
    }
    out
}

/// e(p1, q1)·e(p2, q2) = 1, skipping pairs with a point at infinity, as the
/// spec's `pairingCheck` does. blst 0.3.16's `blst_miller_loop_n` skips none.
pub fn pairing_check(
    p1: &blst_p1_affine,
    q1: &blst_p2_affine,
    p2: &blst_p1_affine,
    q2: &blst_p2_affine,
) -> bool {
    let mut ps: [*const blst_p1_affine; 2] = [std::ptr::null(); 2];
    let mut qs: [*const blst_p2_affine; 2] = [std::ptr::null(); 2];
    let mut n = 0;
    for (p, q) in [(p1, q1), (p2, q2)] {
        // SAFETY: valid pointers to single values.
        if !unsafe { blst_p1_affine_is_inf(p) || blst_p2_affine_is_inf(q) } {
            ps[n] = p;
            qs[n] = q;
            n += 1;
        }
    }
    if n == 0 {
        return true;
    }
    let mut miller = blst_fp12::default();
    let mut result = blst_fp12::default();
    // SAFETY: the first `n` entries of `ps` and `qs` point at valid values.
    unsafe {
        blst_miller_loop_n(&mut miller, qs.as_ptr(), ps.as_ptr(), n);
        blst_final_exp(&mut result, &miller);
        blst_fp12_is_one(&result)
    }
}
