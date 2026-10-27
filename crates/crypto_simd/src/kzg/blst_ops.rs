//! blst's field and curve operations, the references the tests compare against.

use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_eucl_inverse, blst_fr_from_scalar,
    blst_fr_from_uint64, blst_fr_mul, blst_fr_sub, blst_p1, blst_p1_add_or_double, blst_p1_cneg,
    blst_p2, blst_p2_affine, blst_p2_cneg, blst_p2_from_affine, blst_p2_to_affine, blst_scalar,
    blst_scalar_fr_check, blst_scalar_from_bendian, blst_scalar_from_fr, blst_sha256,
};

pub(crate) use super::blst_pairing::{g1_to_affine, pairing_check_affine as pairing_check};

/// `None` unless the 32 big-endian bytes encode a value below r.
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

pub fn fr_from_u64(a: u64) -> blst_fr {
    let limbs = [a, 0, 0, 0];
    let mut fr = blst_fr::default();
    // SAFETY: blst reads four limbs and writes one value.
    unsafe { blst_fr_from_uint64(&mut fr, limbs.as_ptr()) };
    fr
}

pub fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_add(&mut out, a, b) };
    out
}

pub fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_sub(&mut out, a, b) };
    out
}

pub fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fr_mul(&mut out, a, b) };
    out
}

/// The inverse of a nonzero element; 0 for 0, as the spec's `Fr.inverse`.
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
