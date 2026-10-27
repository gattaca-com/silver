//! AVX-512 IFMA fast path for BLS12-381 G1 and G2 point decompression with
//! subgroup membership, eight points per step. Lanes the vector path declines,
//! and short chunks use the portable G1 decoder or blst's G2 decoder.
//! CPUs without IFMA use blst for both groups.
//!
//! The fast path is available when the `simd` build feature is enabled. It
//! additionally requires AVX-512F and AVX-512 IFMA support enabled at run time.
//! IFMA is 52-bit integer multiply-add. This is expected to work on AMD Zen 4
//! and Zen 5, and on Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids
//! and Granite Rapids. Intel laptop and desktop CPUs from Alder Lake on do not
//! support the required instructions.
#![allow(
    clippy::needless_range_loop,
    reason = "Aeneas translates index loops into Lean, but not iterator adaptors"
)]

// The kernels are `#[target_feature]` functions: every one of them is unsafe to
// call for the same single reason, that `ifma_available` must have been checked
// on this CPU, so the safety section lives here rather than on each function.
pub mod constants;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod decompress;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod decompress_g2;
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) mod encoding;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub(crate) mod fp12;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod fp2x8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod fp8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod g1x8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[doc(hidden)]
pub mod g2x8;
pub(crate) mod glv;
pub mod limbs;
#[cfg(target_arch = "x86_64")]
pub(crate) mod miller_lines;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub(crate) mod msm8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub(crate) mod pairing;
pub(crate) mod signed_digits;
#[cfg(test)]
pub(crate) mod spec_pairing;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__mmask8;

use blst::{
    BLST_ERROR, blst_p1_affine_in_g1, blst_p1_uncompress, blst_p2_affine_in_g2, blst_p2_uncompress,
};
pub use blst::{blst_p1_affine, blst_p2_affine};

use crate::ifma_available;
#[cfg(target_arch = "x86_64")]
use crate::portable::decompress::uncompress_all_in_g1;
#[cfg(target_arch = "x86_64")]
use crate::portable::decompress::uncompress_in_g1 as uncompress_one_in_g1;

pub const COMPRESSED_LEN: usize = 48;
pub const G2_COMPRESSED_LEN: usize = 96;
const LANES: usize = 8;
/// A kernel call costs about as much as blst on two or three points, so
/// smaller G2 chunks stay on blst.
const MIN_KERNEL_LANES: usize = 3;

/// Lanes where a Scott test decided membership, and lanes it could not
/// decide.
#[cfg(target_arch = "x86_64")]
pub struct Membership {
    pub members: __mmask8,
    pub undecided: __mmask8,
}

/// `Some` iff blst accepts the encoding as a point of G1.
pub fn uncompress_in_g1_blst(bytes: &[u8; COMPRESSED_LEN]) -> Option<blst_p1_affine> {
    let mut point = blst_p1_affine::default();
    // SAFETY: both pointers are valid for the lengths blst reads and writes.
    let ok = unsafe {
        blst_p1_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS &&
            blst_p1_affine_in_g1(&point)
    };
    ok.then_some(point)
}

/// Sets each `out[i]` to blst's verdict on `inputs[i]`: `blst_p1_uncompress`,
/// then `blst_p1_affine_in_g1`. On IFMA, undecided lanes and short tails use
/// the portable decoder. Without IFMA, every input uses blst.
#[cfg(target_arch = "x86_64")]
pub fn uncompress_in_g1(inputs: &[[u8; COMPRESSED_LEN]], out: &mut [Option<blst_p1_affine>]) {
    assert!(out.len() == inputs.len(), "one verdict slot per input");
    if !ifma_available() {
        uncompress_all_in_g1_blst(inputs, out);
        return;
    }
    let full = inputs.len() / LANES * LANES;
    let mut start = 0;
    while start < full {
        let mut chunk = [[0u8; COMPRESSED_LEN]; LANES];
        chunk.copy_from_slice(&inputs[start..start + LANES]);
        decompress_g1_chunk(&chunk, &mut out[start..start + LANES]);
        start += LANES;
    }
    uncompress_all_in_g1(&inputs[full..inputs.len()], &mut out[full..inputs.len()]);
}

/// Sets each `out[i]` to blst's verdict on `inputs[i]`.
#[cfg(not(target_arch = "x86_64"))]
pub fn uncompress_in_g1(inputs: &[[u8; COMPRESSED_LEN]], out: &mut [Option<blst_p1_affine>]) {
    assert!(out.len() == inputs.len(), "one verdict slot per input");
    uncompress_all_in_g1_blst(inputs, out);
}

fn uncompress_all_in_g1_blst(inputs: &[[u8; COMPRESSED_LEN]], out: &mut [Option<blst_p1_affine>]) {
    for i in 0..inputs.len() {
        out[i] = uncompress_in_g1_blst(&inputs[i]);
    }
}

#[cfg(target_arch = "x86_64")]
fn decompress_g1_chunk(chunk: &[[u8; COMPRESSED_LEN]; LANES], out: &mut [Option<blst_p1_affine>]) {
    // SAFETY: `ifma_available` confirmed avx512f and avx512ifma on this CPU.
    let batch = unsafe { decompress::decompress(chunk) };
    for lane in 0..LANES {
        let bit = 1u8 << lane;
        out[lane] = if batch.undecided & bit != 0 {
            uncompress_one_in_g1(&chunk[lane])
        } else if batch.valid & bit != 0 {
            Some(batch.points[lane])
        } else {
            None
        };
    }
}

/// `Some` iff blst accepts the encoding as a point of G2.
pub fn uncompress_in_g2_blst(bytes: &[u8; G2_COMPRESSED_LEN]) -> Option<blst_p2_affine> {
    let mut point = blst_p2_affine::default();
    // SAFETY: both pointers are valid for the lengths blst reads and writes.
    let ok = unsafe {
        blst_p2_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS &&
            blst_p2_affine_in_g2(&point)
    };
    ok.then_some(point)
}

/// Sets each `out[i]` to a verdict identical to
/// `uncompress_in_g2_blst(&inputs[i])`.
pub fn uncompress_in_g2(inputs: &[[u8; G2_COMPRESSED_LEN]], out: &mut [Option<blst_p2_affine>]) {
    assert!(out.len() == inputs.len(), "one verdict slot per input");
    let simd = ifma_available();
    let mut start = 0;
    while start < inputs.len() {
        let rest = inputs.len() - start;
        let len = if rest < LANES { rest } else { LANES };
        if simd && len >= MIN_KERNEL_LANES {
            decompress_g2_chunk(&inputs[start..start + len], &mut out[start..start + len]);
        } else {
            for lane in 0..len {
                out[start + lane] = uncompress_in_g2_blst(&inputs[start + lane]);
            }
        }
        start += len;
    }
}

/// A short chunk repeats its last input in the unused lanes.
#[cfg(target_arch = "x86_64")]
fn decompress_g2_chunk(chunk: &[[u8; G2_COMPRESSED_LEN]], out: &mut [Option<blst_p2_affine>]) {
    let mut lanes = [[0u8; G2_COMPRESSED_LEN]; LANES];
    for lane in 0..LANES {
        lanes[lane] = chunk[if lane < chunk.len() { lane } else { chunk.len() - 1 }];
    }
    // SAFETY: `ifma_available` confirmed avx512f and avx512ifma on this CPU.
    let batch = unsafe { decompress_g2::decompress(&lanes) };
    for lane in 0..chunk.len() {
        let bit = 1u8 << lane;
        out[lane] = if batch.undecided & bit != 0 {
            uncompress_in_g2_blst(&chunk[lane])
        } else if batch.valid & bit != 0 {
            Some(batch.points[lane])
        } else {
            None
        };
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn decompress_g2_chunk(chunk: &[[u8; G2_COMPRESSED_LEN]], out: &mut [Option<blst_p2_affine>]) {
    for lane in 0..chunk.len() {
        out[lane] = uncompress_in_g2_blst(&chunk[lane]);
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) mod tests;
