//! AVX-512 IFMA fast path for BLS12-381 G2 point decompression with subgroup
//! membership, eight points per step. Lanes the vector path declines, short
//! chunks, and CPUs without the instructions go through blst, so the verdicts
//! are blst's either way.
//!
//! The fast path is available when the `simd` build feature is enabled. It
//! additionally requires AVX-512F and AVX-512 IFMA support enabled at run time.
//! IFMA is 52-bit integer multiply-add. This is expected to work on AMD Zen 4
//! and Zen 5, and on Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids
//! and Granite Rapids. Intel laptop and desktop CPUs from Alder Lake on do not
//! support the required instructions.

// The kernels are `#[target_feature]` functions: every one of them is unsafe to
// call for the same single reason, that `simd_available` must have been checked
// on this CPU, so the safety section lives here rather than on each function.
#[cfg(target_arch = "x86_64")]
pub mod constants;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub mod decompress_g2;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub mod fp2x8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub mod fp8;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub mod g2x8;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__mmask8;

pub use blst::blst_p2_affine;
use blst::{BLST_ERROR, blst_p2_affine_in_g2, blst_p2_uncompress};

pub const G2_COMPRESSED_LEN: usize = 96;
const LANES: usize = 8;
/// A kernel call costs about as much as blst on two or three points, so
/// smaller chunks stay on blst.
const MIN_KERNEL_LANES: usize = 3;

/// Lanes where a Scott test decided membership, and lanes it could not
/// decide.
#[cfg(target_arch = "x86_64")]
pub struct Membership {
    pub members: __mmask8,
    pub undecided: __mmask8,
}

/// Built without the `simd` feature, every point goes to blst, as on a CPU
/// without the instructions.
#[cfg(target_arch = "x86_64")]
pub fn simd_available() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn simd_available() -> bool {
    false
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

/// One verdict per input, identical to `uncompress_in_g2_blst` on each.
pub fn uncompress_in_g2(inputs: &[[u8; G2_COMPRESSED_LEN]]) -> Vec<Option<blst_p2_affine>> {
    let simd = simd_available();
    let mut out = Vec::with_capacity(inputs.len());
    for chunk in inputs.chunks(LANES) {
        if simd && chunk.len() >= MIN_KERNEL_LANES {
            decompress_g2_chunk(chunk, &mut out);
        } else {
            out.extend(chunk.iter().map(uncompress_in_g2_blst));
        }
    }
    out
}

#[cfg(target_arch = "x86_64")]
fn decompress_g2_chunk(chunk: &[[u8; G2_COMPRESSED_LEN]], out: &mut Vec<Option<blst_p2_affine>>) {
    let lanes = std::array::from_fn(|lane| chunk[lane.min(chunk.len() - 1)]);
    // SAFETY: `simd_available` confirmed avx512f and avx512ifma on this CPU.
    let batch = unsafe { decompress_g2::decompress(&lanes) };
    for (lane, input) in chunk.iter().enumerate() {
        let bit = 1u8 << lane;
        out.push(if batch.undecided & bit != 0 {
            uncompress_in_g2_blst(input)
        } else if batch.valid & bit != 0 {
            Some(batch.points[lane])
        } else {
            None
        });
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn decompress_g2_chunk(chunk: &[[u8; G2_COMPRESSED_LEN]], out: &mut Vec<Option<blst_p2_affine>>) {
    out.extend(chunk.iter().map(uncompress_in_g2_blst));
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
