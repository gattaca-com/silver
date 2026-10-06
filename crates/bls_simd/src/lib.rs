//! AVX-512 IFMA fast path for the BLS12-381 G2 subgroup check, eight points
//! per step. Lanes the vector path declines, short chunks, and CPUs without
//! the instructions go through blst, so the verdicts are blst's either way.

// The kernels are `#[target_feature]` functions: every one of them is unsafe to
// call for the same single reason, that `simd_available` must have been checked
// on this CPU, so the safety section lives here rather than on each function.
#[cfg(target_arch = "x86_64")]
pub mod constants;
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
use blst::blst_p2_affine_in_g2;

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

#[cfg(target_arch = "x86_64")]
pub fn simd_available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn simd_available() -> bool {
    false
}

pub fn in_g2_blst(point: &blst_p2_affine) -> bool {
    // SAFETY: blst reads one affine point through a valid reference.
    unsafe { blst_p2_affine_in_g2(point) }
}

/// One verdict per point, identical to `in_g2_blst` on each.
pub fn in_g2(points: &[blst_p2_affine]) -> Vec<bool> {
    let simd = simd_available();
    let mut out = Vec::with_capacity(points.len());
    for chunk in points.chunks(LANES) {
        if simd && chunk.len() >= MIN_KERNEL_LANES {
            in_g2_chunk(chunk, &mut out);
        } else {
            out.extend(chunk.iter().map(in_g2_blst));
        }
    }
    out
}

#[cfg(target_arch = "x86_64")]
fn in_g2_chunk(chunk: &[blst_p2_affine], out: &mut Vec<bool>) {
    let lanes = std::array::from_fn(|lane| chunk[lane.min(chunk.len() - 1)]);
    // SAFETY: `simd_available` confirmed avx512f and avx512ifma on this CPU.
    let membership = unsafe { g2x8::G2x8::scott_membership(&lanes) };
    for (lane, point) in chunk.iter().enumerate() {
        let bit = 1u8 << lane;
        out.push(if membership.undecided & bit != 0 {
            in_g2_blst(point)
        } else {
            membership.members & bit != 0
        });
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn in_g2_chunk(chunk: &[blst_p2_affine], out: &mut Vec<bool>) {
    out.extend(chunk.iter().map(in_g2_blst));
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
