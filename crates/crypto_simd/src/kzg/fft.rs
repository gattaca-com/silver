//! Radix-2 FFT over Fr, recursive as the spec's `fftFieldAux`: the even- and
//! odd-indexed inputs are transformed into the two halves of the output, then
//! combined by butterflies. Inputs and roots are read with strides instead of
//! being copied into halves.

use blst::blst_fr;

use crate::kzg::blst_ops::{fr_add, fr_mul, fr_sub};

/// `out[i] = Σ_j input[j]·ω^(i·j)`, where `roots` holds the powers of a
/// primitive root of an order that `out.len()` divides, and ω is the root of
/// order `out.len()` among them.
pub fn fft(out: &mut [blst_fr], input: &[blst_fr], roots: &[blst_fr]) {
    let n = out.len();
    assert!(n > 0 && n & (n - 1) == 0, "power-of-two length");
    assert!(input.len() == n && roots.len() % n == 0, "matching lengths");
    transform(out, input, 0, 1, roots, roots.len() / n);
}

/// `fft` with `inverse_roots`, the powers of the inverse root, scaled by
/// `inverse_n`: 1/n.
pub fn inverse_fft(
    out: &mut [blst_fr],
    input: &[blst_fr],
    inverse_roots: &[blst_fr],
    inverse_n: &blst_fr,
) {
    fft(out, input, inverse_roots);
    for i in 0..out.len() {
        out[i] = fr_mul(&out[i], inverse_n);
    }
}

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
