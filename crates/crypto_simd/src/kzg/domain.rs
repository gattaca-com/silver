//! Roots of unity, computed as the spec's `computeRootsOfUnity` does: the
//! primitive root 7 raised to (r − 1)/order, then its powers.

use blst::blst_fr;

use crate::kzg::{FR_ONE, PRIMITIVE_ROOT_OF_UNITY, blst_ops::fr_mul};

/// r − 1, little-endian 64-bit words. 2^32 divides it.
const R_MINUS_ONE: [u64; 4] =
    [0xffff_ffff_0000_0000, 0x53bd_a402_fffe_5bfe, 0x3339_d808_09a1_d805, 0x73ed_a753_299d_7d48];

/// 7^((r − 1) / 2^log_order): square-and-multiply over the bits of r − 1 above
/// the lowest `log_order`, which are all zero.
fn primitive_root(log_order: u32) -> blst_fr {
    let mut root = FR_ONE;
    let mut bit = 256;
    while bit > log_order {
        bit -= 1;
        root = fr_mul(&root, &root);
        if (R_MINUS_ONE[(bit / 64) as usize] >> (bit % 64)) & 1 == 1 {
            root = fr_mul(&root, &PRIMITIVE_ROOT_OF_UNITY);
        }
    }
    root
}

/// ω^0, ω^1, …, ω^(2^log_order − 1), for the root ω of order 2^log_order.
pub fn roots_of_unity(log_order: u32) -> Vec<blst_fr> {
    let order = 1usize << log_order;
    let root = primitive_root(log_order);
    let mut roots = Vec::with_capacity(order);
    let mut power = FR_ONE;
    for _ in 0..order {
        roots.push(power);
        power = fr_mul(&power, &root);
    }
    roots
}

/// The spec's reversed roots: `roots[0]`, then `roots[1..]` backwards. These
/// are the powers of the inverse root.
pub fn inverse_roots(roots: &[blst_fr]) -> Vec<blst_fr> {
    let n = roots.len();
    let mut inverse = Vec::with_capacity(n);
    inverse.push(roots[0]);
    let mut i = 1;
    while i < n {
        inverse.push(roots[n - i]);
        i += 1;
    }
    inverse
}

/// `index` with its lowest `bits` bits in reverse order; `index < 2^bits`.
pub fn reverse_bits(index: usize, bits: u32) -> usize {
    let mut rest = index;
    let mut reversed = 0;
    let mut bit = 0;
    while bit < bits {
        reversed = (reversed << 1) | (rest & 1);
        rest >>= 1;
        bit += 1;
    }
    reversed
}
