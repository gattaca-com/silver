//! The compressed encoding's flag bits, and its big-endian coordinates.

use crate::bls::{G2_COMPRESSED_LEN, constants::P_U64};

pub(crate) const FP_BYTES: usize = G2_COMPRESSED_LEN / 2;
pub(crate) const FLAG_COMPRESSED: u8 = 0x80;
pub(crate) const FLAG_INFINITY: u8 = 0x40;
pub(crate) const FLAG_LARGER_ROOT: u8 = 0x20;

/// A 48-byte big-endian coordinate as little-endian 64-bit words.
#[inline]
pub(crate) fn fp_words(be: &[u8]) -> [u64; 6] {
    let mut words = [0u64; 6];
    for w in 0..6 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&be[FP_BYTES - 8 * (w + 1)..FP_BYTES - 8 * w]);
        words[w] = u64::from_be_bytes(bytes);
    }
    words
}

#[inline]
pub(crate) fn less_than_p(x: &[u64; 6]) -> bool {
    let mut w = 6;
    while w > 0 {
        w -= 1;
        if x[w] != P_U64[w] {
            return x[w] < P_U64[w];
        }
    }
    false
}
