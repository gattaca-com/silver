//! SHA-256's compression on the SHA extensions. Vectors are named by their
//! lanes from the top one down, as Intel's documentation names them:
//! `_mm_sha256rnds2_epu32` keeps the state as ABEF and CDGH.

use std::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
    _mm_shuffle_epi32, _mm_storeu_si128,
};

use super::{BLOCK, K};

/// `super::compress_blocks` on the SHA extensions.
#[target_feature(enable = "sha,sse4.1")]
pub fn compress_blocks(state: &[u32; 8], data: &[u8], offset: usize, blocks: usize) -> [u32; 8] {
    let data = &data[offset..offset + BLOCK * blocks];
    let byte_swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
    // SAFETY: `state` holds eight words, so both loads stay inside it.
    let (dcba, hgfe) = unsafe {
        (_mm_loadu_si128(state.as_ptr().cast()), _mm_loadu_si128(state.as_ptr().add(4).cast()))
    };
    let cdab = _mm_shuffle_epi32(dcba, 0xb1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);
    let mut block = 0;
    while block < blocks {
        let (abef_before, cdgh_before) = (abef, cdgh);
        let mut w = [abef; 4];
        let mut i = 0;
        while i < 4 {
            // SAFETY: block < blocks and i < 4 keep the 16 bytes inside `data`.
            let bytes =
                unsafe { _mm_loadu_si128(data.as_ptr().add(BLOCK * block + 16 * i).cast()) };
            w[i] = _mm_shuffle_epi8(bytes, byte_swap);
            i += 1;
        }
        let mut quad = 0;
        while quad < 16 {
            // SAFETY: quad < 16 keeps the four words inside `K`.
            let k = unsafe { _mm_loadu_si128(K.as_ptr().add(4 * quad).cast()) };
            let wk = _mm_add_epi32(w[0], k);
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
            if quad < 12 {
                let partial = _mm_sha256msg1_epu32(w[0], w[1]);
                let next = _mm_sha256msg2_epu32(
                    _mm_add_epi32(partial, _mm_alignr_epi8(w[3], w[2], 4)),
                    w[3],
                );
                w = [w[1], w[2], w[3], next];
            } else {
                w = [w[1], w[2], w[3], w[3]];
            }
            quad += 1;
        }
        abef = _mm_add_epi32(abef, abef_before);
        cdgh = _mm_add_epi32(cdgh, cdgh_before);
        block += 1;
    }
    let feba = _mm_shuffle_epi32(abef, 0x1b);
    let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
    let mut out = [0u32; 8];
    // SAFETY: `out` holds eight words, so both stores stay inside it.
    unsafe {
        _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), _mm_blend_epi16(feba, dchg, 0xf0));
        _mm_storeu_si128(out.as_mut_ptr().add(4).cast::<__m128i>(), _mm_alignr_epi8(dchg, feba, 8));
    }
    out
}
