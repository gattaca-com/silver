//! The FFT kernels of `Fr8`, shared by `SimdCellExtender` and the cell
//! verifier. Stage s has length 2^(s+1); stages shorter than
//! `FIRST_WIDE_STAGE` pair elements within a block of eight vectors, so they
//! run on layout T, and the others on layout S (see `SimdCellExtender`).

use blst::blst_fr;

use crate::kzg::fr8::{Fr8, Fr8Soa, LANES, LIMBS, R52, TWO_R52, to_r260};

pub const BLOCK_VECTORS: usize = 8;
const BLOCK_ELEMENTS: usize = BLOCK_VECTORS * LANES;
pub const FIRST_WIDE_STAGE: usize = 3;

/// Per stage of the transform of length 2^LOG with `roots` its powers of the
/// root: below `FIRST_WIDE_STAGE`, one splat of ω^j per butterfly j; above,
/// vector v holds ω^(8v+l) in lane l.
pub fn twiddles<const LOG: usize>(roots: &[blst_fr]) -> [Vec<Fr8Soa>; LOG] {
    std::array::from_fn(|stage| {
        let step = (1 << LOG) / (2 << stage);
        let splat = |j: usize| {
            let limbs = to_r260(&roots[j * step]);
            Fr8Soa(limbs.map(|limb| [limb; LANES]))
        };
        if stage < FIRST_WIDE_STAGE {
            return (0..1 << stage).map(splat).collect();
        }
        (0..1 << (stage - FIRST_WIDE_STAGE))
            .map(|v| soa_of(|lane| &roots[(LANES * v + lane) * step]))
            .collect()
    })
}

pub fn soa_of<'a>(lane_value: impl Fn(usize) -> &'a blst_fr) -> Fr8Soa {
    let mut soa = Fr8Soa([[0; LANES]; LIMBS]);
    for lane in 0..LANES {
        let limbs = to_r260(lane_value(lane));
        for j in 0..LIMBS {
            soa.0[j][lane] = limbs[j];
        }
    }
    soa
}

/// Vector and lane of element `i` in layout T.
pub fn layout_t(i: usize) -> (usize, usize) {
    let (block, within) = (i / BLOCK_ELEMENTS, i % BLOCK_ELEMENTS);
    (block * BLOCK_VECTORS + within % LANES, within / LANES)
}

/// With R' = 2^260 and r < 2^255, (a·b + q·r) / R' < 2r when b < r and
/// a < R', so the product of any partially reduced `b` stays below 2r. Each
/// DIT stage then adds at most 2r to the running bound.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dit_butterfly(a: &mut Fr8Soa, b: &mut Fr8Soa, twiddle: &Fr8Soa) {
    let two_r = Fr8::splat(&TWO_R52);
    let (x, y) = (Fr8::load(a), Fr8::load(b));
    let product = y.normalise().mul(&Fr8::load(twiddle));
    x.add_raw(&product).store(a);
    x.sub_raw(&product, &two_r).store(b);
}

/// The sum of two values below 2r needs one conditional subtraction of 2r
/// to stay in `mul`'s range; the difference, below 4r, goes straight into
/// the product.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dif_butterfly(a: &mut Fr8Soa, b: &mut Fr8Soa, twiddle: &Fr8Soa) {
    let two_r = Fr8::splat(&TWO_R52);
    let (x, y) = (Fr8::load(a), Fr8::load(b));
    x.add_raw(&y).normalise().cond_sub(&two_r).store(a);
    x.sub_raw(&y, &two_r).normalise().mul(&Fr8::load(twiddle)).store(b);
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dit_stage(buf: &mut [Fr8Soa], twiddles: &[Fr8Soa], half_vectors: usize) {
    for group in buf.chunks_exact_mut(2 * half_vectors) {
        let (low, high) = group.split_at_mut(half_vectors);
        for ((a, b), twiddle) in low.iter_mut().zip(high).zip(twiddles) {
            dit_butterfly(a, b, twiddle);
        }
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dif_stage(buf: &mut [Fr8Soa], twiddles: &[Fr8Soa], half_vectors: usize) {
    for group in buf.chunks_exact_mut(2 * half_vectors) {
        let (low, high) = group.split_at_mut(half_vectors);
        for ((a, b), twiddle) in low.iter_mut().zip(high).zip(twiddles) {
            dif_butterfly(a, b, twiddle);
        }
    }
}

/// Length 2 needs no multiplication: inputs below r give outputs below 2r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dit_first_stage(block: &mut [Fr8Soa]) {
    let r = Fr8::splat(&R52);
    for pair in block.chunks_exact_mut(2) {
        let (x, y) = (Fr8::load(&pair[0]), Fr8::load(&pair[1]));
        x.add_raw(&y).store(&mut pair[0]);
        x.sub_raw(&y, &r).store(&mut pair[1]);
    }
}

/// Length 2 of the forward FFT, reducing the block's outputs below r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dif_last_stage_canonical(block: &mut [Fr8Soa]) {
    let (r, two_r) = (Fr8::splat(&R52), Fr8::splat(&TWO_R52));
    let canonical = |v: Fr8| v.normalise().cond_sub(&two_r).cond_sub(&r);
    for pair in block.chunks_exact_mut(2) {
        let (x, y) = (Fr8::load(&pair[0]), Fr8::load(&pair[1]));
        canonical(x.add_raw(&y)).store(&mut pair[0]);
        canonical(x.sub_raw(&y, &two_r)).store(&mut pair[1]);
    }
}

/// Layout S to T and back.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn transpose_blocks(buf: &mut [Fr8Soa]) {
    for block in buf.chunks_exact_mut(BLOCK_VECTORS) {
        Fr8::transpose_block(block);
    }
}
