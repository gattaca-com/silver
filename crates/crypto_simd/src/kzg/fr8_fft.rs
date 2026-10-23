//! The FFT kernels of `Fr8`, shared by `SimdCellExtender` and the cell
//! verifier. Stage s has length 2^(s+1); stages shorter than
//! `FIRST_WIDE_STAGE` pair elements within a block of eight vectors, so they
//! run on layout T, and the others on layout S (see `SimdCellExtender`).

use blst::blst_fr;

use crate::kzg::fr8::{FOUR_R52, Fr8, Fr8Soa, LANES, LIMBS, R52, TWO_R52, to_r260};

pub const BLOCK_VECTORS: usize = 8;
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

/// Butterflies of one stage over the vectors of `buf`, numbered across
/// blocks of `block_vectors`.
pub struct Stage {
    log_half: u32,
    log_block_pairs: u32,
}

impl Stage {
    pub fn new(half_vectors: usize, block_vectors: usize) -> Self {
        debug_assert!(half_vectors.is_power_of_two() && block_vectors >= 2 * half_vectors);
        Self {
            log_half: half_vectors.trailing_zeros(),
            log_block_pairs: block_vectors.trailing_zeros() - 1,
        }
    }

    /// The two vectors of butterfly `n`, and the index of its twiddle.
    #[inline]
    fn butterfly_at<'a>(
        &self,
        buf: &'a mut [Fr8Soa],
        n: usize,
    ) -> (&'a mut Fr8Soa, &'a mut Fr8Soa, usize) {
        let half = 1 << self.log_half;
        let block = n >> self.log_block_pairs;
        let within = n & ((1 << self.log_block_pairs) - 1);
        let (group, twiddle) = (within >> self.log_half, within & (half - 1));
        let a = (block << (self.log_block_pairs + 1)) + group * 2 * half + twiddle;
        let (low, high) = buf.split_at_mut(a + half);
        (&mut low[a], &mut high[0], twiddle)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn product_operands(&self, buf: &mut [Fr8Soa], twiddles: &[Fr8Soa], n: usize) -> (Fr8, Fr8) {
        let (_, b, twiddle) = self.butterfly_at(buf, n);
        (Fr8::load(b).normalise(), Fr8::load(&twiddles[twiddle]))
    }

    /// With R' = 2^260 and r < 2^255, (a·b + q·r) / R' < 2r when b < r and
    /// a < R', so the product of any partially reduced `b` stays below 2r. Each
    /// stage then adds at most 2r to the running bound.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn dit(&self, buf: &mut [Fr8Soa], twiddles: &[Fr8Soa]) {
        let two_r = Fr8::splat(&TWO_R52);
        pipelined_products(
            buf,
            buf.len() / 2,
            |buf, n| self.product_operands(buf, twiddles, n),
            |buf, n, product| {
                let (a, b, _) = self.butterfly_at(buf, n);
                let x = Fr8::load(a);
                x.add_raw(product).store(a);
                x.sub_raw(product, &two_r).store(b);
            },
        );
    }

    /// The sum of two operands loses 2r when its top limb is above that of 2r,
    /// so operands stay below 2r plus a drift that at most doubles per stage
    /// from 2^208. The difference is offset by 4r to stay positive, and goes
    /// straight into the product. A butterfly's sum is stored when its product
    /// operands are formed.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn dif(&self, buf: &mut [Fr8Soa], twiddles: &[Fr8Soa]) {
        let (two_r, four_r) = (Fr8::splat(&TWO_R52), Fr8::splat(&FOUR_R52));
        pipelined_products(
            buf,
            buf.len() / 2,
            // Outlined (two call sites) this costs 7% on dif stages.
            #[inline(always)]
            |buf, n| {
                let (a, b, twiddle) = self.butterfly_at(buf, n);
                let (x, y) = (Fr8::load(a), Fr8::load(b));
                x.add_raw(&y).normalise().sub_where_top_limb_above(&two_r).store(a);
                let difference = x.sub_raw(&y, &four_r).normalise();
                (difference, Fr8::load(&twiddles[twiddle]))
            },
            |buf, n, product| {
                let (_, b, _) = self.butterfly_at(buf, n);
                product.store(b);
            },
        );
    }
}

/// `buf[v] *= scale[v]` for every vector.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn pointwise_multiply(buf: &mut [Fr8Soa], scale: &[Fr8Soa]) {
    pipelined_products(
        buf,
        scale.len(),
        |buf, v| (Fr8::load(&buf[v]).normalise(), Fr8::load(&scale[v])),
        |buf, v, product| product.store(&mut buf[v]),
    );
}

/// Products `operands(n)` for `n < count`, handed to `finish(n, product)`.
/// The product of n+1 is formed while n is reduced; `operands` of n+1 must
/// not depend on the output of `finish` for n.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn pipelined_products(
    buf: &mut [Fr8Soa],
    count: usize,
    operands: impl Fn(&mut [Fr8Soa], usize) -> (Fr8, Fr8),
    finish: impl Fn(&mut [Fr8Soa], usize, &Fr8),
) {
    debug_assert!(count > 0);
    let (x, y) = operands(buf, 0);
    let mut t = x.product(&y);
    for n in 0..count - 1 {
        let (x, y) = operands(buf, n + 1);
        let (product, next) = Fr8::reduce_while_multiplying::<true>(t, &x, &y);
        t = next;
        finish(buf, n, &product);
    }
    let (product, _) = Fr8::reduce_while_multiplying::<false>(t, &x, &y);
    finish(buf, count - 1, &product);
}

/// Layout S to T, and the length-2 stage of the inverse FFT, which needs no
/// multiplication: inputs below r give outputs below 2r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn transpose_blocks_dit_first_stage(buf: &mut [Fr8Soa]) {
    for block in buf.chunks_exact_mut(BLOCK_VECTORS) {
        Fr8::transpose_block_then_add_sub_pairs(block, &R52);
    }
}

/// Length 2 of the forward FFT, reducing the block's outputs below r. Its
/// inputs are below 2r plus the drift of `Stage::dif`, so sums and offset
/// differences stay below 8r.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn dif_last_stage_canonical(block: &mut [Fr8Soa]) {
    let (r, two_r, four_r) = (Fr8::splat(&R52), Fr8::splat(&TWO_R52), Fr8::splat(&FOUR_R52));
    let canonical = |v: Fr8| v.normalise().cond_sub(&four_r).cond_sub(&two_r).cond_sub(&r);
    for pair in block.chunks_exact_mut(2) {
        let (x, y) = (Fr8::load(&pair[0]), Fr8::load(&pair[1]));
        canonical(x.add_raw(&y)).store(&mut pair[0]);
        canonical(x.sub_raw(&y, &four_r)).store(&mut pair[1]);
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

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::{
        blst_ops::{fr_add, fr_mul, fr_sub},
        fr8_test_util::{available, fr_with_r260, lanes, plus_multiple_of_r, random_fr, soa},
    };

    const SHAPES: [(usize, usize); 4] = [(2, 8), (1, 8), (4, 32), (16, 32)];

    /// 2r + 2^219, the bound on a DIF sum.
    fn drifted_two_r_bound() -> [u64; LIMBS] {
        let mut bound = TWO_R52;
        bound[LIMBS - 1] += 1 << (219 - 52 * (LIMBS - 1));
        bound
    }

    fn below(limbs: &[u64; LIMBS], bound: &[u64; LIMBS]) -> bool {
        limbs.iter().rev().cmp(bound.iter().rev()).is_lt()
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dit_stage_canonical(buf: &mut [Fr8Soa], twiddles: &[Fr8Soa], stage: Stage) {
        stage.dit(buf, twiddles);
        let (r, two_r) = (Fr8::splat(&R52), Fr8::splat(&TWO_R52));
        for vector in buf {
            Fr8::load(vector).normalise().cond_sub(&two_r).cond_sub(&r).store(vector);
        }
    }

    #[test]
    fn dit_stage_matches_blst_butterflies() {
        if !available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        for (half, block) in SHAPES {
            let vectors = 4 * block;
            let values: Vec<[blst_fr; LANES]> =
                (0..vectors).map(|_| std::array::from_fn(|_| random_fr(&mut rng))).collect();
            let weights: Vec<[blst_fr; LANES]> =
                (0..half).map(|_| std::array::from_fn(|_| random_fr(&mut rng))).collect();
            let to_soa =
                |lanes: &[blst_fr; LANES]| soa(&std::array::from_fn(|l| to_r260(&lanes[l])));
            let mut buf: Vec<_> = values.iter().map(to_soa).collect();
            let twiddles: Vec<_> = weights.iter().map(to_soa).collect();
            // SAFETY: `available` checked avx512f and avx512ifma.
            unsafe { dit_stage_canonical(&mut buf, &twiddles, Stage::new(half, block)) };

            for group in (0..vectors).step_by(2 * half) {
                for i in 0..half {
                    let (a, b) = (group + i, group + i + half);
                    for lane in 0..LANES {
                        let product = fr_mul(&values[b][lane], &weights[i][lane]);
                        let sum = fr_add(&values[a][lane], &product);
                        let difference = fr_sub(&values[a][lane], &product);
                        assert_eq!(lanes(&buf[a])[lane], to_r260(&sum), "half {half} sum {a}");
                        assert_eq!(
                            lanes(&buf[b])[lane],
                            to_r260(&difference),
                            "half {half} diff {b}"
                        );
                    }
                }
            }
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dif_stage_outputs(
        buf: &mut [Fr8Soa],
        twiddles: &[Fr8Soa],
        stage: Stage,
    ) -> (Vec<Fr8Soa>, Vec<Fr8Soa>) {
        stage.dif(buf, twiddles);
        let (r, two_r, four_r) = (Fr8::splat(&R52), Fr8::splat(&TWO_R52), Fr8::splat(&FOUR_R52));
        let mut carried = buf.to_vec();
        let mut canonical = buf.to_vec();
        for (carried, canonical) in carried.iter_mut().zip(&mut canonical) {
            let value = Fr8::load(carried).normalise();
            value.store(carried);
            value.cond_sub(&four_r).cond_sub(&two_r).cond_sub(&r).store(canonical);
        }
        (carried, canonical)
    }

    /// Operands spanning [0, 2r + 2^218): below 2r at random, up to 2r + 2^218
    /// - 1 for small residues.
    fn drifted_operand(rng: &mut ChaCha8Rng, lane: usize) -> (blst_fr, [u64; LIMBS]) {
        let small = |rng: &mut ChaCha8Rng| {
            fr_with_r260(&[rng.r#gen(), rng.r#gen(), rng.r#gen(), rng.gen_range(0..1 << 26)])
        };
        let (element, multiple) = match lane % 4 {
            0 => (random_fr(rng), rng.gen_range(0..2)),
            1 => (small(rng), 2),
            2 => (fr_with_r260(&[u64::MAX, u64::MAX, u64::MAX, (1 << 26) - 1]), 2),
            _ => (random_fr(rng), 1),
        };
        (element, plus_multiple_of_r(&to_r260(&element), multiple))
    }

    #[test]
    fn dif_stage_matches_blst_butterflies_and_keeps_its_drift_bound() {
        if !available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let bound = drifted_two_r_bound();
        for (half, block) in SHAPES {
            let vectors = 4 * block;
            let operands: Vec<[(blst_fr, [u64; LIMBS]); LANES]> = (0..vectors)
                .map(|v| std::array::from_fn(|lane| drifted_operand(&mut rng, lane + v)))
                .collect();
            let weights: Vec<[blst_fr; LANES]> =
                (0..half).map(|_| std::array::from_fn(|_| random_fr(&mut rng))).collect();
            let mut buf: Vec<_> =
                operands.iter().map(|v| soa(&std::array::from_fn(|l| v[l].1))).collect();
            let twiddles: Vec<_> =
                weights.iter().map(|w| soa(&std::array::from_fn(|l| to_r260(&w[l])))).collect();
            // SAFETY: `available` checked avx512f and avx512ifma.
            let (carried, canonical) =
                unsafe { dif_stage_outputs(&mut buf, &twiddles, Stage::new(half, block)) };

            for group in (0..vectors).step_by(2 * half) {
                for i in 0..half {
                    let (a, b) = (group + i, group + i + half);
                    for lane in 0..LANES {
                        let (x, y) = (&operands[a][lane].0, &operands[b][lane].0);
                        let sum = fr_add(x, y);
                        let product = fr_mul(&fr_sub(x, y), &weights[i][lane]);
                        assert_eq!(lanes(&canonical[a])[lane], to_r260(&sum), "sum {a}");
                        assert_eq!(lanes(&canonical[b])[lane], to_r260(&product), "product {b}");
                        assert!(below(&lanes(&carried[a])[lane], &bound), "drift of sum {a}");
                    }
                }
            }
        }
    }
}
