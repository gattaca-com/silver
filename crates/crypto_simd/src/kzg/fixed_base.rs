//! Multiplication of the 64 trusted-setup points by a scalar each, from a
//! table precomputed once.

use blst::{
    blst_p1, blst_p1s_mult_wbits, blst_p1s_mult_wbits_precompute,
    blst_p1s_mult_wbits_precompute_sizeof, blst_p1s_mult_wbits_scratch_sizeof, limb_t,
};

use crate::{bls::blst_p1_affine, kzg::FIELD_ELEMENTS_PER_CELL};

const WINDOW_BITS: usize = 10;
const SCALAR_BITS: usize = 255;
const POINTS: usize = FIELD_ELEMENTS_PER_CELL;

pub struct FixedBase {
    table: Vec<blst_p1_affine>,
    scratch: Vec<limb_t>,
}

impl FixedBase {
    pub fn new(points: &[blst_p1_affine; POINTS]) -> Self {
        // SAFETY: a pure size query.
        let table_bytes = unsafe { blst_p1s_mult_wbits_precompute_sizeof(WINDOW_BITS, POINTS) };
        let mut table = vec![blst_p1_affine::default(); table_bytes / size_of::<blst_p1_affine>()];
        let points_arg = [points.as_ptr(), std::ptr::null()];
        // SAFETY: `table` has the size blst asked for, and a null second pointer tells
        // blst that the first points at a contiguous array of `POINTS` points.
        unsafe {
            blst_p1s_mult_wbits_precompute(
                table.as_mut_ptr(),
                WINDOW_BITS,
                points_arg.as_ptr(),
                POINTS,
            );
        }
        // SAFETY: a pure size query.
        let scratch_bytes = unsafe { blst_p1s_mult_wbits_scratch_sizeof(POINTS) };
        Self { table, scratch: vec![0; scratch_bytes.div_ceil(size_of::<limb_t>())] }
    }

    /// Σ scalars[i]·points[i] for little-endian scalars below 2^255.
    pub fn mult(&mut self, scalars: &[[u8; 32]; POINTS]) -> blst_p1 {
        let scalars_arg = [scalars.as_ptr().cast::<u8>(), std::ptr::null()];
        let mut out = blst_p1::default();
        // SAFETY: `table` and `scratch` are the sizes blst asked for in `new`, and
        // `scalars` holds `POINTS` scalars of `SCALAR_BITS` bits.
        unsafe {
            blst_p1s_mult_wbits(
                &mut out,
                self.table.as_ptr(),
                WINDOW_BITS,
                POINTS,
                scalars_arg.as_ptr(),
                SCALAR_BITS,
                self.scratch.as_mut_ptr(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use blst::blst_fr;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::{
        blst_msm::scalar_bytes,
        blst_ops::{LincombScratch, fr_from_bytes, fr_from_u64, fr_sub, g1_lincomb, g1_to_affine},
        setup::Setup,
    };

    fn points() -> [blst_p1_affine; POINTS] {
        Setup::decode().g1_monomial.try_into().unwrap_or_else(|_| unreachable!())
    }

    fn matches_lincomb(base: &mut FixedBase, points: &[blst_p1_affine; POINTS], frs: &[blst_fr]) {
        let scalars: [[u8; 32]; POINTS] = std::array::from_fn(|i| scalar_bytes(&frs[i]));
        let expected = g1_lincomb(points, frs, &mut LincombScratch::new());
        assert!(g1_to_affine(&base.mult(&scalars)) == g1_to_affine(&expected));
    }

    #[test]
    fn matches_lincomb_on_random_and_edge_scalars() {
        let points = points();
        let mut base = FixedBase::new(&points);
        let mut rng = ChaCha8Rng::seed_from_u64(0xf1ed_ba5e);
        let (zero, one) = (fr_from_u64(0), fr_from_u64(1));
        let minus_one = fr_sub(&zero, &one);

        let constant = |value: &blst_fr| vec![*value; POINTS];
        matches_lincomb(&mut base, &points, &constant(&zero));
        matches_lincomb(&mut base, &points, &constant(&one));
        matches_lincomb(&mut base, &points, &constant(&minus_one));

        let mut mixed = constant(&zero);
        mixed[1] = one;
        mixed[2] = minus_one;
        mixed[63] = one;
        matches_lincomb(&mut base, &points, &mixed);

        for _ in 0..8 {
            let random: Vec<_> = (0..POINTS)
                .map(|_| {
                    loop {
                        let mut bytes: [u8; 32] = rng.r#gen();
                        bytes[0] &= 0x7f;
                        if let Some(fr) = fr_from_bytes(&bytes) {
                            break fr;
                        }
                    }
                })
                .collect();
            matches_lincomb(&mut base, &points, &random);
        }
    }
}
