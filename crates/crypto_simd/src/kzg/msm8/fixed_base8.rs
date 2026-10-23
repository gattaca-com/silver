//! Σ sᵢ·[sⁱ] over the 64 trusted-setup points on eight lanes: a signed
//! 8-bit-window table per point, and one Horner chain over the windows that
//! adds eight table points per lane group.

use blst::{blst_p1, blst_p1_add_or_double, blst_p1_add_or_double_affine, blst_p1_to_affine};

use crate::{
    bls::{
        blst_p1_affine,
        fp8::{Fp8, LANES},
        g1x8::G1x8,
        g1x8_lazy::Offsets,
        simd_available,
    },
    kzg::{
        FIELD_ELEMENTS_PER_CELL,
        fixed_base::FixedBase,
        msm8::{
            buckets::SignedDigits,
            reduce::{jacobian_lanes, load_indices},
            store::PointStore,
        },
    },
};

const WINDOW_BITS: usize = 8;
const WINDOWS: usize = 32;
const _: () = assert!(WINDOWS * WINDOW_BITS >= 255 + 1);
const MAGNITUDES: usize = 1 << (WINDOW_BITS - 1);
const POINTS: usize = FIELD_ELEMENTS_PER_CELL;
const VECTORS: usize = POINTS / LANES;

pub struct FixedBase8 {
    /// d·Pᵢ at index i·MAGNITUDES + d − 1.
    table: PointStore,
    /// Decides the rare lane whose running sum meets ±(d·Pᵢ).
    fallback: FixedBase,
}

impl FixedBase8 {
    pub fn new(points: &[blst_p1_affine; POINTS]) -> Self {
        assert!(simd_available(), "the table is built on IFMA");
        let mut entries = Vec::with_capacity(POINTS * MAGNITUDES);
        for point in points {
            let mut running = blst_p1::default();
            for _ in 0..MAGNITUDES {
                let previous = running;
                let mut affine = blst_p1_affine::default();
                // SAFETY: valid pointers to single values.
                unsafe {
                    blst_p1_add_or_double_affine(&mut running, &previous, point);
                    blst_p1_to_affine(&mut affine, &running);
                }
                entries.push(affine);
            }
        }
        let mut table = PointStore::new();
        table.reset(entries.len());
        // SAFETY: asserted above.
        unsafe { table.push_blst(&entries) };
        Self { table, fallback: FixedBase::new(points) }
    }

    /// Σ scalars[i]·points[i] for little-endian scalars below 2^255.
    ///
    /// # Safety
    /// avx512f and avx512ifma must be available.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub unsafe fn mult(&mut self, scalars: &[[u8; 32]; POINTS]) -> blst_p1 {
        let mut magnitude = [[0u8; POINTS]; WINDOWS];
        let mut negated = [[false; POINTS]; WINDOWS];
        for (i, scalar) in scalars.iter().enumerate() {
            SignedDigits::new(scalar, WINDOW_BITS, WINDOWS).for_each(|window, digit, negative| {
                magnitude[window][i] = digit as u8;
                negated[window][i] = negative;
            });
        }

        let c = Offsets::new();
        let mut acc = G1x8::from_affine(&Fp8::zero(), &Fp8::zero());
        let mut infinite: u8 = 0xff;
        for window in (0..WINDOWS).rev() {
            if window + 1 < WINDOWS {
                for _ in 0..WINDOW_BITS {
                    acc = acc.double_loose(&c);
                }
                acc = acc.tighten(&c);
            }
            for v in 0..VECTORS {
                let mut index = [0i64; LANES];
                let (mut present, mut negative) = (0u8, 0u8);
                for lane in 0..LANES {
                    let i = v * LANES + lane;
                    let d = magnitude[window][i];
                    if d != 0 {
                        index[lane] = (i * MAGNITUDES + d as usize - 1) as i64;
                        present |= 1 << lane;
                        negative |= u8::from(negated[window][i]) << lane;
                    }
                }
                if present == 0 {
                    continue;
                }
                let (bx, by) = self.table.load_points(load_indices(&index));
                let by = Fp8::select(negative, &by, &c.neg(&by));
                let (sum, undecided) = acc.add_affine(&bx, &by);
                let first = present & infinite;
                let adding = present & !infinite;
                if undecided & adding != 0 {
                    return self.fallback.mult(scalars);
                }
                acc = G1x8 {
                    x: Fp8::select(adding, &Fp8::select(first, &acc.x, &bx), &sum.x),
                    y: Fp8::select(adding, &Fp8::select(first, &acc.y, &by), &sum.y),
                    z: Fp8::select(adding, &Fp8::select(first, &acc.z, &Fp8::one()), &sum.z),
                };
                infinite &= !present;
            }
        }

        let lanes = jacobian_lanes(&acc);
        let mut total = blst_p1::default();
        for lane in 0..LANES {
            if infinite & (1 << lane) == 0 {
                let before = total;
                // SAFETY: valid pointers to single values.
                unsafe { blst_p1_add_or_double(&mut total, &before, &lanes[lane]) };
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::{
        bls::simd_available,
        kzg::{
            blst_msm::scalar_bytes,
            blst_ops::{fr_from_bytes, fr_from_u64, fr_sub, g1_to_affine},
            setup::Setup,
        },
    };

    #[test]
    fn matches_blst_fixed_base() {
        if !simd_available() {
            return;
        }
        let points: [blst_p1_affine; POINTS] =
            Setup::decode().g1_monomial.try_into().unwrap_or_else(|_| unreachable!());
        let mut ours = FixedBase8::new(&points);
        let mut theirs = FixedBase::new(&points);
        let mut rng = ChaCha8Rng::seed_from_u64(0xf1ed);
        let (zero, one) = (fr_from_u64(0), fr_from_u64(1));
        let minus_one = fr_sub(&zero, &one);
        let mut cases: Vec<[[u8; 32]; POINTS]> = vec![
            [scalar_bytes(&zero); POINTS],
            [scalar_bytes(&one); POINTS],
            [scalar_bytes(&minus_one); POINTS],
        ];
        for _ in 0..8 {
            cases.push(std::array::from_fn(|_| {
                loop {
                    let mut bytes: [u8; 32] = rng.r#gen();
                    bytes[0] &= 0x7f;
                    if let Some(fr) = fr_from_bytes(&bytes) {
                        break scalar_bytes(&fr);
                    }
                }
            }));
        }
        for (k, scalars) in cases.iter().enumerate() {
            // SAFETY: checked above.
            let got = unsafe { ours.mult(scalars) };
            assert!(g1_to_affine(&got) == g1_to_affine(&theirs.mult(scalars)), "case {k}");
        }
    }
}
