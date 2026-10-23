//! The per-cell scalars of the batch check, on `Fr8`: the powers r^k of the
//! challenge, the pairing scalars r^k (proofs, LL), r^k·h_c^64 (proofs, RLP)
//! and the per-commitment sums of r^k (RLC), each as canonical little-endian
//! bytes.
//!
//! Data is kept plain and below 2r, with constants in R' = 2^260 form, so that
//! `Fr8::mul(data, constant)` is the plain product, below 2r. The powers are
//! the exception: they stay in R' form, the form `Fr8::mul` wants of a factor
//! that multiplies plain cell elements.

use blst::blst_fr;

use crate::kzg::{
    blst_msm::scalar_bytes,
    blst_ops::{fr_from_u64, fr_mul},
    cosets::Cosets,
    fr8::{Fr8, Fr8Soa, LANES, LIMBS, MASK52, R52, TWO_R52, to_r260, unpack52},
};

/// A limb of a plain value is below 2^52, so this many of them sum below 2^63,
/// where signed carry propagation still works.
const CELLS_PER_FOLD: usize = 1 << 11;
const ONE: [u64; LIMBS] = [1, 0, 0, 0, 0];

pub struct CellScalars {
    /// h_c^64, plain, for each cell index c.
    shift_pow_cell: Vec<[u64; LIMBS]>,
    one_r260: [u64; LIMBS],
    two_pow_260_r260: [u64; LIMBS],
    /// r^k in R' form, below 2r: lane l of vector g is cell 8g+l.
    powers: Vec<Fr8Soa>,
    ll: Vec<[u8; 32]>,
    rlp: Vec<[u8; 32]>,
    rlc: Vec<[u8; 32]>,
    /// Limb sums of the powers per unique commitment, since the last fold.
    partial: Vec<[u64; LIMBS]>,
    /// Folded sums per unique commitment, plain and below 2r.
    totals: Vec<Fr8Soa>,
}

impl CellScalars {
    pub fn new(cosets: &Cosets) -> Self {
        let plain = |fr: &blst_fr| {
            let bytes = scalar_bytes(fr);
            unpack52(&std::array::from_fn(|w| {
                u64::from_le_bytes(bytes[8 * w..8 * (w + 1)].try_into().unwrap())
            }))
        };
        let mut two_pow_260 = fr_from_u64(1);
        for _ in 0..5 {
            two_pow_260 = fr_mul(&two_pow_260, &fr_from_u64(1 << 52));
        }
        Self {
            shift_pow_cell: cosets.shift_pow_cell.iter().map(plain).collect(),
            one_r260: to_r260(&fr_from_u64(1)),
            two_pow_260_r260: to_r260(&two_pow_260),
            powers: Vec::new(),
            ll: Vec::new(),
            rlp: Vec::new(),
            rlc: Vec::new(),
            partial: Vec::new(),
            totals: Vec::new(),
        }
    }

    pub fn ll(&self) -> &[[u8; 32]] {
        &self.ll
    }

    pub fn rlp(&self) -> &[[u8; 32]] {
        &self.rlp
    }

    pub fn rlc(&self) -> &[[u8; 32]] {
        &self.rlc
    }

    /// r^k in R' form, normalised and below 2r.
    pub fn power_r260(&self, k: usize) -> [u64; LIMBS] {
        std::array::from_fn(|j| self.powers[k / LANES].0[j][k % LANES])
    }

    /// The scalars of the batch whose cell k is in column `cell_indices[k]` and
    /// under commitment `index_of_cell[k]` of `unique`.
    ///
    /// # Safety
    /// avx512f and avx512ifma must be available.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub unsafe fn fill(
        &mut self,
        r: &blst_fr,
        cell_indices: &[u64],
        index_of_cell: &[usize],
        unique: usize,
    ) {
        let n = cell_indices.len();
        self.fill_powers(r, n.div_ceil(LANES));
        self.ll.clear();
        self.rlp.clear();
        self.partial.clear();
        self.partial.resize(unique, [0; LIMBS]);
        self.totals.clear();
        self.totals.resize(unique.div_ceil(LANES), Fr8Soa::ZERO);

        let (one, r_modulus) = (Fr8::splat(&ONE), Fr8::splat(&R52));
        let mut cells_since_fold = 0;
        for g in 0..self.powers.len() {
            let power = Fr8::load(&self.powers[g]);
            let cells = LANES.min(n - g * LANES);

            let mut plain = Fr8Soa::ZERO;
            power.mul(&one).cond_sub(&r_modulus).store(&mut plain);

            let mut shift = Fr8Soa::ZERO;
            for lane in 0..cells {
                let limbs = &self.shift_pow_cell[cell_indices[g * LANES + lane] as usize];
                for j in 0..LIMBS {
                    shift.0[j][lane] = limbs[j];
                }
            }
            let mut shifted = Fr8Soa::ZERO;
            power.mul(&Fr8::load(&shift)).cond_sub(&r_modulus).store(&mut shifted);

            for lane in 0..cells {
                self.ll.push(plain.lane_le_bytes(lane));
                self.rlp.push(shifted.lane_le_bytes(lane));
                let sum = &mut self.partial[index_of_cell[g * LANES + lane]];
                for j in 0..LIMBS {
                    sum[j] += plain.0[j][lane];
                }
                cells_since_fold += 1;
                if cells_since_fold == CELLS_PER_FOLD {
                    self.fold_partial();
                    cells_since_fold = 0;
                }
            }
        }
        self.fold_partial();

        self.rlc.clear();
        for (g, total) in self.totals.iter().enumerate() {
            let mut canonical = Fr8Soa::ZERO;
            Fr8::load(total).cond_sub(&r_modulus).store(&mut canonical);
            for lane in 0..LANES.min(unique - g * LANES) {
                self.rlc.push(canonical.lane_le_bytes(lane));
            }
        }
    }

    /// r^0, r^1, …, in R' form: the first eight from blst, then each vector
    /// from the one before it times r^8.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn fill_powers(&mut self, r: &blst_fr, groups: usize) {
        self.powers.clear();
        if groups == 0 {
            return;
        }
        let mut first = Fr8Soa::ZERO;
        let mut power = fr_from_u64(1);
        for lane in 0..LANES {
            let limbs = to_r260(&power);
            for j in 0..LIMBS {
                first.0[j][lane] = limbs[j];
            }
            power = fr_mul(&power, r);
        }
        let step = Fr8::splat(&to_r260(&power));
        self.powers.push(first);
        for g in 1..groups {
            let mut next = Fr8Soa::ZERO;
            Fr8::load(&self.powers[g - 1]).mul(&step).store(&mut next);
            self.powers.push(next);
        }
    }

    /// Reduces the limb sums into the totals and clears them.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn fold_partial(&mut self) {
        let (one, two_pow_260) = (Fr8::splat(&self.one_r260), Fr8::splat(&self.two_pow_260_r260));
        let two_r = Fr8::splat(&TWO_R52);
        for (g, total) in self.totals.iter_mut().enumerate() {
            let mut low = Fr8Soa::ZERO;
            let mut high = Fr8Soa::ZERO;
            let sums = &self.partial[g * LANES..self.partial.len().min((g + 1) * LANES)];
            for (lane, sum) in sums.iter().enumerate() {
                let mut carry = 0;
                for j in 0..LIMBS {
                    let limb = sum[j] + carry;
                    low.0[j][lane] = limb & MASK52;
                    carry = limb >> 52;
                }
                high.0[0][lane] = carry;
            }
            let low_reduced = Fr8::load(&low).mul(&one);
            let high_reduced = Fr8::load(&high).mul(&two_pow_260);
            let reduced = low_reduced.add_raw(&high_reduced).normalise().cond_sub(&two_r);
            Fr8::load(total).add_raw(&reduced).normalise().cond_sub(&two_r).store(total);
        }
        self.partial.fill([0; LIMBS]);
    }
}
