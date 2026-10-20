//! Iterative in-place radix-2 FFT over Fr on `Fr8` vectors: element 8v + l of
//! the sequence is lane l of vector v. Stages that pair elements h ≥ 8 apart
//! pair whole vectors. The three stages below run on each block of eight
//! vectors transposed, where lane l of vector k is element 8l + k of the
//! block, so they too pair whole vectors.

use blst::blst_fr;

use crate::kzg::{
    blst_ops::fr_from_u64,
    fr8::{Fr8, LANES, multiplier},
};

pub struct Fft8 {
    vectors: usize,
    /// Multipliers of ω_2h^j for j < h, as h / 8 vectors per stage h ≥ 8, h
    /// ascending. Each is below r, so `mul` takes it with any normalised data.
    wide: Vec<Fr8>,
    /// Multipliers of ω_2h^j in every lane at h − 1 + j, for j < h and
    /// h = 1, 2, 4, each below r like `wide`'s. The stages skip the product by
    /// ω_2h^0 = 1.
    short: Vec<Fr8>,
}

impl Fft8 {
    /// For n-element transforms, 64 ≤ n ≤ 4096, with ω the root of order n
    /// among `roots`, the powers of a primitive root of an order that n
    /// divides.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn new(roots: &[blst_fr], n: usize) -> Self {
        assert!(
            n >= LANES * LANES && n & (n - 1) == 0,
            "power-of-two length of eight vectors or more"
        );
        assert!(n <= 1 << 12, "dit's outputs stay below 2^260 only up to 4096 elements");
        assert!(roots.len() % n == 0, "matching lengths");
        let stride = roots.len() / n;
        let mut short = Vec::with_capacity(LANES - 1);
        let mut h = 1;
        while h < LANES {
            let mut j = 0;
            while j < h {
                // One root in every lane.
                let twiddles = stage_twiddles(roots, stride * n / (2 * h), j, 1);
                short.push(Fr8::load(&twiddles, 0));
                j += 1;
            }
            h *= 2;
        }
        let mut wide = Vec::with_capacity(n / LANES);
        let mut h = LANES;
        while h < n {
            let mut v = 0;
            while v < h / LANES {
                let twiddles = stage_twiddles(roots, stride * n / (2 * h), v * LANES, h);
                wide.push(Fr8::load(&twiddles, 0));
                v += 1;
            }
            h *= 2;
        }
        Self { vectors: n / LANES, wide, short }
    }

    /// Σ_j x_j·ω^(i·j) at `reverse_bits(i)`, from x in natural order.
    /// Inputs lazy(2, 32), such as reduced values and products, give reduced
    /// outputs.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn dif(&self, data: &mut [Fr8]) {
        assert!(data.len() == self.vectors, "one transform length");
        let mut half = self.vectors / 2;
        while half > 0 {
            self.dif_wide(data, half);
            half /= 2;
        }
        let mut block = 0;
        while block < self.vectors {
            let mut t = Fr8::transpose(data, block);
            self.dif_short(&mut t, 4);
            self.dif_short(&mut t, 2);
            self.dif_short(&mut t, 1);
            set_block(data, block, &Fr8::transpose(&t, 0));
            block += LANES;
        }
    }

    /// Σ_j x_j·ω^(i·j) at i, from x_j at `reverse_bits(j)`. Sums and
    /// differences stay unreduced, so reduced inputs give outputs in
    /// lazy(16 + 2w, 73 + 33w), w = log2(n) − 3. That is lazy(34, 370) at
    /// n = 4096, the longest transform `new` takes: one more stage would reach
    /// 36r > 2^260.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn dit(&self, data: &mut [Fr8]) {
        assert!(data.len() == self.vectors, "one transform length");
        let mut block = 0;
        while block < self.vectors {
            let mut t = Fr8::transpose(data, block);
            self.dit_short(&mut t, 1);
            self.dit_short(&mut t, 2);
            self.dit_short(&mut t, 4);
            set_block(data, block, &Fr8::transpose(&t, 0));
            block += LANES;
        }
        let mut half = 1;
        while half < self.vectors {
            self.dit_wide(data, half);
            half *= 2;
        }
    }

    /// The stage pairing vectors `half` apart, lazy(2, 32) to lazy(2, 32). Sums
    /// are reduced; differences, offset by 2r, go to their products as they
    /// are.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dif_wide(&self, data: &mut [Fr8], half: usize) {
        let input_bound = Fr8::multiple_of_r(2);
        let pairs = self.vectors / 2;
        let (x, w) = self.dif_wide_operands(data, half, 0, &input_bound);
        let mut t = x.product(&w);
        let mut n = 0;
        while n + 1 < pairs {
            let (x, w) = self.dif_wide_operands(data, half, n + 1, &input_bound);
            let (product, next) = Fr8::reduce_while_multiplying(&t, &x, &w);
            data[first_of_pair(n, half) + half] = product;
            t = next;
            n += 1;
        }
        data[first_of_pair(n, half) + half] = Fr8::reduce(&t);
    }

    /// Butterfly n's sum, stored, and its difference with its twiddle.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dif_wide_operands(
        &self,
        data: &mut [Fr8],
        half: usize,
        n: usize,
        bound: &Fr8,
    ) -> (Fr8, Fr8) {
        let a = first_of_pair(n, half);
        let (x, y) = (data[a], data[a + half]);
        data[a] = x.add(&y);
        (x.sub_raw(&y, bound).normalise(), self.wide[half - 1 + (n & (half - 1))])
    }

    /// lazy(k, m) to lazy(k + 2, m + 33). Products by twiddles below r lie
    /// below 2r, so 2r offsets the differences.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dit_wide(&self, data: &mut [Fr8], half: usize) {
        let product_bound = Fr8::multiple_of_r(2);
        let pairs = self.vectors / 2;
        let (b, w) = self.dit_wide_operands(data, half, 0);
        let mut t = b.product(&w);
        let mut n = 0;
        while n + 1 < pairs {
            let (b, w) = self.dit_wide_operands(data, half, n + 1);
            let (product, next) = Fr8::reduce_while_multiplying(&t, &b, &w);
            dit_finish(data, first_of_pair(n, half), half, &product, &product_bound);
            t = next;
            n += 1;
        }
        dit_finish(data, first_of_pair(n, half), half, &Fr8::reduce(&t), &product_bound);
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dit_wide_operands(&self, data: &[Fr8], half: usize, n: usize) -> (Fr8, Fr8) {
        let a = first_of_pair(n, half);
        (data[a + half].normalise(), self.wide[half - 1 + (n & (half - 1))])
    }

    /// The stage pairing elements h < 8 apart, on a transposed block: vectors
    /// h apart. As in `dif_wide`, except that j = 0 differences skip their
    /// product and so are reduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dif_short(&self, t: &mut [Fr8; LANES], h: usize) {
        let input_bound = Fr8::multiple_of_r(2);
        let mut group = 0;
        while group < LANES {
            let (a, b) = (t[group], t[group + h]);
            t[group] = a.add(&b);
            t[group + h] = a.sub(&b);
            group += 2 * h;
        }
        if h == 1 {
            return;
        }
        let (x, y) = (t[1], t[1 + h]);
        t[1] = x.add(&y);
        let mut pending_at = 1 + h;
        let mut pending = x.sub_raw(&y, &input_bound).normalise().product(&self.short[h]);
        let (mut group, mut j) = (0, 2);
        loop {
            if j == h {
                group += 2 * h;
                j = 1;
                if group >= LANES {
                    break;
                }
            }
            let (x, y) = (t[group + j], t[group + j + h]);
            t[group + j] = x.add(&y);
            let difference = x.sub_raw(&y, &input_bound).normalise();
            let (product, next) =
                Fr8::reduce_while_multiplying(&pending, &difference, &self.short[h - 1 + j]);
            t[pending_at] = product;
            pending = next;
            pending_at = group + j + h;
            j += 1;
        }
        t[pending_at] = Fr8::reduce(&pending);
    }

    /// Stages 1, 2 and 4 in turn take reduced inputs to lazy(4, 3),
    /// lazy(8, 36) and lazy(16, 73). The j = 0 pairs skip the product, so
    /// they offset their differences by the inputs' bound 2h·r, doubling it.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dit_short(&self, t: &mut [Fr8; LANES], h: usize) {
        let input_bound = Fr8::multiple_of_r(2 * h as u64);
        let product_bound = Fr8::multiple_of_r(2);
        let mut group = 0;
        while group < LANES {
            let (a, b) = (t[group], t[group + h]);
            t[group] = a.add_raw(&b);
            t[group + h] = a.sub_raw(&b, &input_bound);
            group += 2 * h;
        }
        if h == 1 {
            return;
        }
        let mut pending_at = 1;
        let mut pending = t[1 + h].normalise().product(&self.short[h]);
        let (mut group, mut j) = (0, 2);
        loop {
            if j == h {
                group += 2 * h;
                j = 1;
                if group >= LANES {
                    break;
                }
            }
            let b = t[group + j + h].normalise();
            let (product, next) =
                Fr8::reduce_while_multiplying(&pending, &b, &self.short[h - 1 + j]);
            dit_finish(t, pending_at, h, &product, &product_bound);
            pending = next;
            pending_at = group + j;
            j += 1;
        }
        dit_finish(t, pending_at, h, &Fr8::reduce(&pending), &product_bound);
    }
}

/// The first vector of butterfly n in the stage pairing vectors `half` apart.
fn first_of_pair(n: usize, half: usize) -> usize {
    2 * n - (n & (half - 1))
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn dit_finish(data: &mut [Fr8], a: usize, half: usize, product: &Fr8, bound: &Fr8) {
    let x = data[a];
    data[a] = x.add_raw(product);
    data[a + half] = x.sub_raw(product, bound);
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn set_block(data: &mut [Fr8], at: usize, block: &[Fr8; LANES]) {
    let mut k = 0;
    while k < LANES {
        data[at + k] = block[k];
        k += 1;
    }
}

/// `multiplier(ω^(k·step))` for k = start + m % h, m < 8.
fn stage_twiddles(roots: &[blst_fr], step: usize, start: usize, h: usize) -> [blst_fr; LANES] {
    let mut twiddles = [fr_from_u64(0); LANES];
    let mut m = 0;
    while m < LANES {
        twiddles[m] = multiplier(&roots[(start + m % h) * step]);
        m += 1;
    }
    twiddles
}
