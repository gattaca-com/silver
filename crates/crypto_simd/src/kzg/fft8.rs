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
    /// ω_2h^j for j < h, as h / 8 vectors per stage h ≥ 8, h ascending.
    wide: Vec<Fr8>,
    /// ω_2h^j in every lane at h − 1 + j, for j < h and h = 1, 2, 4. The
    /// stages skip the product by ω_2h^0 = 1.
    short: Vec<Fr8>,
}

impl Fft8 {
    /// For n-element transforms, n ≥ 64, with ω the root of order n among
    /// `roots`, the powers of a primitive root of an order that n divides.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn new(roots: &[blst_fr], n: usize) -> Self {
        assert!(
            n >= LANES * LANES && n & (n - 1) == 0,
            "power-of-two length of eight vectors or more"
        );
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

    /// Σ_j x_j·ω^(i·j) at i, from x_j at `reverse_bits(j)`.
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

    /// The stage pairing vectors `half` apart.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dif_wide(&self, data: &mut [Fr8], half: usize) {
        let mut block = 0;
        while block < self.vectors {
            let mut j = 0;
            while j < half {
                let (a, b) = (data[block + j], data[block + j + half]);
                data[block + j] = a.add(&b);
                data[block + j + half] = a.sub(&b).mul(&self.wide[half - 1 + j]).normalise();
                j += 1;
            }
            block += 2 * half;
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn dit_wide(&self, data: &mut [Fr8], half: usize) {
        let mut block = 0;
        while block < self.vectors {
            let mut j = 0;
            while j < half {
                let a = data[block + j];
                let t = data[block + j + half].mul(&self.wide[half - 1 + j]).normalise();
                data[block + j] = a.add(&t);
                data[block + j + half] = a.sub(&t);
                j += 1;
            }
            block += 2 * half;
        }
    }

    /// The stage pairing elements h < 8 apart, on a transposed block: vectors
    /// h apart.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dif_short(&self, t: &mut [Fr8; LANES], h: usize) {
        let mut group = 0;
        while group < LANES {
            let mut j = 0;
            while j < h {
                let (a, b) = (t[group + j], t[group + j + h]);
                t[group + j] = a.add(&b);
                let difference = a.sub(&b);
                t[group + j + h] = if j == 0 {
                    difference
                } else {
                    difference.mul(&self.short[h - 1 + j]).normalise()
                };
                j += 1;
            }
            group += 2 * h;
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn dit_short(&self, t: &mut [Fr8; LANES], h: usize) {
        let mut group = 0;
        while group < LANES {
            let mut j = 0;
            while j < h {
                let a = t[group + j];
                let b = t[group + j + h];
                let product = if j == 0 { b } else { b.mul(&self.short[h - 1 + j]).normalise() };
                t[group + j] = a.add(&product);
                t[group + j + h] = a.sub(&product);
                j += 1;
            }
            group += 2 * h;
        }
    }
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
