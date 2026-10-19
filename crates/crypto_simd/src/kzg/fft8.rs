//! Iterative in-place radix-2 FFT over Fr on `Fr8` vectors: element 8v + l of
//! the sequence is lane l of vector v. Stages that pair elements h ≥ 8 apart
//! pair whole vectors. The three stages below pair lanes of two adjacent
//! vectors, gathered into two vectors by `Fr8::permute` and scattered back.

use std::arch::x86_64::{__m512i, _mm512_set_epi64};

use blst::blst_fr;

use crate::kzg::fr8::{Fr8, LANES, multiplier};

pub struct Fft8 {
    vectors: usize,
    /// ω_2h^j for j < h, as h / 8 vectors per stage h ≥ 8, h ascending.
    wide: Vec<Fr8>,
    /// Lane m holds ω_2h^(m % h), the gathered order of stage h.
    stage2: Fr8,
    stage4: Fr8,
}

/// `Fr8::permute` indices for the pairs h apart, h < 8, in two adjacent
/// vectors `a` and `b`. `upper` gathers the first element of each pair, from
/// `a` into lanes 0–3 and from `b` into lanes 4–7; `lower` gathers the
/// second. `first` and `second` scatter the two gathered vectors back into
/// `a` and `b`.
struct LanePairs {
    upper: __m512i,
    lower: __m512i,
    first: __m512i,
    second: __m512i,
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn index_vector(index: &[i64; LANES]) -> __m512i {
    _mm512_set_epi64(index[7], index[6], index[5], index[4], index[3], index[2], index[1], index[0])
}

impl LanePairs {
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn new(h: usize) -> Self {
        let half = LANES / 2;
        let mut upper = [0i64; LANES];
        let mut lower = [0i64; LANES];
        let mut m = 0;
        while m < LANES {
            let element = (m % half / h * 2 * h + m % h + m / half * LANES) as i64;
            upper[m] = element;
            lower[m] = element + h as i64;
            m += 1;
        }
        let mut first = [0i64; LANES];
        let mut second = [0i64; LANES];
        let mut e = 0;
        while e < LANES {
            let m = (e / (2 * h) * h + e % h) as i64;
            let from_lower = if e % (2 * h) < h { 0 } else { LANES as i64 };
            first[e] = m + from_lower;
            second[e] = m + half as i64 + from_lower;
            e += 1;
        }
        Self {
            upper: index_vector(&upper),
            lower: index_vector(&lower),
            first: index_vector(&first),
            second: index_vector(&second),
        }
    }
}

impl Fft8 {
    /// For n-element transforms, n ≥ 16, with ω the root of order n among
    /// `roots`, the powers of a primitive root of an order that n divides.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn new(roots: &[blst_fr], n: usize) -> Self {
        assert!(n >= 2 * LANES && n & (n - 1) == 0, "power-of-two length of two vectors or more");
        assert!(roots.len() % n == 0, "matching lengths");
        let stride = roots.len() / n;
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
        let stage2 = stage_twiddles(roots, stride * n / 4, 0, 2);
        let stage4 = stage_twiddles(roots, stride * n / 8, 0, 4);
        Self {
            vectors: n / LANES,
            wide,
            stage2: Fr8::load(&stage2, 0),
            stage4: Fr8::load(&stage4, 0),
        }
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
        dif_lanes(data, &LanePairs::new(4), Some(&self.stage4));
        dif_lanes(data, &LanePairs::new(2), Some(&self.stage2));
        dif_lanes(data, &LanePairs::new(1), None);
    }

    /// Σ_j x_j·ω^(i·j) at i, from x_j at `reverse_bits(j)`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn dit(&self, data: &mut [Fr8]) {
        assert!(data.len() == self.vectors, "one transform length");
        dit_lanes(data, &LanePairs::new(1), None);
        dit_lanes(data, &LanePairs::new(2), Some(&self.stage2));
        dit_lanes(data, &LanePairs::new(4), Some(&self.stage4));
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
                data[block + j + half] = a.sub(&b).mul(&self.wide[half - 1 + j]);
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
                let t = data[block + j + half].mul(&self.wide[half - 1 + j]);
                data[block + j] = a.add(&t);
                data[block + j + half] = a.sub(&t);
                j += 1;
            }
            block += 2 * half;
        }
    }
}

/// `multiplier(ω^(k·step))` for k = start + m % h, m < 8.
fn stage_twiddles(roots: &[blst_fr], step: usize, start: usize, h: usize) -> [blst_fr; LANES] {
    let mut twiddles = [blst_fr::default(); LANES];
    let mut m = 0;
    while m < LANES {
        twiddles[m] = multiplier(&roots[(start + m % h) * step]);
        m += 1;
    }
    twiddles
}

/// `None` stands for twiddles of 1.
#[target_feature(enable = "avx512f,avx512ifma")]
fn dif_lanes(data: &mut [Fr8], pairs: &LanePairs, twiddles: Option<&Fr8>) {
    let mut v = 0;
    while v < data.len() {
        let (a, b) = (data[v], data[v + 1]);
        let upper = a.permute(pairs.upper, &b);
        let lower = a.permute(pairs.lower, &b);
        let sum = upper.add(&lower);
        let difference = upper.sub(&lower);
        let lower = match twiddles {
            Some(w) => difference.mul(w),
            None => difference,
        };
        data[v] = sum.permute(pairs.first, &lower);
        data[v + 1] = sum.permute(pairs.second, &lower);
        v += 2;
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn dit_lanes(data: &mut [Fr8], pairs: &LanePairs, twiddles: Option<&Fr8>) {
    let mut v = 0;
    while v < data.len() {
        let (a, b) = (data[v], data[v + 1]);
        let upper = a.permute(pairs.upper, &b);
        let lower = a.permute(pairs.lower, &b);
        let t = match twiddles {
            Some(w) => lower.mul(w),
            None => lower,
        };
        let sum = upper.add(&t);
        let difference = upper.sub(&t);
        data[v] = sum.permute(pairs.first, &difference);
        data[v + 1] = sum.permute(pairs.second, &difference);
        v += 2;
    }
}
