//! Eight Fp2 = Fp[i]/(i² + 1) elements, one per lane, over [`Fp8`].

use std::arch::x86_64::__mmask8;

use blst::blst_fp2;

use crate::fp8::{Fp8, LANES, Limbs};

#[derive(Clone, Copy)]
pub struct Fp2x8 {
    pub c0: Fp8,
    pub c1: Fp8,
}

impl Fp2x8 {
    /// Lane `l` takes `values[l]`, in blst's Montgomery form.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn from_blst(values: &[blst_fp2; LANES]) -> Self {
        Self {
            c0: Fp8::from_blst_limbs(&values.map(|v| v.fp[0].l)),
            c1: Fp8::from_blst_limbs(&values.map(|v| v.fp[1].l)),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn splat(limbs: &[Limbs; 2]) -> Self {
        Self { c0: Fp8::splat_limbs(&limbs[0]), c1: Fp8::splat_limbs(&limbs[1]) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn one() -> Self {
        Self { c0: Fp8::one(), c1: Fp8::zero() }
    }

    /// Karatsuba: three Fp products.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn mul(&self, rhs: &Self) -> Self {
        let v0 = self.c0.mul(&rhs.c0);
        let v1 = self.c1.mul(&rhs.c1);
        let s = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1));
        Self { c0: v0.sub(&v1), c1: s.sub(&v0).sub(&v1) }
    }

    /// (c0 + c1)(c0 - c1) + 2·c0·c1·i: two Fp products.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn square(&self) -> Self {
        let c0 = self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1));
        let c1 = self.c0.mul(&self.c1).double();
        Self { c0, c1 }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.add(&rhs.c0), c1: self.c1.add(&rhs.c1) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.sub(&rhs.c0), c1: self.c1.sub(&rhs.c1) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn neg(&self) -> Self {
        Self { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn conjugate(&self) -> Self {
        Self { c0: self.c0, c1: self.c1.neg() }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn eq_mask(&self, rhs: &Self) -> __mmask8 {
        self.c0.eq_mask(&rhs.c0) & self.c1.eq_mask(&rhs.c1)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn is_zero_mask(&self) -> __mmask8 {
        self.c0.is_zero_mask() & self.c1.is_zero_mask()
    }
}
