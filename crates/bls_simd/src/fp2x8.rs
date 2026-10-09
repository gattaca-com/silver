//! Eight Fp2 = Fp[i]/(i² + 1) elements, one per lane, over [`Fp8`].

use std::arch::x86_64::__mmask8;

use crate::fp8::{Fp8, Limbs};

#[derive(Clone, Copy)]
pub struct Fp2x8 {
    pub c0: Fp8,
    pub c1: Fp8,
}

impl Fp2x8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn splat(limbs: &[Limbs; 2]) -> Self {
        Self { c0: Fp8::splat_limbs(&limbs[0]), c1: Fp8::splat_limbs(&limbs[1]) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
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
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.add(&rhs.c0), c1: self.c1.add(&rhs.c1) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.sub(&rhs.c0), c1: self.c1.sub(&rhs.c1) }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn neg(&self) -> Self {
        Self { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn conjugate(&self) -> Self {
        Self { c0: self.c0, c1: self.c1.neg() }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn mul_by_i(&self) -> Self {
        Self { c0: self.c1.neg(), c1: self.c0 }
    }

    /// Lanes of `k` take `b`, the rest `a`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn select(k: __mmask8, a: &Self, b: &Self) -> Self {
        Self { c0: Fp8::select(k, &a.c0, &b.c0), c1: Fp8::select(k, &a.c1, &b.c1) }
    }

    /// blst's `sqrt_fp2`: two Fp exponentiations give a candidate whose
    /// square is χ(t)·self whenever self is a square, so one rotation by i
    /// covers blst's four alignments. The mask marks the lanes that have a
    /// root.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sqrt(&self) -> (Self, __mmask8) {
        let n = self.c0.square().add(&self.c1.square()).sqrt_candidate();
        let plus = self.c0.add(&n);
        let t = Fp8::select(plus.is_zero_mask(), &plus, &self.c0.sub(&n)).half();
        let r = t.pow_p_minus_3_over_4();
        let candidate = Self { c0: t.mul(&r), c1: self.c1.half().mul(&r) };
        let square = candidate.square();
        let squares_to_self = square.eq_mask(self);
        let squares_to_neg = square.eq_mask(&self.neg());
        let root = Self::select(squares_to_neg, &candidate, &candidate.mul_by_i());
        (root, squares_to_self | squares_to_neg)
    }

    /// Lanes holding the lexicographically larger of two square roots: c1
    /// decides, and c0 only where c1 = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn is_larger_root_mask(&self) -> __mmask8 {
        self.c1.is_larger_root_mask() | (self.c0.is_larger_root_mask() & self.c1.is_zero_mask())
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn eq_mask(&self, rhs: &Self) -> __mmask8 {
        self.c0.eq_mask(&rhs.c0) & self.c1.eq_mask(&rhs.c1)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn is_zero_mask(&self) -> __mmask8 {
        self.c0.is_zero_mask() & self.c1.is_zero_mask()
    }
}
