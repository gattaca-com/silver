//! The loose doubling of `G1x8` and the offsets the lazy formulas of `g1x8.rs`
//! subtract with. Ranges are those of `fp8_lazy`; each product's operands are
//! commented with their bounds.

use crate::bls::{
    fp8::Fp8,
    fp8_lazy::{EIGHT_P, FOUR_P, TWO_P},
    g1x8::G1x8,
};

/// The multiples of p the lazy differences are offset by.
pub struct Offsets {
    pub two_p: Fp8,
    pub four_p: Fp8,
    pub eight_p: Fp8,
}

impl Offsets {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn new() -> Self {
        Self {
            two_p: Fp8::splat_limbs(&TWO_P),
            four_p: Fp8::splat_limbs(&FOUR_P),
            eight_p: Fp8::splat_limbs(&EIGHT_P),
        }
    }

    /// Raw `v` below 4p, normalised below 2p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn below_2p_from_4p(&self, v: &Fp8) -> Fp8 {
        v.normalise().cond_sub(&self.two_p)
    }

    /// Raw `v` below 8p, normalised below 2p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn below_2p_from_8p(&self, v: &Fp8) -> Fp8 {
        v.normalise().cond_sub(&self.four_p).cond_sub(&self.two_p)
    }

    /// `2p − v` for `v` in (0, 2p), normalised: the negation of a nonzero
    /// value. No curve point has y = 0, as the group order is odd.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn neg(&self, v: &Fp8) -> Fp8 {
        self.two_p.sub_raw(v, &Fp8::zero()).normalise()
    }
}

impl G1x8 {
    /// dbl-2009-l for a chain of doublings: takes and gives x, y below 8p and
    /// z below 4p, normalised, with no zero test; a lane with y = 0 or z = 0
    /// gets z = 0 for the rest of the chain, which `tighten`'s caller tests.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn double_loose(&self, c: &Offsets) -> Self {
        let a = self.x.square(); // 64p²
        let b = self.y.square(); // 64p²
        let cc = b.square();
        let xb = self.x.add_raw(&b).normalise(); // < 10p
        let d = c.below_2p_from_8p(&xb.square().sub_raw(&a, &c.two_p).sub_raw(&cc, &c.two_p)); // 100p²
        let d = c.below_2p_from_4p(&d.add_raw(&d));
        let e = a.add_raw(&a).add_raw(&a).normalise(); // < 6p
        let f = e.square(); // 36p²
        let x3 = f.sub_raw(&d.add_raw(&d), &c.four_p).normalise(); // (0, 6p)
        let dx = d.sub_raw(&x3, &c.eight_p).normalise(); // < 10p
        let c8 = c.below_2p_from_8p(&cc.add_raw(&cc).add_raw(&cc).add_raw(&cc));
        let y3 = e.mul(&dx).sub_raw(&c8.add_raw(&c8), &c.four_p).normalise(); // 6p · 10p; (0, 6p)
        let yz = self.y.mul(&self.z); // 8p · 4p
        let z3 = yz.add_raw(&yz).normalise(); // < 4p
        Self { x: x3, y: y3, z: z3 }
    }

    /// From `double_loose`'s ranges back below 2p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn tighten(&self, c: &Offsets) -> Self {
        Self {
            x: self.x.cond_sub(&c.four_p).cond_sub(&c.two_p),
            y: self.y.cond_sub(&c.four_p).cond_sub(&c.two_p),
            z: self.z.cond_sub(&c.two_p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{
        constants::P,
        g1x8_test_util::{below, plain, splat_value},
        simd_available,
    };

    #[test]
    fn double_loose_matches_the_reference_at_its_input_bounds() {
        if !simd_available() {
            return;
        }
        let p_minus_one = below(P);
        let (four_p, eight_p) = (below(FOUR_P), below(EIGHT_P));
        // SAFETY: checked above.
        unsafe {
            let c = Offsets::new();
            let point = |x, y, z| G1x8 { x: splat_value(x), y: splat_value(y), z: splat_value(z) };
            let reference = point(p_minus_one, p_minus_one, p_minus_one);
            let mut loose = point(eight_p, eight_p, four_p);
            let mut tight = reference.double_reference().0;
            loose = loose.double_loose(&c);
            assert!(plain(&tight) == plain(&loose.tighten(&c)), "double_loose");
            for _ in 0..4 {
                loose = loose.double_loose(&c);
                tight = tight.double_reference().0;
            }
            assert!(plain(&tight) == plain(&loose.tighten(&c)), "double_loose chain");
        }
    }
}
