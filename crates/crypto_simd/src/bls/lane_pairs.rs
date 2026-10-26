use crate::bls::{
    constants::{Z_BITS, is_lower_z_bit},
    fp2x8::Fp2x8,
    fp8::Fp8,
    fp12::Fp12,
    g2x8::G2x8,
    limbs::LANES,
    pairing_product::{AffinePair, BLST_LIMBS},
};

pub(super) struct LanePairs {
    t: G2x8,
    qx: Fp2x8,
    qy: Fp2x8,
    minus_two_px: Fp8,
    two_py: Fp8,
    count: usize,
    degenerate: u8,
}

pub(super) struct MillerProduct {
    pub value: Fp12,
    pub degenerate: u8,
}

impl LanePairs {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) fn new(pairs: &[AffinePair]) -> Self {
        assert!(!pairs.is_empty() && pairs.len() <= LANES);
        let mut limbs = [[[0u64; BLST_LIMBS]; LANES]; 6];
        for lane in 0..pairs.len() {
            let pair = &pairs[lane];
            limbs[0][lane] = pair.p.x.l;
            limbs[1][lane] = pair.p.y.l;
            limbs[2][lane] = pair.q.x.fp[0].l;
            limbs[3][lane] = pair.q.x.fp[1].l;
            limbs[4][lane] = pair.q.y.fp[0].l;
            limbs[5][lane] = pair.q.y.fp[1].l;
        }
        let px = Fp8::from_blst_limbs(&limbs[0]);
        let py = Fp8::from_blst_limbs(&limbs[1]);
        let qx = Fp2x8 { c0: Fp8::from_blst_limbs(&limbs[2]), c1: Fp8::from_blst_limbs(&limbs[3]) };
        let qy = Fp2x8 { c0: Fp8::from_blst_limbs(&limbs[4]), c1: Fp8::from_blst_limbs(&limbs[5]) };
        Self {
            t: G2x8 { x: qx, y: qy, z: Fp2x8::one() },
            qx,
            qy,
            minus_two_px: px.add(&px).neg(),
            two_py: py.add(&py),
            count: pairs.len(),
            degenerate: 0,
        }
    }

    fn active_mask(&self) -> u8 {
        u8::MAX >> (LANES - self.count)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) fn miller_loop(mut self) -> MillerProduct {
        let mut value = Fp12::one();
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            if bit < Z_BITS[0] - 1 {
                value = value.square();
            }
            value = self.double().multiply_into(&value, self.count);
            if is_lower_z_bit(bit) {
                value = self.add().multiply_into(&value, self.count);
            }
        }
        MillerProduct { value: value.conjugate(), degenerate: self.degenerate }
    }

    // Formulas follow blst's `line_dbl` (dbl-2009-alnr).
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn double(&mut self) -> Lines {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let a = x.square();
        let b = y.square();
        let zz = z.square();
        let c = b.square();
        let d = x.add(&b).square().sub(&a).sub(&c);
        let d = d.add(&d);
        let e = a.add(&a).add(&a);
        let f = e.square();
        let x3 = f.sub(&d).sub(&d);
        let z3 = y.add(z).square().sub(&b).sub(&zz);
        let c2 = c.add(&c);
        let c4 = c2.add(&c2);
        let y3 = e.mul(&d.sub(&x3)).sub(&c4.add(&c4));
        let b2 = b.add(&b);
        let l0 = e.add(x).square().sub(&a).sub(&f).sub(&b2.add(&b2));
        let l1 = e.mul(&zz);
        let l2 = z3.mul(&zz);
        self.degenerate |= z3.is_zero_mask() & self.active_mask();
        self.t = G2x8 { x: x3, y: y3, z: z3 };
        self.at_p(l0, l1, l2)
    }

    // Formulas follow blst's `line_add` (madd-2007-bl).
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add(&mut self) -> Lines {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let z1z1 = z.square();
        let u2 = self.qx.mul(&z1z1);
        let s2 = self.qy.mul(z).mul(&z1z1);
        let h = u2.sub(x);
        let hh = h.square();
        let i2 = hh.add(&hh);
        let i = i2.add(&i2);
        let j = h.mul(&i);
        let r = s2.sub(y);
        let r = r.add(&r);
        let v = x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v).sub(&v);
        let yj = y.mul(&j);
        let y3 = v.sub(&x3).mul(&r).sub(&yj).sub(&yj);
        let z3 = z.add(&h).square().sub(&z1z1).sub(&hh);
        let l0 = r.mul(&self.qx).sub(&self.qy.mul(&z3));
        let l0 = l0.add(&l0);
        self.degenerate |= z3.is_zero_mask() & self.active_mask();
        self.t = G2x8 { x: x3, y: y3, z: z3 };
        self.at_p(l0, r, z3)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn at_p(&self, l0: Fp2x8, l1: Fp2x8, l2: Fp2x8) -> Lines {
        Lines {
            l0,
            l1: Fp2x8 { c0: l1.c0.mul(&self.minus_two_px), c1: l1.c1.mul(&self.minus_two_px) },
            l2: Fp2x8 { c0: l2.c0.mul(&self.two_py), c1: l2.c1.mul(&self.two_py) },
        }
    }
}

struct Lines {
    l0: Fp2x8,
    l1: Fp2x8,
    l2: Fp2x8,
}

impl Lines {
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn multiply_into(&self, value: &Fp12, count: usize) -> Fp12 {
        let mut value = *value;
        for pair in 0..count {
            let i = pair as i64;
            let line = self
                .l0
                .permute2(&self.l1, &[i, 8 + i, i, i, i, i, i, i])
                .permute2(&self.l2, &[0, 1, 8 + i, 0, 0, 0, 0, 0]);
            value = value.mul_by_line(&line);
        }
        value
    }
}
