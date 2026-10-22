use crate::portable::{constants::ONE, fp::Fp, msm::store::PointStore};

/// Independent prefix-product chains: the core overlaps the products of
/// different chains, which keeps each chain's latency off the critical path.
const CHAINS: usize = 4;

/// Pending affine additions `out = a + b` of points in a `PointStore`, where
/// `NEGATED` on a reference to `a` or `b` negates its point. One inversion
/// serves them all: Montgomery's trick.
#[derive(Default)]
pub struct BatchedAdds {
    a: Vec<u32>,
    b: Vec<u32>,
    out: Vec<u32>,
    dx: Vec<Fp>,
    prefix: Vec<Fp>,
}

impl BatchedAdds {
    pub fn clear(&mut self) {
        self.a.clear();
        self.b.clear();
        self.out.clear();
    }

    pub fn push(&mut self, a: u32, b: u32, out: u32) {
        self.a.push(a);
        self.b.push(b);
        self.out.push(out);
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    /// Writes every sum to its `out`. False, with nothing written, when some
    /// pair has equal x coordinates: its points are equal or opposite, and the
    /// slope would divide by zero.
    #[target_feature(enable = "bmi2,adx")]
    pub fn run(&mut self, store: &mut PointStore) -> bool {
        let n = self.a.len();
        self.dx.resize(n, Fp::ZERO);
        self.prefix.resize(n, Fp::ZERO);
        let mut products = [ONE; CHAINS];
        let mut i = 0;
        while i < n {
            let dx = store.x(self.b[i]).sub(&store.x(self.a[i]));
            if dx.is_zero() {
                return false;
            }
            let k = i % CHAINS;
            products[k] = products[k].mul(&dx);
            self.dx[i] = dx;
            self.prefix[i] = products[k];
            i += 1;
        }
        let mut inverses = batch_inverse(&products);
        while i > 0 {
            i -= 1;
            let k = i % CHAINS;
            let dx_inverse =
                if i < CHAINS { inverses[k] } else { inverses[k].mul(&self.prefix[i - CHAINS]) };
            inverses[k] = inverses[k].mul(&self.dx[i]);
            self.finish(store, i, &dx_inverse);
        }
        true
    }

    /// Writes pair i's sum, from the inverse of its x difference.
    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    fn finish(&self, store: &mut PointStore, i: usize, dx_inverse: &Fp) {
        let (xa, ya) = store.signed(self.a[i]);
        let (xb, yb) = store.signed(self.b[i]);
        let slope = yb.sub(&ya).mul(dx_inverse);
        let x3 = slope.square().sub(&xa).sub(&xb);
        let y3 = slope.mul(&xa.sub(&x3)).sub(&ya);
        store.set(self.out[i], &x3, &y3);
    }
}

/// The inverses of `values` by Montgomery's trick: one inversion and
/// 3·(CHAINS − 1) products. Every value must be nonzero.
#[target_feature(enable = "bmi2,adx")]
fn batch_inverse(values: &[Fp; CHAINS]) -> [Fp; CHAINS] {
    let mut prefix = *values;
    let mut k = 1;
    while k < CHAINS {
        prefix[k] = prefix[k - 1].mul(&values[k]);
        k += 1;
    }
    let mut inverse = prefix[CHAINS - 1].inverse();
    let mut out = [Fp::ZERO; CHAINS];
    k = CHAINS - 1;
    while k > 0 {
        out[k] = inverse.mul(&prefix[k - 1]);
        inverse = inverse.mul(&values[k]);
        k -= 1;
    }
    out[0] = inverse;
    out
}
