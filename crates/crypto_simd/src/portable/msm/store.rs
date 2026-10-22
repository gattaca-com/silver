use blst::blst_p1_affine;

use crate::portable::{constants::BETA, fp::Fp};

/// Set on a reference to the negation of the point it names.
pub const NEGATED: u32 = 1 << 31;

/// Affine points by index, in blst's Montgomery form.
#[derive(Default)]
pub struct PointStore {
    points: Vec<[Fp; 2]>,
    len: usize,
}

impl PointStore {
    /// Empties the store and makes room for `capacity` points, keeping what it
    /// has allocated.
    pub fn reset(&mut self, capacity: usize) {
        if self.points.len() < capacity {
            self.points.resize(capacity, [Fp::ZERO; 2]);
        }
        self.len = 0;
    }

    /// The index of a new point, for `set` to write.
    pub fn allocate(&mut self) -> u32 {
        assert!(self.len < self.points.len(), "the store holds every point");
        self.len += 1;
        (self.len - 1) as u32
    }

    /// Appends the points: σ(P) = (β·x, y) instead of P when `endomorphism`,
    /// and the negation of point k where `negated[k]`. The points must be
    /// finite.
    pub fn push_blst(&mut self, points: &[blst_p1_affine], negated: &[bool], endomorphism: bool) {
        assert!(negated.len() == points.len(), "one sign per point");
        assert!(self.len + points.len() <= self.points.len(), "the store holds the points");
        let mut k = 0;
        while k < points.len() {
            let x = Fp(points[k].x.l);
            let y = Fp(points[k].y.l);
            self.points[self.len] =
                [if endomorphism { x.mul(&BETA) } else { x }, if negated[k] { y.neg() } else { y }];
            self.len += 1;
            k += 1;
        }
    }

    /// The point a reference names, negated when it carries `NEGATED`.
    #[inline(always)]
    pub fn signed(&self, reference: u32) -> (Fp, Fp) {
        let point = &self.points[(reference & !NEGATED) as usize];
        (point[0], if reference & NEGATED != 0 { point[1].neg() } else { point[1] })
    }

    #[inline(always)]
    pub fn x(&self, reference: u32) -> Fp {
        self.points[(reference & !NEGATED) as usize][0]
    }

    #[inline(always)]
    pub fn set(&mut self, index: u32, x: &Fp, y: &Fp) {
        self.points[index as usize] = [*x, *y];
    }
}
