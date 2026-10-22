use crate::bls::limbs::{LANES, Limbs};

/// A doubling per bit of |z| below the top one, 63, and an addition per
/// lower set bit, 5.
pub const LINE_COUNT: usize = 68;

/// The Miller loop's lines for two G2 points, a step per doubling or
/// addition in the loop's order. Lanes 0 to 3 hold l1.c0, l1.c1, l2.c0 and
/// l2.c1 for the first point, lanes 4 to 7 for the second, in Fp8's
/// Montgomery form, below p. At P = (x, y) a step's line is
/// (1, l1·x, 0) + (0, l2·y, 0)·w: the spec's line, times a factor in Fp4
/// that the final exponentiation removes.
pub struct MillerLines(pub [[Limbs; LANES]; LINE_COUNT]);
