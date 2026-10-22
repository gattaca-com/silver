/// A scalar's signed digits, window by window from the least significant:
/// digit d_j is in [−2^(w−1), 2^(w−1)], and Σ_j d_j·2^(w·j) is the scalar
/// once the windows reach past its top bit.
pub(crate) struct SignedDigits {
    words: [u64; 4],
    window_bits: usize,
    bit: usize,
    carry: u64,
}

impl SignedDigits {
    pub(crate) fn new(scalar: &[u64; 4], window_bits: usize) -> Self {
        Self { words: *scalar, window_bits, bit: 0, carry: 0 }
    }

    /// The next window's digit, as its magnitude and whether it is negative.
    pub(crate) fn next_digit(&mut self) -> (usize, bool) {
        let value = self.unsigned_window() + self.carry;
        let negated = value > 1 << (self.window_bits - 1);
        let magnitude = if negated { (1 << self.window_bits) - value } else { value };
        self.carry = negated as u64;
        self.bit += self.window_bits;
        (magnitude as usize, negated)
    }

    /// The scalar's bits from `bit`, `window_bits` of them, zero past the
    /// top.
    fn unsigned_window(&self) -> u64 {
        let word = self.bit / 64;
        let high = if word + 1 < 4 { self.words[word + 1] } else { 0 };
        let pair = self.words[word] as u128 | (high as u128) << 64;
        (pair >> (self.bit % 64)) as u64 & ((1 << self.window_bits) - 1)
    }
}
