use crate::kzg::msm8::{pairs::BatchedAdds, store::PointStore};

/// Set on a reference to the negation of the point it names.
pub const NEGATED: u32 = 1 << 31;

/// The points of each window's signed-digit buckets, as references into a
/// `PointStore`. Window j, bucket b (1 ≤ b ≤ 2^(w−1)) is list
/// j·2^(w−1) + b − 1.
pub struct Buckets {
    window_bits: usize,
    windows: usize,
    refs: Vec<u32>,
    starts: Vec<u32>,
    lens: Vec<u32>,
}

impl Buckets {
    pub fn new() -> Self {
        Self { window_bits: 0, windows: 0, refs: Vec::new(), starts: Vec::new(), lens: Vec::new() }
    }

    pub fn windows_for(window_bits: usize, scalar_bits: usize) -> usize {
        scalar_bits.div_ceil(window_bits) + usize::from(scalar_bits % window_bits == 0)
    }

    pub fn windows(&self) -> usize {
        self.windows
    }

    pub fn buckets_per_window(&self) -> usize {
        1 << (self.window_bits - 1)
    }

    /// Sorts point i into the bucket of each window's signed digit of
    /// `scalars[i]`, which is below 2^scalar_bits, by counting.
    pub fn fill(&mut self, scalars: &[[u8; 32]], window_bits: usize, scalar_bits: usize) {
        self.window_bits = window_bits;
        self.windows = Self::windows_for(window_bits, scalar_bits);
        let lists = self.windows * self.buckets_per_window();
        self.lens.clear();
        self.lens.resize(lists, 0);
        for scalar in scalars {
            SignedDigits::new(scalar, window_bits, self.windows).for_each(|window, digit, _| {
                self.lens[window * (1 << (window_bits - 1)) + digit - 1] += 1;
            });
        }

        self.starts.clear();
        let mut total = 0;
        for len in &mut self.lens {
            self.starts.push(total);
            total += *len;
            *len = 0;
        }
        self.refs.clear();
        self.refs.resize(total as usize, 0);
        for (i, scalar) in scalars.iter().enumerate() {
            SignedDigits::new(scalar, window_bits, self.windows).for_each(
                |window, digit, negated| {
                    let list = window * (1 << (window_bits - 1)) + digit - 1;
                    let at = (self.starts[list] + self.lens[list]) as usize;
                    self.refs[at] = i as u32 | if negated { NEGATED } else { 0 };
                    self.lens[list] += 1;
                },
            );
        }
    }

    /// The single point left in bucket `bucket` of `window`, if any.
    pub fn first(&self, window: usize, bucket: usize) -> Option<u32> {
        let list = window * self.buckets_per_window() + bucket - 1;
        (self.lens[list] > 0).then(|| self.refs[self.starts[list] as usize])
    }

    /// Queues the sum of each pair of consecutive points of every list, and
    /// replaces the pair by the sum; an odd last point stays. A sum overwrites
    /// its first point when that is a sum itself, as nothing else names it, and
    /// takes a new slot of `store` when it is one of the first `originals`
    /// points, which every window names.
    pub fn queue_round(
        &mut self,
        adds: &mut BatchedAdds,
        store: &mut PointStore,
        originals: usize,
    ) {
        for list in 0..self.lens.len() {
            let start = self.starts[list] as usize;
            let len = self.lens[list] as usize;
            let mut kept = 0;
            let mut at = 0;
            while at + 1 < len {
                let (a, b) = (self.refs[start + at], self.refs[start + at + 1]);
                let first = (a & !NEGATED) as usize;
                let out = if first < originals { store.allocate() } else { first as u32 };
                adds.push(a, b, out);
                self.refs[start + kept] = out;
                kept += 1;
                at += 2;
            }
            if at < len {
                self.refs[start + kept] = self.refs[start + at];
                kept += 1;
            }
            self.lens[list] = kept as u32;
        }
    }
}

/// The signed digits of a scalar: window j holds digit d_j in
/// [−2^(w−1), 2^(w−1)], with Σ d_j·2^(w·j) the scalar.
pub(super) struct SignedDigits<'a> {
    scalar: &'a [u8; 32],
    window_bits: usize,
    windows: usize,
}

impl<'a> SignedDigits<'a> {
    pub(super) fn new(scalar: &'a [u8; 32], window_bits: usize, windows: usize) -> Self {
        assert!(scalar[31] < 0x80, "scalars are below 2^255");
        Self { scalar, window_bits, windows }
    }

    /// Calls `f(window, magnitude, negated)` for every nonzero digit.
    pub(super) fn for_each(&self, mut f: impl FnMut(usize, usize, bool)) {
        let words: [u64; 4] = std::array::from_fn(|k| {
            u64::from_le_bytes(self.scalar[8 * k..8 * k + 8].try_into().unwrap())
        });
        let half = 1usize << (self.window_bits - 1);
        let mut carry = 0;
        for window in 0..self.windows {
            let value = unsigned_digit(&words, window, self.window_bits) + carry;
            let negated = value > half;
            let magnitude = if negated { (1 << self.window_bits) - value } else { value };
            carry = usize::from(negated);
            if magnitude != 0 {
                f(window, magnitude, negated);
            }
        }
        debug_assert!(carry == 0, "no scalar below 2^255 carries out of the last window");
    }
}

fn unsigned_digit(words: &[u64; 4], window: usize, window_bits: usize) -> usize {
    let bit = window * window_bits;
    if bit >= 4 * 64 {
        return 0;
    }
    let (word, shift) = (bit / 64, bit % 64);
    let mut value = words[word] >> shift;
    if shift + window_bits > 64 && word + 1 < 4 {
        value |= words[word + 1] << (64 - shift);
    }
    (value & ((1 << window_bits) - 1)) as usize
}
