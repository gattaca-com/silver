use std::arch::x86_64::__mmask8;

use crate::bls::{
    fp8::LANES,
    g1x8::G1x8,
    msm8::{
        pairs::{BatchedAdds, NEGATED},
        store::PointStore,
    },
};

/// The points of each window's signed-digit buckets, as references into a
/// `PointStore`: bucket b of window j, 1 ≤ b ≤ 2^(w−1), is list
/// j·2^(w−1) + b − 1.
#[derive(Default)]
pub struct Buckets {
    window_bits: usize,
    windows: usize,
    refs: Vec<u32>,
    starts: Vec<u32>,
    lens: Vec<u32>,
}

/// Entry `at` of one bucket in eight windows' lists.
struct Entries {
    indices: [u32; LANES],
    present: __mmask8,
    negated: __mmask8,
}

impl Buckets {
    pub fn windows(&self) -> usize {
        self.windows
    }

    /// Point i in the bucket of each window's signed digit of `scalars[i]`, by
    /// counting, for scalars below 2^`scalar_bits`. Windows widen with the
    /// number of points, trading windows for buckets; one more window than
    /// whole windows fit `scalar_bits` takes the digits' carry.
    pub fn fill(&mut self, scalars: &[[u64; 4]], scalar_bits: usize) {
        assert!(scalar_bits < 256, "scalars fit four words");
        let window_bits = if scalars.len() < 128 {
            4
        } else if scalars.len() < 1024 {
            6
        } else {
            8
        };
        self.window_bits = window_bits;
        self.windows = scalar_bits / window_bits + 1;
        let lists = self.windows << (window_bits - 1);
        self.lens.clear();
        self.lens.resize(lists, 0);
        let mut i = 0;
        while i < scalars.len() {
            let mut digits = SignedDigits::new(&scalars[i], window_bits);
            let mut window = 0;
            while window < self.windows {
                let (magnitude, _) = digits.next_digit();
                self.count(window, magnitude);
                window += 1;
            }
            i += 1;
        }

        self.starts.clear();
        let mut total = 0;
        let mut list = 0;
        while list < lists {
            self.starts.push(total);
            total += self.lens[list];
            self.lens[list] = 0;
            list += 1;
        }

        self.refs.clear();
        self.refs.resize(total as usize, 0);
        i = 0;
        while i < scalars.len() {
            let mut digits = SignedDigits::new(&scalars[i], window_bits);
            let mut window = 0;
            while window < self.windows {
                let (magnitude, negated) = digits.next_digit();
                let sign = (negated as u32) * NEGATED;
                self.place(window, magnitude, i as u32 | sign);
                window += 1;
            }
            i += 1;
        }
    }

    /// Queues into `adds`, which it clears first, the sum of each pair of
    /// consecutive points of every list, and replaces the pair by the sum; an
    /// odd last point stays. A sum overwrites its first point when that is a
    /// sum itself, as nothing else names it, and takes a new slot of `store`
    /// when it is one of the first `originals` points, which every window
    /// names.
    pub fn queue_round(
        &mut self,
        adds: &mut BatchedAdds,
        store: &mut PointStore,
        originals: usize,
    ) {
        adds.clear();
        let mut list = 0;
        while list < self.lens.len() {
            self.queue_pairs(list, adds, store, originals);
            list += 1;
        }
    }

    /// Σ_j `[2^(w·j)]` S_j in lane 0, the window sums S_j eight windows to
    /// a vector, one per lane, from the top vector down.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn sum(&self, store: &PointStore) -> G1x8 {
        let groups = (self.windows - 1) / LANES + 1;
        let mut group = groups - 1;
        let mut total = self.window_sums(store, group);
        while group > 0 {
            group -= 1;
            let shifted = total.times_two_pow(LANES * self.window_bits);
            total = shifted.add_complete(&self.window_sums(store, group));
        }
        total.sum_lanes_shifted(self.window_bits)
    }

    fn list(&self, window: usize, bucket: usize) -> usize {
        (window << (self.window_bits - 1)) + bucket - 1
    }

    /// Bucket `magnitude` of `window` gains a point; 0 is no bucket.
    fn count(&mut self, window: usize, magnitude: usize) {
        if magnitude != 0 {
            let list = self.list(window, magnitude);
            self.lens[list] += 1;
        }
    }

    /// As `count`, writing `reference` after the list's points so far.
    fn place(&mut self, window: usize, magnitude: usize, reference: u32) {
        if magnitude != 0 {
            let list = self.list(window, magnitude);
            self.refs[(self.starts[list] + self.lens[list]) as usize] = reference;
            self.lens[list] += 1;
        }
    }

    fn queue_pairs(
        &mut self,
        list: usize,
        adds: &mut BatchedAdds,
        store: &mut PointStore,
        originals: usize,
    ) {
        let start = self.starts[list] as usize;
        let len = self.lens[list] as usize;
        let mut at = 0;
        while at + 1 < len {
            let first = self.refs[start + at];
            let out = sum_slot(first, store, originals);
            adds.push(first, self.refs[start + at + 1], out);
            self.refs[start + at / 2] = out;
            at += 2;
        }
        if len % 2 == 1 {
            self.refs[start + len / 2] = self.refs[start + len - 1];
        }
        self.lens[list] = (len / 2 + len % 2) as u32;
    }

    /// The sums S_j = Σ_b b·B_(j,b) of the eight windows from 8·`group`, one
    /// per lane: running sums T += B_(j,b), then S += T, from the top bucket
    /// down. Each list's points join T one at a time, whatever their number.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn window_sums(&self, store: &PointStore, group: usize) -> G1x8 {
        let mut running = G1x8::infinity();
        let mut sum = G1x8::infinity();
        let mut bucket = 1 << (self.window_bits - 1);
        while bucket > 0 {
            let longest = self.longest(group, bucket);
            let mut at = 0;
            while at < longest {
                let entries = self.entries(group, bucket, at);
                let (x, y) = store.load_signed(&entries.indices, entries.negated);
                let joined = running.add_affine_complete(&x, &y);
                running = G1x8::select(entries.present, &running, &joined);
                at += 1;
            }
            sum = sum.add_complete(&running);
            bucket -= 1;
        }
        sum
    }

    /// The longest list of `bucket` among the eight windows from 8·`group`.
    fn longest(&self, group: usize, bucket: usize) -> usize {
        let mut longest = 0;
        let mut lane = 0;
        while lane < LANES {
            let len = self.len(group * LANES + lane, bucket);
            longest = if len > longest { len } else { longest };
            lane += 1;
        }
        longest
    }

    /// Entry `at` of `bucket` in the eight windows from 8·`group`; lanes whose
    /// list is shorter, or whose window is past the last, have none.
    fn entries(&self, group: usize, bucket: usize, at: usize) -> Entries {
        let mut entries = Entries { indices: [0; LANES], present: 0, negated: 0 };
        let mut lane = 0;
        while lane < LANES {
            let window = group * LANES + lane;
            let here = at < self.len(window, bucket);
            let reference = if here {
                self.refs[self.starts[self.list(window, bucket)] as usize + at]
            } else {
                0
            };
            entries.indices[lane] = reference & !NEGATED;
            entries.present |= (here as u8) << lane;
            entries.negated |= ((reference >> 31) as u8) << lane;
            lane += 1;
        }
        entries
    }

    /// The length of `bucket`'s list in `window`, 0 past the last window.
    fn len(&self, window: usize, bucket: usize) -> usize {
        if window < self.windows { self.lens[self.list(window, bucket)] as usize } else { 0 }
    }
}

/// Where the sum of a pair with first point `first` goes.
fn sum_slot(first: u32, store: &mut PointStore, originals: usize) -> u32 {
    let index = first & !NEGATED;
    if (index as usize) < originals { store.allocate() } else { index }
}

/// A scalar's signed digits, window by window from the least significant:
/// digit d_j is in [−2^(w−1), 2^(w−1)], and Σ_j d_j·2^(w·j) is the scalar
/// once the windows reach past its top bit.
struct SignedDigits {
    words: [u64; 4],
    window_bits: usize,
    bit: usize,
    carry: u64,
}

impl SignedDigits {
    fn new(scalar: &[u64; 4], window_bits: usize) -> Self {
        Self { words: *scalar, window_bits, bit: 0, carry: 0 }
    }

    /// The next window's digit, as its magnitude and whether it is negative.
    fn next_digit(&mut self) -> (usize, bool) {
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
