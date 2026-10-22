use crate::{
    bls::msm8::{buckets::SignedDigits, pairs::NEGATED},
    portable::{
        g1::G1,
        msm::{pairs::BatchedAdds, store::PointStore},
    },
};

/// The points of each window's signed-digit buckets, as references into a
/// `PointStore`: bucket b of window j, 1 ≤ b ≤ 2^(w−1), is list
/// j·2^(w−1) + b − 1. The lists are Msm8's; the window sums run one window at
/// a time.
#[derive(Default)]
pub struct Buckets {
    window_bits: usize,
    windows: usize,
    refs: Vec<u32>,
    starts: Vec<u32>,
    lens: Vec<u32>,
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
        let window_bits = window_bits(scalars.len());
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

    /// Σ_j `[2^(w·j)]` S_j, from the top window down.
    #[target_feature(enable = "bmi2,adx")]
    pub fn sum(&self, store: &PointStore) -> G1 {
        let mut window = self.windows - 1;
        let mut total = self.window_sum(store, window);
        while window > 0 {
            window -= 1;
            let mut k = 0;
            while k < self.window_bits {
                total = total.double();
                k += 1;
            }
            total = total.add_complete(&self.window_sum(store, window));
        }
        total
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

    /// The sum S_j = Σ_b b·B_(j,b) of `window`: running sums T += B_(j,b),
    /// then S += T, from the top bucket down. Each list's points join T one at
    /// a time, whatever their number.
    #[target_feature(enable = "bmi2,adx")]
    fn window_sum(&self, store: &PointStore, window: usize) -> G1 {
        let mut running = G1::INFINITY;
        let mut sum = G1::INFINITY;
        let mut bucket = 1 << (self.window_bits - 1);
        while bucket > 0 {
            let list = self.list(window, bucket);
            let start = self.starts[list] as usize;
            let mut at = 0;
            while at < self.lens[list] as usize {
                let (x, y) = store.signed(self.refs[start + at]);
                running = running.add_affine_complete(&x, &y);
                at += 1;
            }
            sum = sum.add_complete(&running);
            bucket -= 1;
        }
        sum
    }
}

/// The window width for `points` scalars, trading windows for buckets.
fn window_bits(points: usize) -> usize {
    if points < 128 {
        4
    } else if points < 1024 {
        6
    } else {
        8
    }
}

/// Where the sum of a pair with first point `first` goes.
fn sum_slot(first: u32, store: &mut PointStore, originals: usize) -> u32 {
    let index = first & !NEGATED;
    if (index as usize) < originals { store.allocate() } else { index }
}
