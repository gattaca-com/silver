/// Below the spec's 2048: with 64 committees a slot, a committee holds
/// `active validators / 2048` members, so this covers ~2.1M active
/// validators, over twice mainnet's.
pub(super) const MAX_COMMITTEE_MEMBERS: usize = 1024;
const WORDS: usize = MAX_COMMITTEE_MEMBERS / 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct CommitteeBits([u64; WORDS]);

impl CommitteeBits {
    pub(super) const EMPTY: Self = Self([0; WORDS]);

    /// `participants` holds the first `committee_len` bits of a bitlist.
    pub(super) fn from_participants(participants: &[u8], committee_len: usize) -> Self {
        debug_assert!(committee_len <= MAX_COMMITTEE_MEMBERS);
        let mut bits = Self::EMPTY;
        for member in 0..committee_len {
            if participants[member / 8] & (1 << (member % 8)) != 0 {
                bits.insert(member);
            }
        }
        bits
    }

    pub(super) fn nonzero(weights: &[u64]) -> Self {
        let mut bits = Self::EMPTY;
        for (word, chunk) in bits.0.iter_mut().zip(weights.chunks(64)) {
            for (bit, &weight) in chunk.iter().enumerate() {
                *word |= ((weight != 0) as u64) << bit;
            }
        }
        bits
    }

    pub(super) fn insert(&mut self, member: usize) {
        self.0[member / 64] |= 1 << (member % 64);
    }

    pub(super) fn contains(&self, member: usize) -> bool {
        self.0[member / 64] & 1 << (member % 64) != 0
    }

    pub(super) fn count(&self) -> u32 {
        self.0.iter().map(|word| word.count_ones()).sum()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.iter().all(|&word| word == 0)
    }

    pub(super) fn intersects(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).any(|(a, b)| a & b != 0)
    }

    pub(super) fn is_subset(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).all(|(a, b)| a & !b == 0)
    }

    pub(super) fn union_with(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }

    pub(super) fn difference(&self, other: &Self) -> Self {
        Self(std::array::from_fn(|at| self.0[at] & !other.0[at]))
    }

    pub(super) fn members(&self) -> impl Iterator<Item = usize> + '_ {
        word_positions(self.0.iter().copied())
    }

    pub(super) fn weight_outside(&self, covered: &Self, weights: &[u64]) -> u64 {
        let words = self.0.iter().zip(&covered.0).map(|(a, c)| a & !c);
        word_positions(words).map(|member| weights[member]).sum()
    }

    /// ORs the bits into `bits` from bit `offset`.
    pub(super) fn write_bits_at(&self, bits: &mut [u8], offset: usize) {
        for member in self.members() {
            let bit = offset + member;
            bits[bit / 8] |= 1 << (bit % 8);
        }
    }
}

fn word_positions(words: impl Iterator<Item = u64>) -> impl Iterator<Item = usize> {
    words.enumerate().flat_map(|(at, word)| bit_positions(word).map(move |bit| at * 64 + bit))
}

pub(super) fn bit_positions(word: u64) -> impl Iterator<Item = usize> + Clone {
    let mut rest = word;
    std::iter::from_fn(move || {
        (rest != 0).then(|| {
            let bit = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            bit
        })
    })
}
