use silver_beacon_state_data::{B256, Epoch, RandaoMixesView, SLOTS_PER_EPOCH};
use silver_common::merkle::sha256;

const SHUFFLE_ROUND_COUNT: u8 = 90;

pub const DOMAIN_BEACON_PROPOSER: u32 = 0;
pub const DOMAIN_BEACON_ATTESTER: u32 = 1;
pub const DOMAIN_RANDAO: u32 = 2;
pub const DOMAIN_SYNC_COMMITTEE: u32 = 7;

const TARGET_COMMITTEE_SIZE: usize = 128;
const MAX_COMMITTEES_PER_SLOT: usize = 64;

#[derive(Clone, Copy)]
pub struct Seed(B256);

impl Seed {
    /// `SHA256(domain || epoch || mix)`.
    pub fn new(mix: &B256, e: Epoch, domain: u32) -> Self {
        let mut preimage = [0u8; 4 + 8 + 32];
        preimage[0..4].copy_from_slice(&domain.to_le_bytes());
        preimage[4..12].copy_from_slice(&e.to_le_bytes());
        preimage[12..44].copy_from_slice(mix);

        Self(sha256(&preimage))
    }

    /// [`Self::new`] over the mix the randao column resolves for `e`.
    #[inline]
    pub fn from_randao(randao: &RandaoMixesView, e: Epoch, domain: u32) -> Self {
        Self::new(&randao.seed_mix(e), e, domain)
    }

    /// The per-slot seed the proposer and PTC selections sample against.
    pub fn for_slot(&self, slot: u64) -> Self {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.0);
        input[32..40].copy_from_slice(&slot.to_le_bytes());
        Self(sha256(&input))
    }

    /// Rejection-sampling stream over `active_indices`, weighted by effective
    /// balance.
    #[inline]
    pub fn sampler(&self, active_count: usize) -> WeightedSampler {
        WeightedSampler {
            pivots: self.pivots(active_count),
            n: active_count,
            i: 0,
            draws: self.draws(),
        }
    }

    /// Spec `compute_proposer_index`. `effective_balances[vi]` must be
    /// indexable for every `vi` in `active_indices` (i.e. the materialised
    /// per-validator column).
    pub fn proposer_index(
        &self,
        active_indices: &[u32],
        effective_balances: &[u64],
        slot: u64,
    ) -> usize {
        if active_indices.is_empty() {
            return 0;
        }
        let mut sampler = self.for_slot(slot).sampler(active_indices.len());
        loop {
            let (candidate, accepted) = sampler.next(active_indices, effective_balances);
            if accepted {
                return candidate;
            }
        }
    }

    /// Cursor over this seed's random draws, 16 to a hash.
    #[inline]
    pub fn draws(&self) -> RandomDraws {
        RandomDraws { seed: *self, block: usize::MAX, hash: [0u8; 32] }
    }

    /// Shuffle a list of indices in place using the swap-or-not algorithm.
    /// Backwards iteration (rounds 89→0) to match the spec's committee
    /// derivation: `result[i] = original[compute_shuffled_index(i)]`.
    pub fn shuffle(&self, indices: &mut [u32]) {
        let seed = &self.0;
        let n = indices.len();
        if n <= 1 {
            return;
        }

        let mut buf = [0u8; 37]; // seed(32) + round(1) + position/256(4)
        buf[..32].copy_from_slice(seed);

        for r in 0..SHUFFLE_ROUND_COUNT as usize {
            let round = SHUFFLE_ROUND_COUNT - 1 - r as u8;
            buf[32] = round;

            let pivot_hash = sha256(&buf[..33]);
            let pivot = u64::from_le_bytes(pivot_hash[..8].try_into().unwrap()) as usize % n;

            // First half: pairs (i, pivot - i).
            let mirror1 = (pivot + 1) >> 1;
            buf[33..37].copy_from_slice(&((pivot >> 8) as u32).to_le_bytes());
            let mut source = sha256(&buf);
            let mut byte_v = source[(pivot & 0xff) >> 3];

            for i in 0..mirror1 {
                let j = pivot - i;
                if j & 0xff == 0xff {
                    buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                    source = sha256(&buf);
                }
                if j & 0x07 == 0x07 {
                    byte_v = source[(j & 0xff) >> 3];
                }
                if (byte_v >> (j & 0x07)) & 1 == 1 {
                    indices.swap(i, j);
                }
            }

            // Second half: pairs (i, end - loop_iter).
            let mirror2 = (pivot + n + 1) >> 1;
            let end = n - 1;
            buf[33..37].copy_from_slice(&((end >> 8) as u32).to_le_bytes());
            source = sha256(&buf);
            byte_v = source[(end & 0xff) >> 3];

            for (loop_iter, i) in ((pivot + 1)..mirror2).enumerate() {
                let j = end - loop_iter;
                if j & 0xff == 0xff {
                    buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                    source = sha256(&buf);
                }
                if j & 0x07 == 0x07 {
                    byte_v = source[(j & 0xff) >> 3];
                }
                if (byte_v >> (j & 0x07)) & 1 == 1 {
                    indices.swap(i, j);
                }
            }
        }
    }

    /// Pivots for all 90 rounds up front, so `shuffled_index` doesn't rehash
    /// one per call per index.
    fn pivots(&self, list_size: usize) -> [usize; SHUFFLE_ROUND_COUNT as usize] {
        let mut pivots = [0usize; SHUFFLE_ROUND_COUNT as usize];
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&self.0);
        for round in 0..SHUFFLE_ROUND_COUNT {
            input[32] = round;
            let h = sha256(&input);
            pivots[round as usize] =
                u64::from_le_bytes(h[..8].try_into().unwrap()) as usize % list_size;
        }
        pivots
    }

    fn shuffled_index(
        &self,
        mut index: usize,
        list_size: usize,
        pivots: &[usize; SHUFFLE_ROUND_COUNT as usize],
    ) -> usize {
        let mut hash_input = [0u8; 37];
        hash_input[..32].copy_from_slice(&self.0);

        for round in 0..SHUFFLE_ROUND_COUNT {
            let pivot = pivots[round as usize];
            let flip = (pivot + list_size - index) % list_size;
            let position = core::cmp::max(index, flip);

            hash_input[32] = round;
            hash_input[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
            let source = sha256(&hash_input);

            let byte = source[(position % 256) / 8];
            let bit = (byte >> (position % 8)) & 1;
            if bit == 1 {
                index = flip;
            }
        }
        index
    }
}

#[inline]
pub fn committees_per_slot(active_validator_count: usize) -> usize {
    let per_slot = active_validator_count / SLOTS_PER_EPOCH as usize / TARGET_COMMITTEE_SIZE;
    per_slot.clamp(1, MAX_COMMITTEES_PER_SLOT)
}

/// One seed's 16-bit random draws, which the spec packs 16 to a SHA256 block —
/// so a sequential sweep rehashes only every 16th draw. Holds the block it
/// last hashed; every weighted selection walks `i` upward, so that is the
/// whole cache.
pub struct RandomDraws {
    seed: Seed,
    block: usize,
    hash: B256,
}

impl RandomDraws {
    #[inline]
    pub fn at(&mut self, i: u64) -> u64 {
        let block = i as usize / 16;
        if block != self.block {
            (self.block, self.hash) = (block, self.seed.for_slot(block as u64).0);
        }
        let offset = (i as usize % 16) * 2;
        u16::from_le_bytes([self.hash[offset], self.hash[offset + 1]]) as u64
    }

    /// Accept draw `i` with probability `effective_balance /
    /// MAX_EFFECTIVE_BALANCE` — the spec's balance-weighted rejection rule.
    #[inline]
    pub fn accept(&mut self, i: u64, effective_balance: u64) -> bool {
        effective_balance * MAX_RANDOM_16 >= MAX_EFFECTIVE_BALANCE * self.at(i)
    }
}

/// Weighted random sampler shared by proposer and sync committee selection.
/// Shuffles candidate index `i`, draws a 16-bit random value, and accepts
/// with probability proportional to `effective_balance /
/// MAX_EFFECTIVE_BALANCE`.
pub struct WeightedSampler {
    pivots: [usize; SHUFFLE_ROUND_COUNT as usize],
    n: usize,
    i: usize,
    draws: RandomDraws,
}

pub const MAX_EFFECTIVE_BALANCE: u64 = 2_048_000_000_000;
const MAX_RANDOM_16: u64 = 0xFFFF;

impl WeightedSampler {
    pub fn next(&mut self, active_indices: &[u32], effective_balances: &[u64]) -> (usize, bool) {
        let shuffled = self.draws.seed.shuffled_index(self.i % self.n, self.n, &self.pivots);
        let candidate = active_indices[shuffled] as usize;
        let accepted = self.draws.accept(self.i as u64, effective_balances[candidate]);

        self.i += 1;
        (candidate, accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_preserves_elements() {
        let seed = Seed([0xAB; 32]);
        let mut indices: Vec<u32> = (0..100).collect();
        seed.shuffle(&mut indices);

        let mut sorted = indices.clone();
        sorted.sort();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn committees_per_slot_bounds() {
        assert_eq!(committees_per_slot(100), 1);
        assert_eq!(committees_per_slot(1_000_000), 64);
        assert_eq!(committees_per_slot(8192), 2);
    }

    /// Hardcoded test vector: compute_shuffled_index(i, 10, [0;32]) for
    /// i=0..10. This can be cross-checked against any spec-compliant
    /// implementation.
    #[test]
    fn hardcoded_shuffle_vector() {
        let seed = Seed([0u8; 32]);
        let expected: &[u32] = &[9, 7, 4, 1, 8, 0, 5, 6, 3, 2];
        let n = expected.len();

        // Verify shuffled_index produces the expected mapping.
        let pivots = seed.pivots(n);
        for i in 0..n {
            let s = seed.shuffled_index(i, n, &pivots);
            assert_eq!(s, expected[i] as usize, "shuffled_index({i})");
        }

        // Verify the backwards shuffle matches: result[i] = csi(i).
        let mut list: Vec<u32> = (0..n as u32).collect();
        seed.shuffle(&mut list);
        assert_eq!(&list, expected);
    }

    #[test]
    fn shuffled_index_matches_full_shuffle() {
        let seed = Seed([0x99u8; 32]);
        let n = 64;

        // Backwards shuffle: result[i] = original[shuffled_index(i)].
        // With identity input, result[i] = shuffled_index(i).
        let mut full: Vec<u32> = (0..n as u32).collect();
        seed.shuffle(&mut full);

        let pivots = seed.pivots(n);
        for i in 0..n {
            let shuffled_pos = seed.shuffled_index(i, n, &pivots);
            assert_eq!(
                full[i], shuffled_pos as u32,
                "backwards shuffle: result[{i}] should be compute_shuffled_index({i})"
            );
        }
    }
}
