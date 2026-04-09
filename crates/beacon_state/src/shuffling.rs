use ring::digest;

use crate::types::{B256, EPOCHS_PER_HISTORICAL_VECTOR, Epoch, EpochData, SLOTS_PER_EPOCH};

const SHUFFLE_ROUND_COUNT: u8 = 90;

pub const DOMAIN_BEACON_PROPOSER: u32 = 0;
pub const DOMAIN_BEACON_ATTESTER: u32 = 1;
pub const DOMAIN_RANDAO: u32 = 2;
pub const DOMAIN_SYNC_COMMITTEE: u32 = 7;

const TARGET_COMMITTEE_SIZE: usize = 128;
const MAX_COMMITTEES_PER_SLOT: usize = 64;
const MIN_SEED_LOOKAHEAD: u64 = 1;

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// seed = SHA256(domain_bytes || epoch_bytes || randao_mix)
pub fn get_seed(epoch: &EpochData, e: Epoch, domain: u32) -> B256 {
    let mix_epoch = e + EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD - 1;
    let mix_idx = mix_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR;
    let mix = &epoch.randao_mixes[mix_idx];

    let mut preimage = [0u8; 4 + 8 + 32];
    preimage[0..4].copy_from_slice(&domain.to_le_bytes());
    preimage[4..12].copy_from_slice(&e.to_le_bytes());
    preimage[12..44].copy_from_slice(mix);

    sha256(&preimage)
}

/// Shuffle a list of indices in place using the swap-or-not algorithm.
/// Backwards iteration (rounds 89→0) to match the spec's committee
/// derivation: `result[i] = original[compute_shuffled_index(i)]`.
pub fn shuffle_list(indices: &mut [u32], seed: &B256) {
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

pub fn committees_per_slot(active_validator_count: usize) -> usize {
    let per_slot = active_validator_count / SLOTS_PER_EPOCH as usize / TARGET_COMMITTEE_SIZE;
    per_slot.clamp(1, MAX_COMMITTEES_PER_SLOT)
}

pub fn get_beacon_committee(
    shuffled: &[u32],
    slot: u64,
    committee_index: usize,
    committees_per_slot: usize,
) -> &[u32] {
    let epoch_committee_count = committees_per_slot * SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = (slot % SLOTS_PER_EPOCH) as usize;
    let index_in_epoch = slot_in_epoch * committees_per_slot + committee_index;

    let start = shuffled.len() * index_in_epoch / epoch_committee_count;
    let end = shuffled.len() * (index_in_epoch + 1) / epoch_committee_count;

    &shuffled[start..end]
}

pub fn compute_proposer_index(
    epoch_data: &EpochData,
    active_indices: &[u32],
    slot: u64,
    seed: &B256,
) -> usize {
    if active_indices.is_empty() {
        return 0;
    }

    // Proposer seed = SHA256(epoch_seed || slot_bytes).
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed);
    input[32..40].copy_from_slice(&slot.to_le_bytes());
    let proposer_seed = sha256(&input);

    let mut sampler = WeightedSampler::new(&proposer_seed, active_indices.len());
    loop {
        let (candidate, accepted) = sampler.next(active_indices, &epoch_data.val_effective_balance);
        if accepted {
            return candidate;
        }
    }
}

/// Weighted random sampler shared by proposer and sync committee selection.
/// Shuffles candidate index `i`, draws a 16-bit random value, and accepts
/// with probability proportional to `effective_balance /
/// MAX_EFFECTIVE_BALANCE`.
pub struct WeightedSampler {
    seed: B256,
    pivots: [usize; SHUFFLE_ROUND_COUNT as usize],
    n: usize,
    i: usize,
    cached_hash: [u8; 32],
    cached_hash_block: usize,
}

const MAX_EFFECTIVE_BALANCE: u64 = 2_048_000_000_000;
const MAX_RANDOM_16: u64 = 0xFFFF;

impl WeightedSampler {
    pub fn new(seed: &B256, active_count: usize) -> Self {
        Self {
            seed: *seed,
            pivots: precompute_pivots(seed, active_count),
            n: active_count,
            i: 0,
            cached_hash: [0u8; 32],
            cached_hash_block: usize::MAX,
        }
    }

    pub fn next(&mut self, active_indices: &[u32], effective_balances: &[u64]) -> (usize, bool) {
        let shuffled =
            compute_shuffled_index_with_pivots(self.i % self.n, self.n, &self.seed, &self.pivots);
        let candidate = active_indices[shuffled] as usize;

        let hash_block = self.i / 16;
        if hash_block != self.cached_hash_block {
            let mut buf = [0u8; 40];
            buf[..32].copy_from_slice(&self.seed);
            buf[32..40].copy_from_slice(&hash_block.to_le_bytes());
            self.cached_hash = sha256(&buf);
            self.cached_hash_block = hash_block;
        }
        let offset = (self.i % 16) * 2;
        let random_value =
            u16::from_le_bytes([self.cached_hash[offset], self.cached_hash[offset + 1]]) as u64;

        self.i += 1;

        let accepted =
            effective_balances[candidate] * MAX_RANDOM_16 >= MAX_EFFECTIVE_BALANCE * random_value;
        (candidate, accepted)
    }
}

/// Precompute pivots for all 90 rounds (avoids recomputing in
/// compute_shuffled_index).
fn precompute_pivots(seed: &[u8; 32], list_size: usize) -> [usize; SHUFFLE_ROUND_COUNT as usize] {
    let mut pivots = [0usize; SHUFFLE_ROUND_COUNT as usize];
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    for round in 0..SHUFFLE_ROUND_COUNT {
        input[32] = round;
        let h = sha256(&input);
        pivots[round as usize] =
            u64::from_le_bytes(h[..8].try_into().unwrap()) as usize % list_size;
    }
    pivots
}

fn compute_shuffled_index_with_pivots(
    mut index: usize,
    list_size: usize,
    seed: &[u8; 32],
    pivots: &[usize; SHUFFLE_ROUND_COUNT as usize],
) -> usize {
    let mut hash_input = [0u8; 37];
    hash_input[..32].copy_from_slice(seed);

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

/// Append active validator indices for `epoch` into `out` (does not clear
/// first — caller-controlled). `n` is `ValidatorIdentity.validator_cnt`.
pub fn get_active_validator_indices_into(
    epoch_data: &EpochData,
    n: usize,
    epoch: Epoch,
    out: &mut Vec<u32>,
) {
    out.clear();
    for i in 0..n {
        if epoch_data.val_activation_epoch[i] <= epoch && epoch < epoch_data.val_exit_epoch[i] {
            out.push(i as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_preserves_elements() {
        let seed = [0xAB; 32];
        let mut indices: Vec<u32> = (0..100).collect();
        shuffle_list(&mut indices, &seed);

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

    #[test]
    fn committee_slicing() {
        let shuffled: Vec<u32> = (0..640).collect();
        let cps = 2;

        let c = get_beacon_committee(&shuffled, 0, 0, cps);
        assert_eq!(c.len(), 10);

        let c1 = get_beacon_committee(&shuffled, 0, 1, cps);
        assert_eq!(c1.len(), 10);
        assert_ne!(c[0], c1[0]);

        let c_last = get_beacon_committee(&shuffled, 31, 1, cps);
        assert_eq!(c_last.len(), 10);
    }

    /// Hardcoded test vector: compute_shuffled_index(i, 10, [0;32]) for
    /// i=0..10. This can be cross-checked against any spec-compliant
    /// implementation.
    #[test]
    fn hardcoded_shuffle_vector() {
        let seed = [0u8; 32];
        let expected: &[u32] = &[9, 7, 4, 1, 8, 0, 5, 6, 3, 2];
        let n = expected.len();

        // Verify compute_shuffled_index produces the expected mapping.
        let pivots = precompute_pivots(&seed, n);
        for i in 0..n {
            let s = compute_shuffled_index_with_pivots(i, n, &seed, &pivots);
            assert_eq!(s, expected[i] as usize, "compute_shuffled_index({i})");
        }

        // Verify backwards shuffle_list matches: result[i] = csi(i).
        let mut list: Vec<u32> = (0..n as u32).collect();
        shuffle_list(&mut list, &seed);
        assert_eq!(&list, expected);
    }

    #[test]
    fn shuffled_index_matches_full_shuffle() {
        let seed = [0x99u8; 32];
        let n = 64;

        // Backwards shuffle: result[i] = original[compute_shuffled_index(i)].
        // With identity input, result[i] = compute_shuffled_index(i).
        let mut full: Vec<u32> = (0..n as u32).collect();
        shuffle_list(&mut full, &seed);

        let pivots = precompute_pivots(&seed, n);
        for i in 0..n {
            let shuffled_pos = compute_shuffled_index_with_pivots(i, n, &seed, &pivots);
            assert_eq!(
                full[i], shuffled_pos as u32,
                "backwards shuffle: result[{i}] should be compute_shuffled_index({i})"
            );
        }
    }
}
