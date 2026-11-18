//! WOTS+ C over `LANES` one-time keys at once: lane `l` is key `e[l]` under
//! parameter `p[l]`. Values are chain-major, `values[i][l]` chain `i` of lane
//! `l`.

use crate::xmss::{
    CHAIN, CHAINS, Digest, LEAF, LEAF_INPUT, PRF, Secret, address, address_word, hi,
    lanes::{LANES, RATE_WORDS, absorb, digest, pad, permutation_lanes},
    wots::LAST_POSITION,
};

/// `P` of every lane as two words.
pub(super) type PWords = [[u64; LANES]; 2];

pub(super) fn p_words(p: &[Digest; LANES]) -> PWords {
    let word = |l: usize, at: usize| u64::from_le_bytes(p[l][at..at + 8].try_into().unwrap());
    [std::array::from_fn(|l| word(l, 0)), std::array::from_fn(|l| word(l, 8))]
}

/// Step `mu` of chain `i` on every lane; lanes with `take` keep the result. The
/// block is `P ∥ A_chain ∥ value ∥ LE128(i)`, written as words, padded.
pub(super) fn chain_step(
    p: &PWords,
    layer: u32,
    e: &[u32; LANES],
    i: usize,
    mu: u8,
    values: &mut [Digest; LANES],
    take: &[bool; LANES],
) {
    let mut lanes = [[0u64; LANES]; 25];
    lanes[0] = p[0];
    lanes[1] = p[1];
    lanes[2] = std::array::from_fn(|l| address_word(CHAIN, mu, hi(layer, 0), e[l]));
    for (l, value) in values.iter().enumerate() {
        lanes[4][l] = u64::from_le_bytes(value[..8].try_into().unwrap());
        lanes[5][l] = u64::from_le_bytes(value[8..].try_into().unwrap());
    }
    lanes[6] = [i as u64; LANES];
    lanes[8] = [0x01; LANES];
    lanes[RATE_WORDS - 1] = [0x80 << 56; LANES];
    permutation_lanes(&mut lanes);
    for (l, value) in values.iter_mut().enumerate() {
        if take[l] {
            *value = digest(&lanes, l, 0);
        }
    }
}

/// `Th(P, A_leaf, ends)` per lane: 7 full blocks and a tail.
pub(super) fn leaf_hashes(
    p: &[Digest; LANES],
    layer: u32,
    e: &[u32; LANES],
    ends: &[[Digest; LANES]; CHAINS],
) -> [Digest; LANES] {
    let mut inputs = [[0u8; LEAF_INPUT]; LANES];
    for (l, input) in inputs.iter_mut().enumerate() {
        input[..16].copy_from_slice(&p[l]);
        input[16..32].copy_from_slice(&address(LEAF, 0, hi(layer, 0), e[l]));
        for (i, end) in ends.iter().enumerate() {
            input[32 + 16 * i..48 + 16 * i].copy_from_slice(&end[l]);
        }
    }

    let mut lanes = [[0u64; LANES]; 25];
    let full_blocks = LEAF_INPUT / (RATE_WORDS * 8);
    for block in 0..full_blocks {
        for (l, input) in inputs.iter().enumerate() {
            absorb(&mut lanes, l, 0, &input[block * 136..(block + 1) * 136]);
        }
        permutation_lanes(&mut lanes);
    }
    for (l, input) in inputs.iter().enumerate() {
        absorb(&mut lanes, l, 0, &input[full_blocks * 136..]);
    }
    pad(&mut lanes, LEAF_INPUT % 136);
    permutation_lanes(&mut lanes);
    std::array::from_fn(|l| digest(&lanes, l, 0))
}

/// Chain starts of keys `e`: one hash of the seed per pair of chains.
fn chain_starts(secret: &Secret, layer: u32, e: &[u32; LANES]) -> [[Digest; LANES]; CHAINS] {
    let mut starts = [[[0u8; 16]; LANES]; CHAINS];
    for j in 0..CHAINS / 2 {
        let mut lanes = [[0u64; LANES]; 25];
        for (l, &e) in e.iter().enumerate() {
            absorb(&mut lanes, l, 0, &secret.p);
            absorb(&mut lanes, l, 2, &address(PRF, 0, hi(layer, j as u32), e));
            absorb(&mut lanes, l, 4, &secret.s);
        }
        pad(&mut lanes, 64);
        permutation_lanes(&mut lanes);
        let [even, odd] = &mut starts[2 * j..2 * j + 2] else { unreachable!() };
        for (l, (even, odd)) in even.iter_mut().zip(odd.iter_mut()).enumerate() {
            *even = digest(&lanes, l, 0);
            *odd = digest(&lanes, l, 2);
        }
    }
    starts
}

/// Leaves of keys `e`: every chain walked to its end.
pub(super) fn ots_leaves(secret: &Secret, layer: u32, e: &[u32; LANES]) -> [Digest; LANES] {
    let p = [secret.p; LANES];
    let words = p_words(&p);
    let mut values = chain_starts(secret, layer, e);
    for (i, value) in values.iter_mut().enumerate() {
        for mu in 0..LAST_POSITION {
            chain_step(&words, layer, e, i, mu, value, &[true; LANES]);
        }
    }
    leaf_hashes(&p, layer, e, &values)
}

#[cfg(test)]
mod tests {
    use super::{LANES, ots_leaves};
    use crate::xmss::{Secret, wots::ots_leaf};

    #[test]
    fn leaves_match_scalar() {
        let secret = Secret::new(&[3; 32]);
        for layer in 0..2 {
            let e: [u32; LANES] = std::array::from_fn(|l| 1000 + 7 * l as u32);
            let leaves = ots_leaves(&secret, layer, &e);
            for l in 0..LANES {
                assert_eq!(leaves[l], ots_leaf(&secret, layer, e[l]), "layer {layer} lane {l}");
            }
        }
    }
}
