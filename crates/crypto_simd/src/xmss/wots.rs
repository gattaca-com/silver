//! WOTS+ C one-time keys (spec §3): `CHAINS` chains of 4 positions, signing a
//! 16-byte digest that is a codeword.

use crate::xmss::{
    CHAIN, CHAINS, Digest, LEAF, MSG, PRF, RND, Secret, address, h, hi,
    lanes::{LANES, absorb, digest, pad, permutation_lanes},
    th,
};

const TARGET_SUM: u32 = 106;
pub(super) const LAST_POSITION: u8 = 3;

/// Digits of `digest`, two bits each little endian, when they form a codeword:
/// digits past `CHAINS` zero and the rest summing to `TARGET_SUM`.
pub(super) fn codeword(digest: &Digest) -> Option<[u8; CHAINS]> {
    const LOW_BITS: u128 = u128::MAX / 3;
    let d = u128::from_le_bytes(*digest);
    let sum = (d & LOW_BITS).count_ones() + 2 * (d & !LOW_BITS).count_ones();
    let is_codeword = d >> (2 * CHAINS) == 0 && sum == TARGET_SUM;
    is_codeword.then(|| std::array::from_fn(|i| ((d >> (2 * i)) & 3) as u8))
}

/// One hash of the secret seeds two chains: `2j` and `2j + 1` are its halves.
fn chain_starts(secret: &Secret, layer: u32, e: u32) -> [Digest; CHAINS] {
    let mut starts = [[0u8; 16]; CHAINS];
    for (j, pair) in starts.chunks_exact_mut(2).enumerate() {
        let hash = h(&secret.p, &address(PRF, 0, hi(layer, j as u32), e), &secret.s);
        pair[0].copy_from_slice(&hash[..16]);
        pair[1].copy_from_slice(&hash[16..]);
    }
    starts
}

/// Chain `i` of key `e` from position `from` to `to`. A step's address names
/// the position it leaves; the chain index follows the value.
fn walk(p: &Digest, layer: u32, e: u32, i: usize, from: u8, to: u8, mut value: Digest) -> Digest {
    for mu in from..to {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&value);
        m[16..].copy_from_slice(&(i as u128).to_le_bytes());
        value = th(p, &address(CHAIN, mu, hi(layer, 0), e), &m);
    }
    value
}

fn leaf_hash(p: &Digest, layer: u32, e: u32, ends: &[Digest; CHAINS]) -> Digest {
    th(p, &address(LEAF, 0, hi(layer, 0), e), ends.as_flattened())
}

/// `Th(P, A_msg, M ∥ ρ)`: the digest key `e` signs.
fn message_digest(p: &Digest, layer: u32, e: u32, m: &[u8], randomizer: &Digest) -> Digest {
    debug_assert!(m.len() <= 32);
    let mut input = [0u8; 48];
    input[..m.len()].copy_from_slice(m);
    input[m.len()..m.len() + 16].copy_from_slice(randomizer);
    th(p, &address(MSG, 0, hi(layer, 0), e), &input[..m.len() + 16])
}

/// Reference for `ots_lanes::ots_leaves`.
#[cfg(test)]
pub(super) fn ots_leaf(secret: &Secret, layer: u32, e: u32) -> Digest {
    let starts = chain_starts(secret, layer, e);
    let ends = std::array::from_fn(|i| walk(&secret.p, layer, e, i, 0, LAST_POSITION, starts[i]));
    leaf_hash(&secret.p, layer, e, &ends)
}

/// `Ots.sign`: the least randomizer `R_0 + c` whose digest is a codeword, and
/// the chain value each digit opens. Deterministic, so a key never opens two
/// codewords.
pub(super) fn ots_sign(
    secret: &Secret,
    layer: u32,
    e: u32,
    m: &[u8],
) -> Option<(Digest, [Digest; CHAINS])> {
    debug_assert!(m.len() <= 32);
    let mut seed_and_m = [0u8; 64];
    seed_and_m[..32].copy_from_slice(&secret.s);
    seed_and_m[32..32 + m.len()].copy_from_slice(m);
    let r0 = th(&secret.p, &address(RND, 0, hi(layer, 0), e), &seed_and_m[..32 + m.len()]);
    let base = u128::from_le_bytes(r0);

    // Template `P ∥ A_msg ∥ M ∥ 0^128` padded, the same on every lane; a trial XORs
    // its randomizer into the two words after `M`.
    let mut template = [[0u64; LANES]; 25];
    for l in 0..LANES {
        absorb(&mut template, l, 0, &secret.p);
        absorb(&mut template, l, 2, &address(MSG, 0, hi(layer, 0), e));
        absorb(&mut template, l, 4, m);
    }
    pad(&mut template, 32 + m.len() + 16);
    let at = 4 + m.len() / 8;

    for first in (0..1u64 << 32).step_by(LANES) {
        let mut lanes = template;
        let (low, high) = lanes[at..].split_at_mut(1);
        for (l, (low, high)) in low[0].iter_mut().zip(high[0].iter_mut()).enumerate() {
            let randomizer = base.wrapping_add((first + l as u64) as u128);
            *low ^= randomizer as u64;
            *high ^= (randomizer >> 64) as u64;
        }
        permutation_lanes(&mut lanes);
        for l in 0..LANES {
            let Some(x) = codeword(&digest(&lanes, l, 0)) else {
                continue;
            };
            let randomizer = base.wrapping_add((first + l as u64) as u128).to_le_bytes();
            debug_assert_eq!(
                message_digest(&secret.p, layer, e, m, &randomizer),
                digest(&lanes, l, 0)
            );
            let starts = chain_starts(secret, layer, e);
            let values = std::array::from_fn(|i| walk(&secret.p, layer, e, i, 0, x[i], starts[i]));
            return Some((randomizer, values));
        }
    }
    None
}

/// `Ots.leaf`: the leaf a signature of `m` by key `e` recovers, or `None` when
/// its digest is not a codeword.
pub(super) fn ots_recover(
    p: &Digest,
    layer: u32,
    e: u32,
    m: &[u8],
    randomizer: &Digest,
    values: &[Digest; CHAINS],
) -> Option<Digest> {
    let x = codeword(&message_digest(p, layer, e, m, randomizer))?;
    let ends = std::array::from_fn(|i| walk(p, layer, e, i, x[i], LAST_POSITION, values[i]));
    Some(leaf_hash(p, layer, e, &ends))
}

#[cfg(test)]
mod tests {
    use super::{CHAINS, TARGET_SUM, codeword};

    #[test]
    fn codeword_digits() {
        // 53 digits of 2 sum to 106; the rest zero.
        let d: u128 = (0..53).fold(0, |d, i| d | 2 << (2 * i));
        let x = codeword(&d.to_le_bytes()).unwrap();
        assert_eq!(x[..53], [2; 53]);
        assert_eq!(x[53..], [0; CHAINS - 53]);
        assert_eq!(x.iter().map(|&x| x as u32).sum::<u32>(), TARGET_SUM);

        assert!(codeword(&(d | 1).to_le_bytes()).is_none(), "sum 107");
        assert!(codeword(&(d >> 2 | 1 << (2 * CHAINS)).to_le_bytes()).is_none(), "digit past v");
        assert!(codeword(&u128::MAX.to_le_bytes()).is_none());
    }
}
