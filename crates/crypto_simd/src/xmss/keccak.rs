//! Keccak-256: FIPS 202 Keccak-f[1600] with the pre-standard 0x01 pad byte.

const RATE: usize = 1088 / 8;

/// FIPS 202 §3.2.5.
pub(super) const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];

    let mut blocks = input.chunks_exact(RATE);
    for block in &mut blocks {
        absorb(&mut state, block);
        permutation(&mut state);
    }

    // pad10*1 behind the 0x01 domain byte; both land in one byte when the tail is
    // RATE - 1 long.
    let tail = blocks.remainder();
    let mut last = [0u8; RATE];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb(&mut state, &last);
    permutation(&mut state);

    let mut out = [0u8; 32];
    for (lane, bytes) in state.iter().zip(out.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn absorb(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), RATE);
    for (lane, bytes) in state.iter_mut().zip(block.chunks_exact(8)) {
        *lane ^= u64::from_le_bytes(bytes.try_into().unwrap());
    }
}

/// Rho and pi as one in-place walk (FIPS 202 §3.2.2–3): the lane at position
/// `t` of the walk `(x, y) ← (y, 2x + 3y)` from `(1, 0)` moves to `PI[t]`,
/// rotated by `RHO[t]`.
const WALK: ([usize; 24], [u32; 24]) = {
    let (mut pi, mut rho) = ([0usize; 24], [0u32; 24]);
    let (mut x, mut y) = (1usize, 0usize);
    let mut t = 0;
    while t < 24 {
        rho[t] = ((t + 1) * (t + 2) / 2 % 64) as u32;
        (x, y) = (y, (2 * x + 3 * y) % 5);
        pi[t] = x + 5 * y;
        t += 1;
    }
    (pi, rho)
};
pub(super) const PI: [usize; 24] = WALK.0;
pub(super) const RHO: [u32; 24] = WALK.1;

pub(crate) fn permutation(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        let mut last = a[1];
        for t in 0..24 {
            let next = a[PI[t]];
            a[PI[t]] = last.rotate_left(RHO[t]);
            last = next;
        }

        for y in 0..5 {
            let row: [u64; 5] = a[5 * y..5 * y + 5].try_into().unwrap();
            for x in 0..5 {
                a[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        a[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use sha3::{Digest, Keccak256};

    use super::{RATE, keccak256, permutation};

    // First lanes of Keccak-f[1600] on the zero state, from the Keccak team's
    // reference values.
    #[test]
    fn permutation_of_zero_state() {
        let mut state = [0u64; 25];
        permutation(&mut state);
        assert_eq!(state[0], 0xF125_8F79_40E1_DDE7);
        assert_eq!(state[1], 0x84D5_CCF9_33C0_478A);
        assert_eq!(state[2], 0xD598_261E_A65A_A9EE);
        assert_eq!(state[3], 0xBD15_4730_6F80_494D);
    }

    #[test]
    fn empty_input() {
        let expected = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(keccak256(b""), expected);
    }

    // Every pad position across two blocks, plus the leanXMSS input sizes (64, 80
    // and 960 bytes).
    #[test]
    fn matches_sha3_crate() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut input = [0u8; 960];
        rng.fill_bytes(&mut input);
        for len in (0..=2 * RATE).chain([960]) {
            let expected: [u8; 32] = Keccak256::digest(&input[..len]).into();
            assert_eq!(keccak256(&input[..len]), expected, "len {len}");
        }
    }
}
