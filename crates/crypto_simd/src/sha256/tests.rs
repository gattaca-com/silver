use blst::blst_sha256;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Sha256;
use crate::sha_kernel_runs;

/// For tests that have seen `sha_kernel_runs` hold.
fn digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // SAFETY: `sha_kernel_runs` checked the SHA extensions and SSE4.1.
    unsafe {
        hasher.update(message);
        hasher.finish()
    }
}

fn blst_digest(message: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: blst reads `message.len()` bytes and writes 32.
    unsafe { blst_sha256(out.as_mut_ptr(), message.as_ptr(), message.len()) };
    out
}

fn from_hex(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The examples of FIPS 180-2's Appendix B, and the empty message.
#[test]
fn fips_examples() {
    if !sha_kernel_runs() {
        return;
    }
    let cases: [(&[u8], &str); 3] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(digest(message), from_hex(expected), "{:?}", String::from_utf8_lossy(message));
    }
    assert_eq!(
        digest(&vec![b'a'; 1_000_000]),
        from_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    );
}

/// Every count of bytes left for the last block, with one and with two
/// padding blocks, after zero to four full blocks.
#[test]
fn every_length_to_five_blocks_matches_blst() {
    if !sha_kernel_runs() {
        return;
    }
    let mut message = [0u8; 5 * 64];
    ChaCha8Rng::seed_from_u64(0x5a).fill(&mut message[..]);
    for len in 0..=message.len() {
        assert_eq!(digest(&message[..len]), blst_digest(&message[..len]), "length {len}");
    }
}

#[test]
fn parts_hash_as_their_concatenation() {
    if !sha_kernel_runs() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x9a);
    let mut message = [0u8; 600];
    rng.fill(&mut message[..]);
    // Parts that fill the pending block exactly, start on a block boundary,
    // span several blocks, and are empty.
    let mut splits = vec![vec![10, 54, 64, 1, 63, 128, 0, 5, 0, 211]];
    for _ in 0..200 {
        let mut parts = Vec::new();
        let mut left = rng.gen_range(0..message.len());
        while left > 0 {
            let part = rng.gen_range(0..=left.min(150));
            parts.push(part);
            left -= part;
        }
        splits.push(parts);
    }
    for parts in splits {
        let mut hasher = Sha256::new();
        let mut start = 0;
        for part in &parts {
            // SAFETY: as in `digest`.
            unsafe { hasher.update(&message[start..start + part]) };
            start += part;
        }
        // SAFETY: as in `digest`.
        let got = unsafe { hasher.finish() };
        assert_eq!(got, digest(&message[..start]), "parts {parts:?}");
    }
}
