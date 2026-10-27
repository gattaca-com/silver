/// Below this many blocks the AVX-512 kernel falls back to AVX2, which is
/// slower than SHA-NI.
const AVX512_GROUP: usize = 16;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// In the static `libhashtree` that `hashtree-rs` links.
    fn hashtree_sha256_avx512_x16(output: *mut u8, input: *const u8, count: u64);
}

/// hashtree picks SHA-NI whenever the CPU has it, which wins only on short
/// inputs.
#[cfg(target_arch = "x86_64")]
fn has_avx512_groups() -> bool {
    is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512vl") &&
        is_x86_feature_detected!("avx512bw")
}

/// The kernel returns with the upper vector state dirty. On Zen 5 that made
/// the code after it, SHA-NI included, measurably slower.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn hash_avx512_groups(out: &mut [B256], pairs: &[B256]) {
    unsafe {
        hashtree_sha256_avx512_x16(out.as_mut_ptr().cast(), pairs.as_ptr().cast(), out.len() as u64)
    };
    std::arch::x86_64::_mm256_zeroupper();
}

pub type B256 = [u8; 32];

#[inline]
pub fn hash_concat(a: &B256, b: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    let mut out = [0u8; 32];
    hashtree_rs::hash(&mut out, &buf, 1);
    out
}

#[inline]
pub fn hash_concat_many(out: &mut [B256], pairs: &[B256]) {
    debug_assert_eq!(pairs.len(), 2 * out.len());
    let mut grouped = 0;
    #[cfg(target_arch = "x86_64")]
    if out.len() >= AVX512_GROUP && has_avx512_groups() {
        grouped = out.len() / AVX512_GROUP * AVX512_GROUP;
        // SAFETY: `has_avx512_groups` checked the CPU.
        unsafe { hash_avx512_groups(&mut out[..grouped], &pairs[..2 * grouped]) };
    }
    let rest = out.len() - grouped;
    hashtree_rs::hash(out[grouped..].as_flattened_mut(), pairs[2 * grouped..].as_flattened(), rest);
}

/// SSZ bytes as 32-byte leaf chunks, the last one zero-padded.
pub fn byte_chunks(bytes: &[u8]) -> impl Iterator<Item = B256> + '_ {
    bytes.chunks(32).map(|c| {
        let mut chunk = [0u8; 32];
        chunk[..c.len()].copy_from_slice(c);
        chunk
    })
}

#[inline]
pub fn mix_in_length(root: &B256, length: usize) -> B256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&(length as u64).to_le_bytes());
    hash_concat(root, &chunk)
}

/// Max SSZ depth we ever hit is 40 (VALIDATOR_REGISTRY_LIMIT = 2^40);
const ZERO_HASHES_LEN: usize = 48;

pub const ZERO_HASHES: [B256; ZERO_HASHES_LEN] = {
    let mut zh = [[0u8; 32]; ZERO_HASHES_LEN];
    let mut i = 1;
    while i < ZERO_HASHES_LEN {
        zh[i] = sha2_const_stable::Sha256::new().update(&zh[i - 1]).update(&zh[i - 1]).finalize();
        i += 1;
    }
    zh
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_concat_many_matches_hash_concat() {
        let pairs: Vec<B256> = (0..2 * 49).map(|i| [i as u8; 32]).collect();
        for n in 0..=49 {
            let mut out = vec![[0; 32]; n];
            hash_concat_many(&mut out, &pairs[..2 * n]);
            for (i, digest) in out.iter().enumerate() {
                assert_eq!(
                    *digest,
                    hash_concat(&pairs[2 * i], &pairs[2 * i + 1]),
                    "{n} pairs, pair {i}"
                );
            }
        }
    }
}
