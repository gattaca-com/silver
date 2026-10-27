use std::{ffi::c_int, sync::LazyLock};

type HashFn = unsafe extern "C" fn(output: *mut u8, input: *const u8, count: u64);

unsafe extern "C" {
    /// `None` keeps hashtree's own CPU detection.
    fn hashtree_init(backend: Option<HashFn>) -> c_int;
}

/// Serializes backend installation before either hashing entry point uses
/// hashtree's unsynchronized global function pointer.
static HASHTREE_READY: LazyLock<()> = LazyLock::new(|| {
    // SAFETY: `avx512_groups::backend` checked the CPU for every kernel it calls.
    let rc = unsafe { hashtree_init(avx512_groups::backend()) };
    debug_assert_eq!(rc, 1, "hashtree_init() failed");
});

#[cfg(target_arch = "x86_64")]
mod avx512_groups {
    use std::arch::x86_64::_mm256_zeroupper;

    use super::HashFn;

    /// Smaller batches fall back to AVX2 inside the AVX-512 kernel.
    const GROUP: u64 = 16;

    unsafe extern "C" {
        fn hashtree_sha256_avx512_x16(output: *mut u8, input: *const u8, count: u64);
        fn hashtree_sha256_shani_x2(output: *mut u8, input: *const u8, count: u64);
    }

    pub(super) fn backend() -> Option<HashFn> {
        let supported = is_x86_feature_detected!("sha") &&
            is_x86_feature_detected!("avx512f") &&
            is_x86_feature_detected!("avx512vl") &&
            is_x86_feature_detected!("avx512bw");
        supported.then_some(hash as HashFn)
    }

    #[target_feature(enable = "avx")]
    unsafe extern "C" fn hash(output: *mut u8, input: *const u8, count: u64) {
        let grouped = count / GROUP * GROUP;
        if grouped > 0 {
            unsafe { hashtree_sha256_avx512_x16(output, input, grouped) };
            // The assembly kernel leaves upper vector state dirty.
            _mm256_zeroupper();
        }
        let done = grouped as usize;
        unsafe {
            hashtree_sha256_shani_x2(output.add(32 * done), input.add(64 * done), count - grouped)
        };
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod avx512_groups {
    pub(super) fn backend() -> Option<super::HashFn> {
        None
    }
}

pub type B256 = [u8; 32];

#[inline]
pub fn hash_concat(a: &B256, b: &B256) -> B256 {
    LazyLock::force(&HASHTREE_READY);
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
    LazyLock::force(&HASHTREE_READY);
    let n = out.len();
    hashtree_rs::hash(out.as_flattened_mut(), pairs.as_flattened(), n);
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
