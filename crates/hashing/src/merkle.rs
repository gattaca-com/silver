use std::sync::LazyLock;

#[cfg(test)]
mod tests;

/// One-time hashtree backend selection (SHA-NI / AVX-512 / AVX2 / SSE).
/// Forced on the first `hash_concat` call. Holds whether full groups of
/// [`AVX512_GROUP`] go to the AVX-512 kernel.
///
/// hashtree picks SHA-NI whenever the CPU has it, since SHA-NI wins on short
/// inputs. On Zen 5 the AVX-512 kernel hashes full groups of 16 about twice as
/// fast as SHA-NI.
static HASHTREE_READY: LazyLock<bool> = LazyLock::new(|| {
    let rc = hashtree_rs::init();
    debug_assert_eq!(rc, 1, "hashtree_rs::init() failed");
    avx512_groups_available()
});

/// Below this many blocks the AVX-512 kernel falls back to AVX2, which is
/// slower than SHA-NI.
const AVX512_GROUP: usize = 16;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// In the static `libhashtree` that `hashtree-rs` links.
    fn hashtree_sha256_avx512_x16(output: *mut u8, input: *const u8, count: u64);
}

/// The kernel returns with the upper vector state dirty. Without
/// `vzeroupper`, the SSE-encoded SHA-NI kernel and non-VEX code after it run
/// slower.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn hash_avx512_groups(out: &mut [u8], pairs: &[u8], count: usize) {
    debug_assert!(out.len() >= count * 32 && pairs.len() >= count * 64);
    unsafe { hashtree_sha256_avx512_x16(out.as_mut_ptr(), pairs.as_ptr(), count as u64) };
    std::arch::x86_64::_mm256_zeroupper();
}

#[cfg(target_arch = "x86_64")]
fn avx512_groups_available() -> bool {
    is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512vl")
}

#[cfg(not(target_arch = "x86_64"))]
fn avx512_groups_available() -> bool {
    false
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
    let avx512_groups = *HASHTREE_READY;
    let n = out.len();
    let out_bytes = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, n * 32) };
    let in_bytes = unsafe { std::slice::from_raw_parts(pairs.as_ptr() as *const u8, n * 64) };
    let grouped = if avx512_groups { n / AVX512_GROUP * AVX512_GROUP } else { 0 };
    #[cfg(target_arch = "x86_64")]
    if grouped > 0 {
        // SAFETY: `avx512_groups_available` checked the CPU; `grouped <= n`
        // blocks fit both slices.
        unsafe { hash_avx512_groups(out_bytes, in_bytes, grouped) };
    }
    if grouped < n {
        hashtree_rs::hash(&mut out_bytes[grouped * 32..], &in_bytes[grouped * 64..], n - grouped);
    }
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
