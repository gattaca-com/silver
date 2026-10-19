use std::sync::LazyLock;

/// One-time hashtree backend selection (SHA-NI / AVX-512 / AVX2 / SSE).
/// Forced on the first `hash_concat` call; result is `1` on success.
static HASHTREE_READY: LazyLock<()> = LazyLock::new(|| {
    let rc = hashtree_rs::init();
    debug_assert_eq!(rc, 1, "hashtree_rs::init() failed");
});

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
    let out_bytes = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, n * 32) };
    let in_bytes = unsafe { std::slice::from_raw_parts(pairs.as_ptr() as *const u8, n * 64) };
    hashtree_rs::hash(out_bytes, in_bytes, n);
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
