//! leanXMSS: two layers of height-16 XMSS over WOTS+ C, hashed with Keccak-256.
//! Spec: "leanXMSS for Ethereum PQ-Consensus, specification draft".
//!
//! `SecretKey::new` builds the top tree (2^16 one-time keys). Signing at leaf
//! index `idx` needs `BottomTree` `idx >> 16`, which costs the same again; the
//! caller decides which bottom trees to keep. A leaf index must sign one
//! message only.

pub use crate::xmss::batch::{Item, verify_batch};
use crate::xmss::{
    keccak::keccak256,
    lanes::LANES,
    ots_lanes::ots_leaves,
    tree::{Tree, fold},
    wots::{ots_recover, ots_sign},
};

mod batch;
pub mod keccak;
mod lanes;
mod ots_lanes;
mod tree;
mod wots;

#[cfg(test)]
mod bench;
#[cfg(all(test, feature = "spec_vectors"))]
mod spec_vectors;
#[cfg(test)]
mod tests;

const CHAINS: usize = 58;
const HEIGHT: usize = 16;
const LEAVES: usize = 1 << HEIGHT;
const BOTTOM_LAYER: u32 = 0;
const TOP_LAYER: u32 = 1;

// Address types (spec §7).
const PRF: u8 = 0;
const CHAIN: u8 = 1;
const LEAF: u8 = 2;
const NODE: u8 = 3;
const PARAM: u8 = 5;
const RND: u8 = 7;
const MSG: u8 = 12;

type Digest = [u8; 16];

const LEAF_INPUT: usize = 32 + CHAINS * 16;

/// `ρ ∥ y_0 ∥ … ∥ y_{v-1} ∥ π_0 ∥ … ∥ π_{h-1}`.
const LAYER_SIG_LEN: usize = 16 + CHAINS * 16 + HEIGHT * 16;
const VALUES_AT: usize = 16;
const PATH_AT: usize = VALUES_AT + CHAINS * 16;
/// `LE32(idx)`, then the bottom layer's signature, then the top layer's.
pub const SIGNATURE_LEN: usize = 4 + 2 * LAYER_SIG_LEN;

pub fn get_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SecretKey::new(seed).public_key()
}

/// The leaf index `signature` carries.
pub fn leaf_index(signature: &[u8; SIGNATURE_LEN]) -> u32 {
    u32::from_le_bytes(signature[..4].try_into().unwrap())
}

/// Whether `signature` signs `message` at `leaf_index` under `public_key`.
pub fn verify(
    public_key: &[u8; 32],
    leaf_index: u64,
    message: &[u8; 32],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let idx = self::leaf_index(signature);
    if u64::from(idx) != leaf_index {
        return false;
    }
    let (root, p) = public_key.split_at(16);
    let p: &Digest = p.try_into().unwrap();
    let (bottom, top) = signature[4..].split_at(LAYER_SIG_LEN);

    let Some(bottom_root) = layer_root(p, BOTTOM_LAYER, idx, message, bottom) else {
        return false;
    };
    let Some(top_root) = layer_root(p, TOP_LAYER, idx >> HEIGHT, &bottom_root, top) else {
        return false;
    };
    top_root == root
}

/// The root one layer's signature of `m` by key `e` reaches, or `None` when its
/// digest is not a codeword.
fn layer_root(p: &Digest, layer: u32, e: u32, m: &[u8], sig: &[u8]) -> Option<Digest> {
    debug_assert_eq!(sig.len(), LAYER_SIG_LEN);
    let randomizer = sig[..VALUES_AT].try_into().unwrap();
    let values = sig[VALUES_AT..PATH_AT].as_chunks().0.try_into().unwrap();
    let path = sig[PATH_AT..].as_chunks().0;
    let leaf = ots_recover(p, layer, e, m, randomizer, values)?;
    Some(fold(p, layer, e, leaf, path))
}

pub struct SecretKey {
    secret: Secret,
    top: Tree,
}

impl SecretKey {
    pub fn new(seed: &[u8; 32]) -> SecretKey {
        let secret = Secret::new(seed);
        let top = build_tree(&secret, TOP_LAYER, 0);
        SecretKey { secret, top }
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[..16].copy_from_slice(self.top.root());
        pk[16..].copy_from_slice(&self.secret.p);
        pk
    }

    /// Bottom tree `b`, with the top layer's signature of its root.
    pub fn bottom_tree(&self, b: u32) -> BottomTree {
        let tree = build_tree(&self.secret, BOTTOM_LAYER, b << HEIGHT);
        let mut top_sig = [0u8; LAYER_SIG_LEN];
        layer_sign(&self.secret, &self.top, TOP_LAYER, b, tree.root(), &mut top_sig);
        BottomTree { b, tree, top_sig }
    }

    pub fn sign(&self, bottom: &BottomTree, message: &[u8; 32], idx: u32) -> [u8; SIGNATURE_LEN] {
        assert_eq!(idx >> HEIGHT, bottom.b);
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..4].copy_from_slice(&idx.to_le_bytes());
        let (bottom_sig, top_sig) = sig[4..].split_at_mut(LAYER_SIG_LEN);
        layer_sign(&self.secret, &bottom.tree, BOTTOM_LAYER, idx, message, bottom_sig);
        top_sig.copy_from_slice(&bottom.top_sig);
        sig
    }
}

pub struct BottomTree {
    b: u32,
    tree: Tree,
    top_sig: [u8; LAYER_SIG_LEN],
}

fn build_tree(secret: &Secret, layer: u32, first: u32) -> Tree {
    let mut leaves = vec![[0u8; 16]; LEAVES];
    for (group, out) in leaves.chunks_exact_mut(LANES).enumerate() {
        let e = std::array::from_fn(|l| first + (group * LANES + l) as u32);
        out.copy_from_slice(&ots_leaves(secret, layer, &e));
    }
    Tree::build(&secret.p, layer, first, &leaves)
}

fn layer_sign(secret: &Secret, tree: &Tree, layer: u32, e: u32, m: &[u8], out: &mut [u8]) {
    let (randomizer, values) =
        ots_sign(secret, layer, e, m).expect("a codeword among 2^32 randomizers");
    out[..VALUES_AT].copy_from_slice(&randomizer);
    out[VALUES_AT..PATH_AT].copy_from_slice(values.as_flattened());
    tree.path(e, out[PATH_AT..].as_chunks_mut().0);
}

struct Secret {
    s: [u8; 32],
    p: Digest,
}

impl Secret {
    fn new(seed: &[u8; 32]) -> Secret {
        let mut named = [0u8; 40];
        named[..8].copy_from_slice(b"leanXMSS");
        named[8..].copy_from_slice(seed);
        let s = keccak256(&named);
        let p = th(&[0u8; 16], &address(PARAM, 0, 0, 0), &s);
        Secret { s, p }
    }
}

/// `enc(τ, µ, hi, lo)` of spec §7: `LE32(lo) ∥ LE24(hi) ∥ LE8(τ + 32µ) ∥ 0^64`.
fn address(kind: u8, mu: u8, hi: u32, lo: u32) -> Digest {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&address_word(kind, mu, hi, lo).to_le_bytes());
    a
}

/// The first word of `address`; the second is zero.
fn address_word(kind: u8, mu: u8, hi: u32, lo: u32) -> u64 {
    debug_assert!(kind < 32 && mu < 8 && hi < 1 << 24);
    lo as u64 | (hi as u64) << 32 | ((kind + 32 * mu) as u64) << 56
}

fn hi(layer: u32, a: u32) -> u32 {
    debug_assert!(layer < 2 && a < 1 << 23);
    a | layer << 23
}

/// `H(P ∥ A ∥ M)`; `th` is its first half.
fn h(p: &Digest, a: &Digest, m: &[u8]) -> [u8; 32] {
    debug_assert!(m.len() <= LEAF_INPUT - 32);
    let mut input = [0u8; LEAF_INPUT];
    input[..16].copy_from_slice(p);
    input[16..32].copy_from_slice(a);
    input[32..32 + m.len()].copy_from_slice(m);
    keccak256(&input[..32 + m.len()])
}

fn th(p: &Digest, a: &Digest, m: &[u8]) -> Digest {
    h(p, a, m)[..16].try_into().unwrap()
}
