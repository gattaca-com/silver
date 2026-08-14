//! The incremental [`MerkleStack`] tree builder and the [`Merkleizer`] trait
//! that abstracts it from its unbounded EIP-7916 twin.

use flux::utils::ArrayVec;

use super::hash::{B256, ZERO_HASHES, ZERO_HASHES_LEN, hash_concat};

#[inline]
const fn depth_for(capacity: usize) -> u8 {
    capacity.next_power_of_two().trailing_zeros() as u8
}

/// Stack of parked subtree roots keyed by height (heights strictly decrease
/// from bottom to top), building a tree padded up to a fixed leaf `capacity`
/// (rounded to the next power of two) at [`finalize`](Self::finalize).
/// `Default` yields capacity 1 (a single-leaf tree).
#[derive(Clone, Copy, Default)]
pub struct MerkleStack {
    stack: ArrayVec<(u8, B256), ZERO_HASHES_LEN>,
    target_depth: u8,
}

impl MerkleStack {
    pub fn new(capacity: usize) -> Self {
        Self { stack: ArrayVec::new(), target_depth: depth_for(capacity) }
    }

    /// Root of an empty tree of the given leaf `capacity`: the precomputed
    /// zero-subtree hash, skipping accumulation entirely. `const` so callers
    /// with a static capacity get a compile-time constant.
    pub const fn empty_root(capacity: usize) -> B256 {
        ZERO_HASHES[depth_for(capacity) as usize]
    }

    /// Absorb a leaf, combining upward with any left-sibling already parked at
    /// the same height.
    pub fn push(&mut self, leaf: B256) {
        let mut cur = leaf;
        let mut h: u8 = 0;
        while let Some(&(top_h, top_root)) = self.stack.as_slice().last() {
            if top_h != h {
                break;
            }
            self.stack.pop();
            cur = hash_concat(&top_root, &cur);
            h += 1;
        }
        self.stack.push((h, cur));
    }

    /// Walk the parked stack up to `target_depth`, padding with zero subtrees
    /// where no right-sibling is available.
    pub fn finalize(mut self) -> B256 {
        if self.stack.is_empty() {
            return ZERO_HASHES[self.target_depth as usize];
        }
        let (first_h, first_root) = self.stack.pop().unwrap();
        let mut cur = first_root;
        let mut h = first_h;
        while h < self.target_depth {
            match self.stack.as_slice().last() {
                Some(&(top_h, top_root)) if top_h == h => {
                    self.stack.pop();
                    cur = hash_concat(&top_root, &cur);
                }
                _ => {
                    cur = hash_concat(&cur, &ZERO_HASHES[h as usize]);
                }
            }
            h += 1;
        }
        cur
    }
}

/// Absorbs 32-byte leaves into a merkle root. The axis a fixed-limit list and
/// its EIP-7916 progressive twin differ on: [`MerkleStack`] pads to a limit,
/// [`ProgressiveHasher`](crate::progressive::ProgressiveHasher) is unbounded —
/// so the list hashers take one generically.
pub trait Merkleizer {
    fn push(&mut self, chunk: B256);
    fn finalize(self) -> B256;
}

impl Merkleizer for MerkleStack {
    #[inline]
    fn push(&mut self, chunk: B256) {
        MerkleStack::push(self, chunk);
    }
    #[inline]
    fn finalize(self) -> B256 {
        MerkleStack::finalize(self)
    }
}
