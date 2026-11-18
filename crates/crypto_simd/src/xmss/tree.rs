//! One layer's Merkle tree (spec §4). Node addresses carry the node's index on
//! the layer, so a bottom tree's nodes are indexed from `first >> level`.

use crate::xmss::{Digest, NODE, address, hi, th};

/// Heap layout: root at index 1, node `(level, j)` at `(leaves >> level) + j`
/// with `j` local to the tree. Index 0 is unused.
pub(super) struct Tree {
    first: u32,
    nodes: Vec<Digest>,
}

impl Tree {
    pub(super) fn build(p: &Digest, layer: u32, first: u32, leaves: &[Digest]) -> Tree {
        assert!(leaves.len().is_power_of_two());
        debug_assert_eq!(first as usize % leaves.len(), 0);
        let mut nodes = vec![[0u8; 16]; 2 * leaves.len()];
        nodes[leaves.len()..].copy_from_slice(leaves);

        let mut level = 0;
        let mut width = leaves.len();
        while width > 1 {
            width /= 2;
            level += 1;
            for j in 0..width {
                let parent = width + j;
                let children = [nodes[2 * parent], nodes[2 * parent + 1]];
                let index = (first >> level) + j as u32;
                nodes[parent] = node(p, layer, level, index, &children);
            }
        }
        Tree { first, nodes }
    }

    pub(super) fn root(&self) -> &Digest {
        &self.nodes[1]
    }

    /// `π_λ = X_{λ, ⌊e/2^λ⌋ ⊕ 1}` for `λ < out.len()`.
    pub(super) fn path(&self, e: u32, out: &mut [Digest]) {
        let leaves = self.nodes.len() / 2;
        let k = (e - self.first) as usize;
        debug_assert!(k < leaves && out.len() <= leaves.trailing_zeros() as usize);
        for (level, sibling) in out.iter_mut().enumerate() {
            *sibling = self.nodes[(leaves >> level) + ((k >> level) ^ 1)];
        }
    }
}

fn node(p: &Digest, layer: u32, level: u32, j: u32, children: &[Digest; 2]) -> Digest {
    th(p, &address(NODE, 0, hi(layer, level), j), children.as_flattened())
}

/// `Tree.fold`: the root `leaf` at index `e` reaches along `path`.
pub(super) fn fold(p: &Digest, layer: u32, e: u32, leaf: Digest, path: &[Digest]) -> Digest {
    path.iter().enumerate().fold(leaf, |current, (level, &sibling)| {
        let children = if (e >> level) & 1 == 0 { [current, sibling] } else { [sibling, current] };
        node(p, layer, level as u32 + 1, e >> (level + 1), &children)
    })
}
