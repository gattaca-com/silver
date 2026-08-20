use silver_beacon_state_data::{B256, Version};

use crate::ssz_hash::hash_tree_root_fork_data;

/// A chain sees a handful of fork versions over its whole life; past the cap
/// the root is simply recomputed (one compression).
const MAX_ENTRIES: usize = 8;

/// Lazy (fork version -> fork-data root) table. Keyed by the version itself,
/// so an entry can never go stale — no refresh choreography at fork
/// transitions.
pub struct ForkDataRoots {
    genesis_validators_root: B256,
    entries: Vec<(Version, B256)>,
}

impl Default for ForkDataRoots {
    fn default() -> Self {
        Self { genesis_validators_root: B256::default(), entries: Vec::with_capacity(MAX_ENTRIES) }
    }
}

impl ForkDataRoots {
    pub fn root(&mut self, version: Version, genesis_validators_root: &B256) -> B256 {
        if self.genesis_validators_root != *genesis_validators_root {
            self.entries.clear();
            self.genesis_validators_root = *genesis_validators_root;
        }
        if let Some((_, root)) = self.entries.iter().find(|(v, _)| *v == version) {
            return *root;
        }

        let root = hash_tree_root_fork_data(version, genesis_validators_root);
        if self.entries.len() < MAX_ENTRIES {
            self.entries.push((version, root));
        }
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GVR: B256 = [0x11; 32];

    #[test]
    fn miss_then_hit_agree_with_direct() {
        let mut roots = ForkDataRoots::default();
        let version = [1, 2, 3, 4];
        let expected = hash_tree_root_fork_data(version, &GVR);
        assert_eq!(roots.root(version, &GVR), expected);
        assert_eq!(roots.entries.len(), 1);
        assert_eq!(roots.root(version, &GVR), expected);
        assert_eq!(roots.entries.len(), 1);
    }

    #[test]
    fn genesis_validators_root_change_resets() {
        let mut roots = ForkDataRoots::default();
        let version = [1, 2, 3, 4];
        let stale = roots.root(version, &GVR);

        let other_gvr = [0x22; 32];
        let fresh = roots.root(version, &other_gvr);
        assert_ne!(fresh, stale);
        assert_eq!(fresh, hash_tree_root_fork_data(version, &other_gvr));
        assert_eq!(roots.entries.len(), 1);
    }

    #[test]
    fn cap_overflow_still_computes() {
        let mut roots = ForkDataRoots::default();
        for i in 0..MAX_ENTRIES as u8 {
            roots.root([i, 0, 0, 0], &GVR);
        }
        assert_eq!(roots.entries.len(), MAX_ENTRIES);

        let overflow = [9, 9, 9, 9];
        assert_eq!(roots.root(overflow, &GVR), hash_tree_root_fork_data(overflow, &GVR));
        assert_eq!(roots.entries.len(), MAX_ENTRIES);
        assert_eq!(roots.root(overflow, &GVR), hash_tree_root_fork_data(overflow, &GVR));
    }
}
