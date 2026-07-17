use crate::{
    hash_tree::{DeltaHashTree, FinalizedHashTree, GloasDeltaHashTree, GloasFinalized},
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

const LIST_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.trailing_zeros();

pub(super) enum VersionedFinalizedHash {
    Fulu(FinalizedHashTree),
    Transition { fulu: FinalizedHashTree, gloas: GloasFinalized },
    Gloas(GloasFinalized),
}

impl VersionedFinalizedHash {
    #[cfg(test)]
    pub(super) fn fulu(&self) -> &FinalizedHashTree {
        match self {
            Self::Fulu(t) | Self::Transition { fulu: t, .. } => t,
            Self::Gloas(_) => unreachable!("no fulu tree past the fork transition"),
        }
    }

    pub(super) fn begin_transition(&mut self, populated: usize) {
        let Self::Fulu(fulu) = self else { return };
        let max = fulu.max_elements();
        debug_assert!(populated <= max);
        let gloas = GloasFinalized::from_leaf_hashes(
            (0..populated).map(|i| *fulu.node_hash((max + i) as u32)),
            max,
        );
        *self = Self::Transition { fulu: std::mem::take(fulu), gloas };
    }

    /// Drop the fulu side once finalization crossed the fork slot.
    pub(super) fn close_transition(&mut self) {
        if let Self::Transition { gloas, .. } = self {
            *self = Self::Gloas(std::mem::take(gloas));
        }
    }
}

#[derive(Clone)]
pub(super) enum VersionedDeltaHash {
    Fulu(DeltaHashTree),
    Gloas(GloasDeltaHashTree),
}

impl Default for VersionedDeltaHash {
    fn default() -> Self {
        VersionedDeltaHash::Fulu(DeltaHashTree::default())
    }
}

impl VersionedDeltaHash {
    pub(super) fn anchor_at(finalized: &VersionedFinalizedHash) -> Self {
        match finalized {
            VersionedFinalizedHash::Fulu(_) | VersionedFinalizedHash::Transition { .. } => {
                VersionedDeltaHash::Fulu(DeltaHashTree::default())
            }
            VersionedFinalizedHash::Gloas(g) => {
                VersionedDeltaHash::Gloas(GloasDeltaHashTree::new_at(g))
            }
        }
    }

    pub(super) fn adopt_gloas(&mut self, finalized: &VersionedFinalizedHash) {
        let VersionedDeltaHash::Fulu(fulu_overlay) = &*self else { return };
        let VersionedFinalizedHash::Transition { fulu, gloas } = finalized else {
            panic!("EIP-7688 version transition not started before the fork block")
        };
        *self = VersionedDeltaHash::Gloas(synthesized_gloas(fulu_overlay, fulu, gloas));
    }

    pub(super) fn crossed_hardfork(&self) -> bool {
        matches!(self, VersionedDeltaHash::Gloas(_))
    }

    pub(super) fn set_leaf(&mut self, base: &VersionedFinalizedHash, idx: usize, leaf: B256) {
        self.set_leaves(base, &[(idx as u32, leaf)]);
    }

    pub(super) fn set_leaves(&mut self, base: &VersionedFinalizedHash, sorted: &[(u32, B256)]) {
        match (self, base) {
            (VersionedDeltaHash::Fulu(o), VersionedFinalizedHash::Fulu(b)) => {
                o.set_leaves(b, sorted)
            }
            (
                VersionedDeltaHash::Gloas(o),
                VersionedFinalizedHash::Gloas(b) |
                VersionedFinalizedHash::Transition { gloas: b, .. },
            ) => o.set_leaves(b, sorted),
            _ => unreachable!(
                "Version of DeltaHashTree is incompatible with version of FinalizedHashTree"
            ),
        }
    }

    pub(super) fn ssz_list_root(&self, base: &VersionedFinalizedHash, len: usize) -> B256 {
        match (self, base) {
            (
                VersionedDeltaHash::Fulu(o),
                VersionedFinalizedHash::Fulu(b) |
                VersionedFinalizedHash::Transition { fulu: b, .. },
            ) => o.ssz_list_root(b, LIST_DEPTH, len),
            (
                VersionedDeltaHash::Gloas(o),
                VersionedFinalizedHash::Gloas(b) |
                VersionedFinalizedHash::Transition { gloas: b, .. },
            ) => o.ssz_list_root(b, len),
            _ => unreachable!(
                "Version of DeltaHashTree is incompatible with version of FinalizedHashTree"
            ),
        }
    }

    pub(super) fn rebased_and_pruned(
        old: &Self,
        base: &VersionedFinalizedHash,
        winner: &Self,
    ) -> Self {
        match (old, winner, base) {
            (
                VersionedDeltaHash::Fulu(old_f),
                VersionedDeltaHash::Fulu(win_f),
                VersionedFinalizedHash::Fulu(b) |
                VersionedFinalizedHash::Transition { fulu: b, .. },
            ) => VersionedDeltaHash::Fulu(rebased_and_pruned_fulu(old_f, b, win_f)),
            (
                VersionedDeltaHash::Gloas(old_g),
                VersionedDeltaHash::Gloas(win_g),
                VersionedFinalizedHash::Gloas(b) |
                VersionedFinalizedHash::Transition { gloas: b, .. },
            ) => VersionedDeltaHash::Gloas(rebased_and_pruned_gloas(old_g, b, win_g)),
            // Transition only — pre-fork winner, post-fork survivor: rebase against
            // the winner's synthesized gloas edits (same leaf domain and values
            // as its fulu edits).
            (
                VersionedDeltaHash::Gloas(old_g),
                VersionedDeltaHash::Fulu(win_f),
                VersionedFinalizedHash::Transition { fulu, gloas },
            ) => {
                let win_g = synthesized_gloas(win_f, fulu, gloas);
                VersionedDeltaHash::Gloas(rebased_and_pruned_gloas(old_g, gloas, &win_g))
            }
            _ => unreachable!("overlay shapes incompatible with base shape"),
        }
    }

    /// Fold this winner into `base` at finalization. A `Fulu` winner during
    /// the transition folds into BOTH sides — that is the transition invariant
    /// (gloas base values == fulu base values) that keeps later
    /// adoption/rebase syntheses valid.
    pub(super) fn promote_into(&self, base: &mut VersionedFinalizedHash) {
        match (self, base) {
            (VersionedDeltaHash::Fulu(o), VersionedFinalizedHash::Fulu(b)) => b.promote_delta(o),
            (VersionedDeltaHash::Fulu(o), VersionedFinalizedHash::Transition { fulu, gloas }) => {
                let synth = synthesized_gloas(o, fulu, gloas);
                fulu.promote_delta(o);
                gloas.promote_delta(&synth);
            }
            // Fork-crossing winner: advance only the gloas base — the fulu
            // side is dropped by the transition close that follows this promote.
            (VersionedDeltaHash::Gloas(o), VersionedFinalizedHash::Transition { gloas, .. }) => {
                gloas.promote_delta(o)
            }
            (VersionedDeltaHash::Gloas(o), VersionedFinalizedHash::Gloas(b)) => b.promote_delta(o),
            _ => unreachable!("overlay shape incompatible with base shape"),
        }
    }
}

fn rebased_and_pruned_fulu(
    old: &DeltaHashTree,
    base: &FinalizedHashTree,
    winner: &DeltaHashTree,
) -> DeltaHashTree {
    let mut overlay = old.clone();
    overlay.rebase(base, winner);
    base.prune_delta_against(&mut overlay, winner);
    overlay
}

fn rebased_and_pruned_gloas(
    old: &GloasDeltaHashTree,
    base: &GloasFinalized,
    winner: &GloasDeltaHashTree,
) -> GloasDeltaHashTree {
    let mut overlay = old.clone();
    overlay.rebase(base, winner);
    base.prune_delta_against(&mut overlay, winner);
    overlay
}

/// A gloas overlay with exactly the fulu overlay's leaf edits — valid
/// whenever the transition invariant holds. O(edits · log) SHA,
/// transition-scoped.
fn synthesized_gloas(
    fulu_overlay: &DeltaHashTree,
    fulu_base: &FinalizedHashTree,
    gloas_base: &GloasFinalized,
) -> GloasDeltaHashTree {
    let mut edits = Vec::new();
    fulu_overlay.collect_leaf_edits(0, fulu_base.max_elements() as u32, &mut edits);
    let mut overlay = GloasDeltaHashTree::new_at(gloas_base);
    overlay.set_leaves(gloas_base, &edits);
    overlay
}
