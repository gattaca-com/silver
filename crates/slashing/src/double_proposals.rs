use std::collections::hash_map::Entry;

use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_ssz::ssz_view::{
    BEACON_BLOCK_HEADER_SIZE, PROPOSER_SLASHING_SIZE, ProposerSlashingView, SignedBeaconBlockView,
};

use crate::PROOFS_CAPACITY;

const SIGNED_HEADER_SIZE: usize = PROPOSER_SLASHING_SIZE / 2;
const _: () = assert!(SIGNED_HEADER_SIZE == BEACON_BLOCK_HEADER_SIZE + 96);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ProposalKey {
    slot: Slot,
    proposer_index: u64,
}

/// SSZ `SignedBeaconBlockHeader`.
#[derive(Clone, Copy)]
pub struct SignedHeader([u8; SIGNED_HEADER_SIZE]);

impl SignedHeader {
    pub fn of_block(block: &[u8], body_root: &B256) -> Self {
        let mut ssz = [0u8; SIGNED_HEADER_SIZE];
        ssz[0..8].copy_from_slice(&SignedBeaconBlockView::slot(block).to_le_bytes());
        ssz[8..16].copy_from_slice(&SignedBeaconBlockView::proposer_index(block).to_le_bytes());
        ssz[16..48].copy_from_slice(SignedBeaconBlockView::parent_root(block));
        ssz[48..80].copy_from_slice(SignedBeaconBlockView::state_root(block));
        ssz[80..112].copy_from_slice(body_root);
        ssz[112..].copy_from_slice(SignedBeaconBlockView::signature(block));
        Self(ssz)
    }

    fn message(&self) -> &[u8] {
        &self.0[..BEACON_BLOCK_HEADER_SIZE]
    }

    fn key(&self) -> ProposalKey {
        ProposalKey {
            slot: u64::from_le_bytes(self.0[0..8].try_into().unwrap()),
            proposer_index: u64::from_le_bytes(self.0[8..16].try_into().unwrap()),
        }
    }

    fn slashing_with(&self, second: &Self) -> [u8; PROPOSER_SLASHING_SIZE] {
        let mut ssz = [0u8; PROPOSER_SLASHING_SIZE];
        ssz[..SIGNED_HEADER_SIZE].copy_from_slice(&self.0);
        ssz[SIGNED_HEADER_SIZE..].copy_from_slice(&second.0);
        ssz
    }
}

struct Proposal {
    header: SignedHeader,
    /// Local proposals never enter a proof; a reported first enters one.
    provable: bool,
}

#[derive(Default)]
pub struct DoubleProposals {
    firsts: FxHashMap<ProposalKey, Proposal>,
    proofs: Vec<[u8; PROPOSER_SLASHING_SIZE]>,
}

impl DoubleProposals {
    pub fn is_closed(
        &self,
        slot: Slot,
        proposer_index: u64,
        slashable: impl FnOnce(u64) -> bool,
    ) -> bool {
        self.firsts
            .get(&ProposalKey { slot, proposer_index })
            .is_some_and(|first| !first.provable || !slashable(proposer_index))
    }

    /// Takes verified headers only and tells whether `header` conflicts
    /// with its key's first. A conflict queues one proof per key, pairing two
    /// headers that are not local.
    pub fn observe(&mut self, header: SignedHeader, local: bool) -> bool {
        let first = match self.firsts.entry(header.key()) {
            Entry::Vacant(vacant) => {
                vacant.insert(Proposal { header, provable: !local });
                return false;
            }
            Entry::Occupied(occupied) => occupied.into_mut(),
        };
        if first.header.message() == header.message() {
            return false;
        }
        if !local && first.provable && self.proofs.len() < PROOFS_CAPACITY {
            first.provable = false;
            self.proofs.push(first.header.slashing_with(&header));
        }
        true
    }

    pub fn has_proofs(&self) -> bool {
        !self.proofs.is_empty()
    }

    /// The newest queued proof whose proposer is slashable, left queued.
    /// Proofs ahead of it are dropped.
    pub fn next_proof(
        &mut self,
        slashable: impl Fn(u64) -> bool,
    ) -> Option<&[u8; PROPOSER_SLASHING_SIZE]> {
        while let Some(proof) = self.proofs.last() {
            if slashable(ProposerSlashingView::h1_proposer_index(proof)) {
                break;
            }
            self.proofs.pop();
        }
        self.proofs.last()
    }

    pub fn pop_proof(&mut self) {
        self.proofs.pop();
    }

    pub fn prune_finalized(&mut self, finalized_slot: Slot) {
        self.firsts.retain(|key, _| key.slot > finalized_slot);
    }
}
