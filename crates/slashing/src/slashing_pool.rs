use std::cmp::Reverse;

use silver_beacon_state_data::{
    Epoch, EpochView, SLOTS_PER_EPOCH, StateReadView, ValidatorsView, Version,
};
use silver_ssz::ssz_view::{
    AttesterSlashingView, MAX_ATTESTER_SLASHINGS_ELECTRA, MAX_PROPOSER_SLASHINGS,
    PROPOSER_SLASHING_SIZE, ProposerSlashingView,
};

const PROPOSER_SLASHINGS_CAPACITY: usize = 128;
// Attester proofs can occupy about 2.5 MiB each, including offender indices.
const ATTESTER_SLASHINGS_CAPACITY: usize = 16;

const _: () =
    assert!(MAX_ATTESTER_SLASHINGS_ELECTRA == 1, "Selection carries at most one attester slashing");

/// Accepts proofs already verified on `head`; does not verify signatures or
/// slashing conditions. Ranks proofs by the effective balance they can slash.
pub struct SlashingPool {
    proposer: Bounded<ProposerSlashing, PROPOSER_SLASHINGS_CAPACITY>,
    attester: Bounded<AttesterSlashing, ATTESTER_SLASHINGS_CAPACITY>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Stored,
    /// Stored in place of the least valuable proof of its kind.
    Replaced,
    /// Worth no more than any stored proof of its kind.
    Dropped,
    /// A signer's key may differ on the fork a block is built on.
    UnfinalizedSigner,
}

/// The SSZ lists a block body carries, reused across selections.
#[derive(Default)]
pub struct Selection {
    proposer_slashings: Vec<u8>,
    attester_slashings: Vec<u8>,
}

impl Selection {
    pub fn proposer_slashings(&self) -> &[u8] {
        &self.proposer_slashings
    }

    pub fn attester_slashings(&self) -> &[u8] {
        &self.attester_slashings
    }

    pub fn clear(&mut self) {
        self.proposer_slashings.clear();
        self.attester_slashings.clear();
    }
}

impl Default for SlashingPool {
    fn default() -> Self {
        Self { proposer: Bounded::new(), attester: Bounded::new() }
    }
}

impl SlashingPool {
    /// `head` values the stored proofs when the pool is full.
    pub fn insert_proposer_slashing(
        &mut self,
        ssz: &[u8; PROPOSER_SLASHING_SIZE],
        head: &StateReadView,
    ) -> Admission {
        let head = ForkFacts::of(head);
        self.proposer.admit(ProposerSlashing::new(ssz, head), |p| p.value(head))
    }

    /// `offenders` are the validators both attestations name; `head` values
    /// the stored proofs when the pool is full.
    pub fn insert_attester_slashing(
        &mut self,
        ssz: &[u8],
        offenders: &[u32],
        head: &StateReadView,
    ) -> Admission {
        debug_assert!(AttesterSlashingView::check_size(ssz));
        let finalized = head.validators.finalized().validator_count() as u64;
        let signers = [
            AttesterSlashingView::att1_attesting_indices(ssz),
            AttesterSlashingView::att2_attesting_indices(ssz),
        ];
        // Verified attestations have sorted indices. Finalized keys survive reorgs.
        if signers
            .iter()
            .filter_map(|list| list.last_chunk())
            .any(|&last| u64::from_le_bytes(last) >= finalized)
        {
            return Admission::UnfinalizedSigner;
        }
        let head = ForkFacts::of(head);
        self.attester.admit(AttesterSlashing::new(ssz, offenders, head), |a| a.value(head, &[]))
    }

    /// `pre_state` must be the proposal's parent state advanced into its epoch.
    ///
    /// Proposer slashings apply first. An attester slashing must still slash
    /// someone afterward, or the block is invalid.
    pub fn select(&self, pre_state: &StateReadView, into: &mut Selection) {
        let pre_state = ForkFacts::of(pre_state);
        into.clear();

        let mut ranked = [(Reverse(0), 0); PROPOSER_SLASHINGS_CAPACITY];
        let mut ranked_len = 0;
        for (i, p) in self.proposer.0.iter().enumerate() {
            let balance = p.value(pre_state);
            if balance > 0 {
                ranked[ranked_len] = (Reverse(balance), i);
                ranked_len += 1;
            }
        }
        // Ties keep insertion order.
        ranked[..ranked_len].sort_unstable();

        let mut slashed = [0; MAX_PROPOSER_SLASHINGS];
        let mut slashed_len = 0;
        for &(_, i) in &ranked[..ranked_len] {
            if slashed_len == MAX_PROPOSER_SLASHINGS {
                break;
            }
            let p = &self.proposer.0[i];
            if slashed[..slashed_len].contains(&p.offender()) {
                continue;
            }
            slashed[slashed_len] = p.offender();
            slashed_len += 1;
            into.proposer_slashings.extend_from_slice(&p.ssz);
        }
        let slashed = &slashed[..slashed_len];

        let attester_slashing = self
            .attester
            .0
            .iter()
            .map(|a| (a.value(pre_state, slashed), a))
            .filter(|&(balance, _)| balance > 0)
            .max_by_key(|&(balance, _)| balance);
        if let Some((_, a)) = attester_slashing {
            let only_offset = size_of::<u32>() as u32;
            into.attester_slashings.extend_from_slice(&only_offset.to_le_bytes());
            into.attester_slashings.extend_from_slice(&a.ssz);
        }
    }

    /// Retains proofs until all offenders are slashed or withdrawable in
    /// `finalized`. Ignores signing versions: the head may have upgraded
    /// before finalization.
    pub fn prune(&mut self, finalized: &StateReadView) {
        let finalized = ForkFacts::of(finalized);
        self.proposer.0.retain(|p| !p.is_retired(finalized));
        self.attester.0.retain(|a| !a.is_retired(finalized));
    }
}

struct ProposerSlashing {
    ssz: [u8; PROPOSER_SLASHING_SIZE],
    signing_version: Version,
}

impl ProposerSlashing {
    fn new(ssz: &[u8; PROPOSER_SLASHING_SIZE], head: ForkFacts) -> Self {
        let mut slashing = Self { ssz: *ssz, signing_version: Version::default() };
        slashing.signing_version = head.signing_version(slashing.signing_epoch());
        slashing
    }

    fn offender(&self) -> usize {
        ProposerSlashingView::h1_proposer_index(&self.ssz) as usize
    }

    fn signing_epoch(&self) -> Epoch {
        ProposerSlashingView::h1_slot(&self.ssz) / SLOTS_PER_EPOCH
    }

    fn signatures_hold(&self, fork: ForkFacts) -> bool {
        fork.signing_version(self.signing_epoch()) == self.signing_version
    }

    fn value(&self, fork: ForkFacts) -> u64 {
        if self.signatures_hold(fork) { fork.slashable_balance(self.offender()) } else { 0 }
    }

    fn is_retired(&self, fork: ForkFacts) -> bool {
        fork.is_retired(self.offender())
    }
}

struct AttesterSlashing {
    ssz: Vec<u8>,
    offenders: Vec<u32>,
    signing_versions: [Version; 2],
}

impl AttesterSlashing {
    fn new(ssz: &[u8], offenders: &[u32], head: ForkFacts) -> Self {
        let mut slashing = Self {
            ssz: ssz.to_vec(),
            offenders: offenders.to_vec(),
            signing_versions: Default::default(),
        };
        slashing.signing_versions = slashing.signing_epochs().map(|e| head.signing_version(e));
        slashing
    }

    fn signing_epochs(&self) -> [Epoch; 2] {
        [
            AttesterSlashingView::att1_target_epoch(&self.ssz),
            AttesterSlashingView::att2_target_epoch(&self.ssz),
        ]
    }

    fn signatures_hold(&self, fork: ForkFacts) -> bool {
        self.signing_epochs().map(|e| fork.signing_version(e)) == self.signing_versions
    }

    fn value(&self, fork: ForkFacts, excluded: &[usize]) -> u64 {
        if !self.signatures_hold(fork) {
            return 0;
        }
        self.offenders
            .iter()
            .map(|&vi| vi as usize)
            .filter(|vi| !excluded.contains(vi))
            .map(|vi| fork.slashable_balance(vi))
            .sum()
    }

    fn is_retired(&self, fork: ForkFacts) -> bool {
        self.offenders.iter().all(|&vi| fork.is_retired(vi as usize))
    }
}

struct Bounded<T, const N: usize>(Vec<T>);

impl<T, const N: usize> Bounded<T, N> {
    fn new() -> Self {
        Self(Vec::with_capacity(N))
    }

    fn admit(&mut self, incoming: T, value: impl Fn(&T) -> u64) -> Admission {
        if self.0.len() < N {
            self.0.push(incoming);
            return Admission::Stored;
        }
        let least = self.0.iter().enumerate().map(|(i, e)| (i, value(e))).min_by_key(|&(_, v)| v);
        match least {
            Some((i, least_value)) if value(&incoming) > least_value => {
                self.0[i] = incoming;
                Admission::Replaced
            }
            _ => Admission::Dropped,
        }
    }
}

#[derive(Clone, Copy)]
struct ForkFacts<'a> {
    validators: ValidatorsView<'a>,
    versions: EpochView<'a>,
    epoch: Epoch,
}

impl<'a> ForkFacts<'a> {
    fn of(state: &StateReadView<'a>) -> Self {
        Self {
            validators: state.validators,
            versions: state.epoch,
            epoch: state.slot.current_epoch(),
        }
    }

    /// A later fork upgrade can change the version for the same message
    /// epoch, and with it the signing domain.
    fn signing_version(self, message_epoch: Epoch) -> Version {
        self.versions.fork_version_at(message_epoch)
    }

    fn slashable_balance(self, vi: usize) -> u64 {
        if vi < self.validators.count() && self.validators.is_slashable(vi, self.epoch) {
            self.validators.effective_balance(vi)
        } else {
            0
        }
    }

    fn is_retired(self, vi: usize) -> bool {
        vi < self.validators.count() &&
            (self.validators.is_slashed(vi) ||
                self.epoch >= self.validators.withdrawable_epoch(vi))
    }
}

#[cfg(test)]
mod tests;
