use flux::utils::ArrayVec;

use super::{Eth1Group, Eth1Id, finalized::Eth1Votes};
use crate::{
    buffer::{Reset, Slot},
    types::{Eth1Data, MAX_ETH1_VOTES},
};

/// One fork's vote-list delta: `appended` holds the votes pushed since the
/// fork base (or since the fork's last voting-period clear); `resets` counts
/// the clears — non-zero means the finalized list is out of scope for this
/// fork.
#[derive(Clone, Default)]
pub(super) struct Eth1VotesDelta {
    resets: u32,
    appended: Vec<Eth1Data>,
}

impl Eth1VotesDelta {
    /// The finalized list still prefixes this fork's effective votes.
    #[inline]
    fn keeps_base(&self) -> bool {
        self.resets == 0
    }

    /// Re-base onto a freshly-promoted base: drop the inherited prefix the
    /// winner just folded in, or — if this fork cleared after the winner —
    /// keep standing alone on its own appends.
    pub(super) fn rebase(&mut self, winner: &Self) {
        debug_assert!(
            self.resets >= winner.resets,
            "descendant cleared less than the promoted delta",
        );
        if self.resets == winner.resets {
            // No clear since the winner: the inherited prefix is exactly the
            // winner's appends, now folded into the base.
            self.appended.drain(..winner.appended.len());
            self.resets = 0;
        } else {
            // Cleared after the winner: nothing inherited survives in
            // `appended`, and the new base stays out of scope.
            self.resets -= winner.resets;
        }
    }

    /// Fold into the finalized list: apply the clear, append the new votes.
    pub(super) fn promote_into(&self, base: &mut ArrayVec<Eth1Data, MAX_ETH1_VOTES>) {
        if !self.keeps_base() {
            base.clear();
        }
        for v in &self.appended {
            base.push(*v);
        }
    }
}

impl Reset for Eth1VotesDelta {
    fn reset(&mut self) {
        self.resets = 0;
        self.appended.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.resets = other.resets;
        self.appended.clone_from(&other.appended);
    }
}

/// Value-layer read over the eth1 votes (base + a per-fork delta).
#[derive(Clone, Copy)]
pub struct Eth1View<'a> {
    base: &'a Eth1Votes,
    delta: &'a Eth1VotesDelta,
}

impl<'a> Eth1View<'a> {
    #[inline]
    pub(super) fn new(base: &'a Eth1Votes, delta: &'a Eth1VotesDelta) -> Self {
        Self { base, delta }
    }

    #[inline]
    fn kept_base(&self) -> &'a [Eth1Data] {
        if self.delta.keeps_base() { self.base.as_slice() } else { &[] }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.kept_base().len() + self.delta.appended.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'a Eth1Data> + use<'a> {
        self.kept_base().iter().chain(self.delta.appended.iter())
    }
}

pub struct Eth1WriteView<'a> {
    base: &'a Eth1Votes,
    fork: Slot<'a, Eth1Group, Eth1VotesDelta>,
}

impl<'a> Eth1WriteView<'a> {
    #[inline]
    pub(super) fn new(base: &'a Eth1Votes, fork: Slot<'a, Eth1Group, Eth1VotesDelta>) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> Eth1Id {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> Eth1View<'_> {
        Eth1View { base: self.base, delta: &self.fork }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.reader().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.reader().is_empty()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Eth1Data> {
        self.reader().iter()
    }

    /// Append a vote. The spec cap holds in release too: an overflow here
    /// would otherwise grow the finalized list past its structural bound at
    /// promote.
    #[inline]
    pub fn push(&mut self, vote: Eth1Data) {
        assert!(self.len() < MAX_ETH1_VOTES, "eth1_votes exceeded MAX_ETH1_VOTES");
        self.fork.appended.push(vote);
    }

    /// Voting-period boundary: drop every effective vote.
    #[inline]
    pub fn clear(&mut self) {
        self.fork.resets += 1;
        self.fork.appended.clear();
    }
}
