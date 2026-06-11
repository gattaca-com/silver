use std::io::{self, Write};

use flux::utils::ArrayVec;

use super::delta::Eth1VotesDelta;
use crate::{
    encode::write_eth1_data,
    types::{Eth1Data, MAX_ETH1_VOTES},
};

/// Finalized eth1 vote list. Inline fixed-capacity storage: the spec bound is
/// structural, and the buffer never moves, so the checkpoint encoder's
/// cross-thread read can't dangle — torn bytes are discarded by its version
/// re-check.
#[derive(Default)]
pub struct Eth1Votes {
    votes: ArrayVec<Eth1Data, MAX_ETH1_VOTES>,
}

impl Eth1Votes {
    #[inline]
    pub fn len(&self) -> usize {
        self.votes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    #[inline]
    pub(super) fn as_slice(&self) -> &[Eth1Data] {
        self.votes.as_slice()
    }

    /// Seed one vote — checkpoint decompose only.
    #[inline]
    pub(crate) fn push(&mut self, vote: Eth1Data) {
        self.votes.push(vote);
    }

    /// SSZ-encode the vote list — checkpoint section body.
    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for e in self.votes.iter() {
            write_eth1_data(w, e)?;
        }
        Ok(())
    }

    /// Fold a fork's delta in: apply its voting-period clear, append its
    /// votes. The data half of finalization.
    pub(super) fn promote(&mut self, delta: &Eth1VotesDelta) {
        delta.promote_into(&mut self.votes);
    }
}
