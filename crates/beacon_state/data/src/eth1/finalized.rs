use std::io::{self, Write};

use flux::utils::ArrayVec;

use super::delta::Eth1VotesDelta;
use crate::{
    DecomposeError,
    decompose::common::{ETH1_DATA_SSZ_SIZE, Offsets},
    encode::write_eth1_data,
    merkle::MerkleStack,
    types::{Eth1Data, MAX_ETH1_VOTES},
};

/// Finalized eth1 vote list. Inline fixed-capacity storage: the spec bound is
/// structural, and the buffer never moves, so the checkpoint encoder's
/// cross-thread read can't dangle — torn bytes are discarded by its version
/// re-check.
///
/// `hasher` accumulates the votes' element roots in order, so a fork's delta
/// starts from it instead of re-folding the whole list.
pub struct Eth1Votes {
    votes: ArrayVec<Eth1Data, MAX_ETH1_VOTES>,
    hasher: MerkleStack,
}

impl Default for Eth1Votes {
    fn default() -> Self {
        Self { votes: ArrayVec::new(), hasher: MerkleStack::new(MAX_ETH1_VOTES) }
    }
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

    #[inline]
    pub(super) fn hasher(&self) -> MerkleStack {
        self.hasher
    }

    /// Seed one vote — checkpoint decompose only.
    #[inline]
    pub(crate) fn push(&mut self, vote: Eth1Data) {
        self.hasher.push(vote.leaf());
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
    /// votes, and adopt its hasher — a delta folds exactly the effective vote
    /// sequence that promoting makes this list's, so nothing is re-hashed.
    pub(super) fn promote(&mut self, delta: &Eth1VotesDelta) {
        delta.promote_into(&mut self.votes);
        self.hasher = delta.hasher();
    }
}

impl Eth1Votes {
    pub(crate) fn from_ssz(ssz: &[u8], o: &Offsets) -> Result<Self, DecomposeError> {
        let votes_bytes = &ssz[o.eth1_votes..o.validators];
        if !votes_bytes.len().is_multiple_of(ETH1_DATA_SSZ_SIZE) {
            return Err(DecomposeError::Eth1VotesLenNotMultiple { len: votes_bytes.len() });
        }
        let vote_count = votes_bytes.len() / ETH1_DATA_SSZ_SIZE;
        if vote_count > MAX_ETH1_VOTES {
            return Err(DecomposeError::TooManyEth1Votes { n: vote_count, max: MAX_ETH1_VOTES });
        }
        let mut votes = Self::default();
        for i in 0..vote_count {
            votes.push(Eth1Data::from_ssz(&votes_bytes[i * ETH1_DATA_SSZ_SIZE..]));
        }
        Ok(votes)
    }
}
