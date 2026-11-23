use silver_beacon_state_data::Epoch;
use silver_ssz::ssz_view::{ATTESTATION_DATA_SIZE, AttestationDataView, INDEXED_ATTESTATION_FIXED};

use crate::Offence;

pub(crate) const SIGNED_VOTE_SIZE: usize = ATTESTATION_DATA_SIZE + 96;

/// `AttestationData` and its signature.
#[derive(Clone, Copy)]
pub(crate) struct SignedVote(pub(crate) [u8; SIGNED_VOTE_SIZE]);

impl SignedVote {
    pub(crate) fn new(data: AttestationDataView, signature: &[u8; 96]) -> Self {
        let mut vote = [0u8; SIGNED_VOTE_SIZE];
        vote[..ATTESTATION_DATA_SIZE].copy_from_slice(data.as_bytes());
        vote[ATTESTATION_DATA_SIZE..].copy_from_slice(signature);
        Self(vote)
    }

    pub(crate) fn data(&self) -> AttestationDataView<'_> {
        AttestationDataView::new(self.0[..ATTESTATION_DATA_SIZE].try_into().unwrap())
    }
}

/// A verified vote and its signers, sorted: an `IndexedAttestation`.
pub(crate) struct IndexedVote {
    pub(crate) vote: SignedVote,
    pub(crate) signers: Vec<u32>,
}

impl IndexedVote {
    fn encoded_len(&self) -> usize {
        INDEXED_ATTESTATION_FIXED + 8 * self.signers.len()
    }

    fn encode_into(&self, ssz: &mut [u8]) {
        let (fixed, indices) = ssz.split_at_mut(INDEXED_ATTESTATION_FIXED);
        let (offset, signed) = fixed.split_at_mut(4);
        offset.copy_from_slice(&(INDEXED_ATTESTATION_FIXED as u32).to_le_bytes());
        signed.copy_from_slice(&self.vote.0);
        for (index, &signer) in indices.chunks_exact_mut(8).zip(&self.signers) {
            index.copy_from_slice(&u64::from(signer).to_le_bytes());
        }
    }
}

/// Two verified votes; their common signers committed the offence.
pub struct AttesterProof {
    pub offence: Offence,
    first: IndexedVote,
    second: IndexedVote,
}

impl AttesterProof {
    pub(crate) fn new(offence: Offence, first: IndexedVote, second: IndexedVote) -> Self {
        debug_assert!([&first, &second].iter().all(|side| side.signers.is_sorted()));
        Self { offence, first, second }
    }

    pub fn offenders(&self) -> impl Iterator<Item = u64> + '_ {
        let second = &self.second.signers;
        let common = self.first.signers.iter().filter(|index| second.binary_search(index).is_ok());
        common.map(|&index| u64::from(index))
    }

    pub fn slashing_len(&self) -> usize {
        8 + self.first.encoded_len() + self.second.encoded_len()
    }

    /// SSZ `AttesterSlashing`, filling `ssz` of `slashing_len()` bytes.
    pub fn write_slashing(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.slashing_len());
        let second_at = 8 + self.first.encoded_len();
        ssz[..4].copy_from_slice(&8u32.to_le_bytes());
        ssz[4..8].copy_from_slice(&(second_at as u32).to_le_bytes());
        self.first.encode_into(&mut ssz[8..second_at]);
        self.second.encode_into(&mut ssz[second_at..]);
    }

    pub(crate) fn verifies_under(&self, verifiable: impl Fn(Epoch) -> bool) -> bool {
        [&self.first, &self.second].iter().all(|side| verifiable(side.vote.data().target_epoch()))
    }
}
