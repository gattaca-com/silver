use silver_beacon_state_data::{Epoch, Version};
use silver_ssz::ssz_view::{ATTESTATION_DATA_SIZE, AttestationDataView, INDEXED_ATTESTATION_FIXED};

use crate::{Offence, versioned_data::VersionedData};

const SIGNATURE_END: usize = ATTESTATION_DATA_SIZE + 96;
pub(crate) const SIGNED_VOTE_SIZE: usize = SIGNATURE_END + size_of::<Version>();

/// `AttestationData`, its signature, and the fork version the signature
/// verified under.
#[derive(Clone, Copy)]
pub(crate) struct SignedVote(pub(crate) [u8; SIGNED_VOTE_SIZE]);

impl SignedVote {
    pub(crate) fn new(
        data: AttestationDataView,
        signature: &[u8; 96],
        fork_version: Version,
    ) -> Self {
        let mut vote = [0u8; SIGNED_VOTE_SIZE];
        vote[..ATTESTATION_DATA_SIZE].copy_from_slice(data.as_bytes());
        vote[ATTESTATION_DATA_SIZE..SIGNATURE_END].copy_from_slice(signature);
        vote[SIGNATURE_END..].copy_from_slice(&fork_version);
        Self(vote)
    }

    pub(crate) fn data(&self) -> AttestationDataView<'_> {
        AttestationDataView::new(self.0[..ATTESTATION_DATA_SIZE].try_into().unwrap())
    }

    fn signature(&self) -> &[u8; 96] {
        self.0[ATTESTATION_DATA_SIZE..SIGNATURE_END].try_into().unwrap()
    }

    pub(crate) fn versioned_data(&self) -> VersionedData<&[u8; ATTESTATION_DATA_SIZE]> {
        VersionedData::new(self.data().as_bytes(), self.0[SIGNATURE_END..].try_into().unwrap())
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

    fn encode_into(&self, ssz: &mut Vec<u8>) {
        ssz.extend_from_slice(&(INDEXED_ATTESTATION_FIXED as u32).to_le_bytes());
        ssz.extend_from_slice(self.vote.data().as_bytes());
        ssz.extend_from_slice(self.vote.signature());
        ssz.extend(self.signers.iter().flat_map(|&index| u64::from(index).to_le_bytes()));
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

    /// SSZ `AttesterSlashing`.
    pub fn slashing(&self) -> Vec<u8> {
        let first_len = self.first.encoded_len();
        let mut ssz = Vec::with_capacity(8 + first_len + self.second.encoded_len());
        ssz.extend_from_slice(&8u32.to_le_bytes());
        ssz.extend_from_slice(&((8 + first_len) as u32).to_le_bytes());
        self.first.encode_into(&mut ssz);
        self.second.encode_into(&mut ssz);
        ssz
    }

    pub(crate) fn verifies_under(&self, signing_version: impl Fn(Epoch) -> Version) -> bool {
        self.first.vote.versioned_data().verifies_under(&signing_version) &&
            self.second.vote.versioned_data().verifies_under(&signing_version)
    }
}
