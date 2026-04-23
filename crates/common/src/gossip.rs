use std::fmt;

use crate::{
    Error,
    ssz_view::{
        AttesterSlashingView, BlobSidecarView, DataColumnSidecarView,
        LightClientFinalityUpdateView, LightClientOptimisticUpdateView, ProposerSlashingView,
        SignedAggregateAndProofView, SignedBeaconBlockView, SignedBlsToExecutionChangeView,
        SignedContributionAndProofView, SignedVoluntaryExitView, SingleAttestationView, SszView,
        SyncCommitteeView,
    },
};

mod hash;

pub use hash::{
    MESSAGE_ID_LEN, MessageId, MessageIdHasher, msg_id_invalid_snappy, msg_id_valid_snappy,
};

/// Eth2 gossipsub topic name. Wire topic is
/// `/eth2/{fork_digest_hex}/{name}/ssz_snappy`; this enum covers the `{name}`
/// portion. Subnet ids travel inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, u8)]
pub enum GossipTopic {
    BeaconBlock,
    BeaconAggregateAndProof,
    BeaconAttestation(u64),
    VoluntaryExit,
    ProposerSlashing,
    AttesterSlashing,
    SyncCommitteeContributionAndProof,
    SyncCommittee(u64),
    LightClientFinalityUpdate,
    LightClientOptimisticUpdate,
    BlsToExecutionChange,
    BlobSidecar(u64),
    DataColumnSidecar(u64),
    ExecutionPayloadBid,
    ExecutionPayload,
    PayloadAttestationMessage,
    ProposerPreferences,
    InclusionList,
}

impl fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeaconBlock => f.write_str("beacon_block"),
            Self::BeaconAggregateAndProof => f.write_str("beacon_aggregate_and_proof"),
            Self::BeaconAttestation(id) => write!(f, "beacon_attestation_{id}"),
            Self::VoluntaryExit => f.write_str("voluntary_exit"),
            Self::ProposerSlashing => f.write_str("proposer_slashing"),
            Self::AttesterSlashing => f.write_str("attester_slashing"),
            Self::SyncCommitteeContributionAndProof => {
                f.write_str("sync_committee_contribution_and_proof")
            }
            Self::SyncCommittee(id) => write!(f, "sync_committee_{id}"),
            Self::LightClientFinalityUpdate => f.write_str("light_client_finality_update"),
            Self::LightClientOptimisticUpdate => f.write_str("light_client_optimistic_update"),
            Self::BlsToExecutionChange => f.write_str("bls_to_execution_change"),
            Self::BlobSidecar(id) => write!(f, "blob_sidecar_{id}"),
            Self::DataColumnSidecar(id) => write!(f, "data_column_sidecar_{id}"),
            Self::ExecutionPayloadBid => f.write_str("execution_payload_bid"),
            Self::ExecutionPayload => f.write_str("execution_payload"),
            Self::PayloadAttestationMessage => f.write_str("payload_attestation_message"),
            Self::ProposerPreferences => f.write_str("proposer_preferences"),
            Self::InclusionList => f.write_str("inclusion_list"),
        }
    }
}

impl From<GossipTopic> for String {
    fn from(t: GossipTopic) -> Self {
        t.to_string()
    }
}

impl GossipTopic {
    /// Format the full wire topic `/eth2/{fork_digest_hex}/{name}/ssz_snappy`.
    pub fn to_wire(&self, fork_digest_hex: &str) -> String {
        format!("/eth2/{fork_digest_hex}/{self}/ssz_snappy")
    }

    /// Parse the full wire topic `/eth2/{fork_digest_hex}/{name}/ssz_snappy`.
    /// Verifies the envelope and that the fork digest matches
    /// `fork_digest_hex`.
    pub fn from_wire(topic: &str, fork_digest_hex: &str) -> Result<Self, Error> {
        let rest = topic.strip_prefix("/eth2/").ok_or(Error::ParseTopicError)?;
        let rest = rest.strip_prefix(fork_digest_hex).ok_or(Error::ParseTopicError)?;
        let rest = rest.strip_prefix('/').ok_or(Error::ParseTopicError)?;
        let name = rest.strip_suffix("/ssz_snappy").ok_or(Error::ParseTopicError)?;
        Self::try_from(name)
    }

    /// View marker for topics whose payload is an ssz_view type.
    pub fn view(&self) -> SszView {
        match self {
            Self::BeaconBlock => SszView::SignedBeaconBlock(SignedBeaconBlockView),
            Self::BeaconAggregateAndProof => {
                SszView::SignedAggregateAndProof(SignedAggregateAndProofView)
            }
            Self::BeaconAttestation(_) => SszView::SingleAttestation(SingleAttestationView),
            Self::VoluntaryExit => SszView::SignedVoluntaryExit(SignedVoluntaryExitView),
            Self::ProposerSlashing => SszView::ProposerSlashing(ProposerSlashingView),
            Self::AttesterSlashing => SszView::AttesterSlashing(AttesterSlashingView),
            Self::SyncCommitteeContributionAndProof => {
                SszView::SignedContributionAndProof(SignedContributionAndProofView)
            }
            Self::SyncCommittee(_) => SszView::SyncCommittee(SyncCommitteeView),
            Self::BlsToExecutionChange => {
                SszView::SignedBlsToExecutionChange(SignedBlsToExecutionChangeView)
            }
            Self::BlobSidecar(_) => SszView::BlobSidecar(BlobSidecarView),
            Self::DataColumnSidecar(_) => SszView::DataColumnSidecar(DataColumnSidecarView),
            Self::LightClientFinalityUpdate => {
                SszView::LightClientFinalityUpdate(LightClientFinalityUpdateView)
            }
            Self::LightClientOptimisticUpdate => {
                SszView::LightClientOptimisticUpdate(LightClientOptimisticUpdateView)
            }
            // Post-Fulu
            Self::ExecutionPayloadBid |
            Self::ExecutionPayload |
            Self::PayloadAttestationMessage |
            Self::ProposerPreferences |
            Self::InclusionList => unimplemented!(),
        }
    }
}

impl TryFrom<&str> for GossipTopic {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // Match exact strings first; prefix checks only fire on non-match, so
        // `sync_committee_contribution_and_proof` is never mis-parsed as the
        // `sync_committee_{id}` subnet form.
        Ok(match s {
            "beacon_block" => Self::BeaconBlock,
            "beacon_aggregate_and_proof" => Self::BeaconAggregateAndProof,
            "voluntary_exit" => Self::VoluntaryExit,
            "proposer_slashing" => Self::ProposerSlashing,
            "attester_slashing" => Self::AttesterSlashing,
            "sync_committee_contribution_and_proof" => Self::SyncCommitteeContributionAndProof,
            "light_client_finality_update" => Self::LightClientFinalityUpdate,
            "light_client_optimistic_update" => Self::LightClientOptimisticUpdate,
            "bls_to_execution_change" => Self::BlsToExecutionChange,
            "execution_payload_bid" => Self::ExecutionPayloadBid,
            "execution_payload" => Self::ExecutionPayload,
            "payload_attestation_message" => Self::PayloadAttestationMessage,
            "proposer_preferences" => Self::ProposerPreferences,
            "inclusion_list" => Self::InclusionList,
            other => {
                if let Some(id) = other.strip_prefix("beacon_attestation_") {
                    Self::BeaconAttestation(id.parse().map_err(|_| Error::ParseTopicError)?)
                } else if let Some(id) = other.strip_prefix("sync_committee_") {
                    Self::SyncCommittee(id.parse().map_err(|_| Error::ParseTopicError)?)
                } else if let Some(id) = other.strip_prefix("data_column_sidecar_") {
                    Self::DataColumnSidecar(id.parse().map_err(|_| Error::ParseTopicError)?)
                } else if let Some(id) = other.strip_prefix("blob_sidecar_") {
                    Self::BlobSidecar(id.parse().map_err(|_| Error::ParseTopicError)?)
                } else {
                    return Err(Error::ParseTopicError);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_unit() {
        for t in [
            GossipTopic::BeaconBlock,
            GossipTopic::BeaconAggregateAndProof,
            GossipTopic::VoluntaryExit,
            GossipTopic::ProposerSlashing,
            GossipTopic::AttesterSlashing,
            GossipTopic::SyncCommitteeContributionAndProof,
            GossipTopic::LightClientFinalityUpdate,
            GossipTopic::LightClientOptimisticUpdate,
            GossipTopic::BlsToExecutionChange,
            GossipTopic::ExecutionPayloadBid,
            GossipTopic::ExecutionPayload,
            GossipTopic::PayloadAttestationMessage,
            GossipTopic::ProposerPreferences,
            GossipTopic::InclusionList,
        ] {
            let s: String = t.into();
            assert_eq!(GossipTopic::try_from(s.as_str()).unwrap(), t);
        }
    }

    #[test]
    fn roundtrip_subnets() {
        for i in [0u64, 1, 63, 127] {
            for t in [
                GossipTopic::BeaconAttestation(i),
                GossipTopic::SyncCommittee(i),
                GossipTopic::BlobSidecar(i),
                GossipTopic::DataColumnSidecar(i),
            ] {
                let s: String = t.into();
                assert_eq!(GossipTopic::try_from(s.as_str()).unwrap(), t);
            }
        }
    }

    #[test]
    fn sync_committee_disambiguation() {
        // The contribution topic must not be misparsed as subnet form.
        let t = GossipTopic::SyncCommitteeContributionAndProof;
        let s: String = t.into();
        assert_eq!(GossipTopic::try_from(s.as_str()).unwrap(), t);
    }

    #[test]
    fn unknown_rejects() {
        assert!(GossipTopic::try_from("nope").is_err());
        assert!(GossipTopic::try_from("beacon_attestation_").is_err());
        assert!(GossipTopic::try_from("beacon_attestation_abc").is_err());
    }

    #[test]
    fn wire_roundtrip() {
        let fd = "abcd1234";
        for t in [
            GossipTopic::BeaconBlock,
            GossipTopic::BeaconAttestation(17),
            GossipTopic::DataColumnSidecar(127),
        ] {
            let w = t.to_wire(fd);
            assert_eq!(GossipTopic::from_wire(&w, fd).unwrap(), t);
        }
    }

    #[test]
    fn wire_rejects_bad_envelope() {
        let fd = "abcd1234";
        assert!(GossipTopic::from_wire("beacon_block", fd).is_err());
        assert!(GossipTopic::from_wire("/eth2/abcd1234/beacon_block", fd).is_err());
        assert!(
            GossipTopic::from_wire("/eth2/deadbeef/beacon_block/ssz_snappy", fd).is_err(),
            "fork digest mismatch must fail"
        );
    }
}
