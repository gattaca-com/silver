use std::fmt;

use crate::{
    Error,
    ssz_view::{
        ATTESTER_SLASHING_MAX, ATTESTER_SLASHING_MIN, AttesterSlashingView,
        DATA_COLUMN_SIDECAR_GLOAS_MIN, DATA_COLUMN_SIDECAR_MAX, DataColumnSidecarFuluView,
        LIGHT_CLIENT_FINALITY_UPDATE_MAX, LIGHT_CLIENT_FINALITY_UPDATE_MIN,
        LIGHT_CLIENT_OPTIMISTIC_UPDATE_MAX, LIGHT_CLIENT_OPTIMISTIC_UPDATE_MIN,
        LightClientFinalityUpdateView, LightClientOptimisticUpdateView, MAX_PAYLOAD_SIZE,
        PAYLOAD_ATTESTATION_MESSAGE_SIZE, PROPOSER_SLASHING_SIZE, PayloadAttestationMessageView,
        ProposerSlashingView, SIGNED_AGG_PROOF_MAX, SIGNED_AGG_PROOF_MIN, SIGNED_BEACON_BLOCK_MIN,
        SIGNED_BLS_CHANGE_SIZE, SIGNED_CONTRIBUTION_AND_PROOF_SIZE,
        SIGNED_EXECUTION_PAYLOAD_BID_MAX, SIGNED_EXECUTION_PAYLOAD_BID_MIN,
        SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN, SIGNED_PROPOSER_PREFERENCES_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SYNC_COMMITTEE_MSG_SIZE,
        SignedAggregateAndProofView, SignedBeaconBlockView, SignedBlsToExecutionChangeView,
        SignedContributionAndProofView, SignedExecutionPayloadBidView,
        SignedExecutionPayloadEnvelopeView, SignedProposerPreferencesView, SignedVoluntaryExitView,
        SingleAttestationView, SszView, SyncCommitteeView,
    },
};

mod hash;

pub use hash::{
    MESSAGE_ID_LEN, MessageId, MessageIdHasher, msg_id_invalid_snappy, msg_id_valid_snappy,
};

pub const MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE: usize = MAX_PAYLOAD_SIZE;
pub const MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE: usize =
    32 + MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE + MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE / 6;
pub const MAX_GOSSIP_FRAME_SIZE: usize = MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE + 1024;

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
    DataColumnSidecar(u64),
    ExecutionPayloadBid,
    ExecutionPayload,
    PayloadAttestationMessage,
    ProposerPreferences,
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
            Self::DataColumnSidecar(id) => write!(f, "data_column_sidecar_{id}"),
            Self::ExecutionPayloadBid => f.write_str("execution_payload_bid"),
            Self::ExecutionPayload => f.write_str("execution_payload"),
            Self::PayloadAttestationMessage => f.write_str("payload_attestation_message"),
            Self::ProposerPreferences => f.write_str("proposer_preferences"),
        }
    }
}

impl From<GossipTopic> for String {
    fn from(t: GossipTopic) -> Self {
        t.to_string()
    }
}

pub const ATTESTATION_SUBNETS: usize = 64;
pub const SYNC_COMMITTEE_SUBNETS: usize = 4;

const ATTESTATION_BASE: usize = 2;
const VOLUNTARY_EXIT_SLOT: usize = ATTESTATION_BASE + ATTESTATION_SUBNETS;
const SYNC_CONTRIB_SLOT: usize = VOLUNTARY_EXIT_SLOT + 3;
const SYNC_COMMITTEE_BASE: usize = SYNC_CONTRIB_SLOT + 1;
const LC_FINALITY_SLOT: usize = SYNC_COMMITTEE_BASE + SYNC_COMMITTEE_SUBNETS;
const DATA_COLUMN_BASE: usize = LC_FINALITY_SLOT + 3;
const EXECUTION_BID_SLOT: usize = DATA_COLUMN_BASE + crate::NUMBER_OF_CUSTODY_GROUPS as usize;

/// Dense per-topic slot space for counters/telemetry: subnet topics get one
/// slot per subnet, everything else one slot. The layout is fixed so
/// observers label by the same arithmetic (`gossip_topic_for_counter_slot`).
pub const GOSSIP_TOPIC_COUNTER_SLOTS: usize = EXECUTION_BID_SLOT + 4;

/// Inverse of `GossipTopic::counter_slot`, for observer-side labelling.
pub fn gossip_topic_for_counter_slot(slot: usize) -> Option<GossipTopic> {
    Some(match slot {
        0 => GossipTopic::BeaconBlock,
        1 => GossipTopic::BeaconAggregateAndProof,
        s if s < VOLUNTARY_EXIT_SLOT => {
            GossipTopic::BeaconAttestation((s - ATTESTATION_BASE) as u64)
        }
        s if s == VOLUNTARY_EXIT_SLOT => GossipTopic::VoluntaryExit,
        s if s == VOLUNTARY_EXIT_SLOT + 1 => GossipTopic::ProposerSlashing,
        s if s == VOLUNTARY_EXIT_SLOT + 2 => GossipTopic::AttesterSlashing,
        s if s == SYNC_CONTRIB_SLOT => GossipTopic::SyncCommitteeContributionAndProof,
        s if s < LC_FINALITY_SLOT => GossipTopic::SyncCommittee((s - SYNC_COMMITTEE_BASE) as u64),
        s if s == LC_FINALITY_SLOT => GossipTopic::LightClientFinalityUpdate,
        s if s == LC_FINALITY_SLOT + 1 => GossipTopic::LightClientOptimisticUpdate,
        s if s == LC_FINALITY_SLOT + 2 => GossipTopic::BlsToExecutionChange,
        s if s < EXECUTION_BID_SLOT => {
            GossipTopic::DataColumnSidecar((s - DATA_COLUMN_BASE) as u64)
        }
        s if s == EXECUTION_BID_SLOT => GossipTopic::ExecutionPayloadBid,
        s if s == EXECUTION_BID_SLOT + 1 => GossipTopic::ExecutionPayload,
        s if s == EXECUTION_BID_SLOT + 2 => GossipTopic::PayloadAttestationMessage,
        s if s == EXECUTION_BID_SLOT + 3 => GossipTopic::ProposerPreferences,
        _ => return None,
    })
}

impl GossipTopic {
    /// Format the full wire topic `/eth2/{fork_digest_hex}/{name}/ssz_snappy`.
    pub fn to_wire(&self, fork_digest_hex: &str) -> String {
        format!("/eth2/{fork_digest_hex}/{self}/ssz_snappy")
    }

    /// Slot in the dense counter space; out-of-range subnet ids clamp to
    /// their kind's last slot.
    pub fn counter_slot(self) -> usize {
        fn subnet(base: usize, id: u64, count: usize) -> usize {
            base + (id as usize).min(count - 1)
        }
        match self {
            Self::BeaconBlock => 0,
            Self::BeaconAggregateAndProof => 1,
            Self::BeaconAttestation(id) => subnet(ATTESTATION_BASE, id, ATTESTATION_SUBNETS),
            Self::VoluntaryExit => VOLUNTARY_EXIT_SLOT,
            Self::ProposerSlashing => VOLUNTARY_EXIT_SLOT + 1,
            Self::AttesterSlashing => VOLUNTARY_EXIT_SLOT + 2,
            Self::SyncCommitteeContributionAndProof => SYNC_CONTRIB_SLOT,
            Self::SyncCommittee(id) => subnet(SYNC_COMMITTEE_BASE, id, SYNC_COMMITTEE_SUBNETS),
            Self::LightClientFinalityUpdate => LC_FINALITY_SLOT,
            Self::LightClientOptimisticUpdate => LC_FINALITY_SLOT + 1,
            Self::BlsToExecutionChange => LC_FINALITY_SLOT + 2,
            Self::DataColumnSidecar(id) => {
                subnet(DATA_COLUMN_BASE, id, crate::NUMBER_OF_CUSTODY_GROUPS as usize)
            }
            Self::ExecutionPayloadBid => EXECUTION_BID_SLOT,
            Self::ExecutionPayload => EXECUTION_BID_SLOT + 1,
            Self::PayloadAttestationMessage => EXECUTION_BID_SLOT + 2,
            Self::ProposerPreferences => EXECUTION_BID_SLOT + 3,
        }
    }

    pub fn max_uncompressed_size(self) -> usize {
        match self {
            Self::BeaconBlock | Self::ExecutionPayload => MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE,
            Self::BeaconAggregateAndProof => SIGNED_AGG_PROOF_MAX,
            Self::BeaconAttestation(_) => SINGLE_ATT_SIZE,
            Self::VoluntaryExit => SIGNED_VOLUNTARY_EXIT_SIZE,
            Self::ProposerSlashing => PROPOSER_SLASHING_SIZE,
            Self::AttesterSlashing => ATTESTER_SLASHING_MAX,
            Self::SyncCommitteeContributionAndProof => SIGNED_CONTRIBUTION_AND_PROOF_SIZE,
            Self::SyncCommittee(_) => SYNC_COMMITTEE_MSG_SIZE,
            Self::LightClientFinalityUpdate => LIGHT_CLIENT_FINALITY_UPDATE_MAX,
            Self::LightClientOptimisticUpdate => LIGHT_CLIENT_OPTIMISTIC_UPDATE_MAX,
            Self::BlsToExecutionChange => SIGNED_BLS_CHANGE_SIZE,
            Self::DataColumnSidecar(_) => DATA_COLUMN_SIDECAR_MAX,
            Self::ExecutionPayloadBid => SIGNED_EXECUTION_PAYLOAD_BID_MAX,
            Self::PayloadAttestationMessage => PAYLOAD_ATTESTATION_MESSAGE_SIZE,
            Self::ProposerPreferences => SIGNED_PROPOSER_PREFERENCES_SIZE,
        }
    }

    pub fn min_uncompressed_size(self) -> usize {
        match self {
            Self::BeaconBlock => SIGNED_BEACON_BLOCK_MIN,
            Self::ExecutionPayload => SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN,
            Self::BeaconAggregateAndProof => SIGNED_AGG_PROOF_MIN,
            Self::BeaconAttestation(_) => SINGLE_ATT_SIZE,
            Self::VoluntaryExit => SIGNED_VOLUNTARY_EXIT_SIZE,
            Self::ProposerSlashing => PROPOSER_SLASHING_SIZE,
            Self::AttesterSlashing => ATTESTER_SLASHING_MIN,
            Self::SyncCommitteeContributionAndProof => SIGNED_CONTRIBUTION_AND_PROOF_SIZE,
            Self::SyncCommittee(_) => SYNC_COMMITTEE_MSG_SIZE,
            Self::LightClientFinalityUpdate => LIGHT_CLIENT_FINALITY_UPDATE_MIN,
            Self::LightClientOptimisticUpdate => LIGHT_CLIENT_OPTIMISTIC_UPDATE_MIN,
            Self::BlsToExecutionChange => SIGNED_BLS_CHANGE_SIZE,
            // Both sidecar layouts share the topic, and the gloas one is
            // shorter (its commitments live on the bid, not the sidecar).
            Self::DataColumnSidecar(_) => DATA_COLUMN_SIDECAR_GLOAS_MIN,
            Self::ExecutionPayloadBid => SIGNED_EXECUTION_PAYLOAD_BID_MIN,
            Self::PayloadAttestationMessage => PAYLOAD_ATTESTATION_MESSAGE_SIZE,
            Self::ProposerPreferences => SIGNED_PROPOSER_PREFERENCES_SIZE,
        }
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
            Self::DataColumnSidecar(_) => SszView::DataColumnSidecar(DataColumnSidecarFuluView),
            Self::LightClientFinalityUpdate => {
                SszView::LightClientFinalityUpdate(LightClientFinalityUpdateView)
            }
            Self::LightClientOptimisticUpdate => {
                SszView::LightClientOptimisticUpdate(LightClientOptimisticUpdateView)
            }
            Self::ExecutionPayloadBid => {
                SszView::SignedExecutionPayloadBid(SignedExecutionPayloadBidView)
            }
            Self::ExecutionPayload => {
                SszView::SignedExecutionPayloadEnvelope(SignedExecutionPayloadEnvelopeView)
            }
            Self::PayloadAttestationMessage => {
                SszView::PayloadAttestationMessage(PayloadAttestationMessageView)
            }
            Self::ProposerPreferences => {
                SszView::SignedProposerPreferences(SignedProposerPreferencesView)
            }
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
            other => {
                if let Some(id) = other.strip_prefix("beacon_attestation_") {
                    let subnet = id.parse().map_err(|_| Error::ParseTopicError)?;
                    if subnet >= 64 {
                        return Err(Error::ParseTopicError);
                    }
                    Self::BeaconAttestation(subnet)
                } else if let Some(id) = other.strip_prefix("sync_committee_") {
                    let subnet = id.parse().map_err(|_| Error::ParseTopicError)?;
                    if subnet >= 4 {
                        return Err(Error::ParseTopicError);
                    }
                    Self::SyncCommittee(subnet)
                } else if let Some(id) = other.strip_prefix("data_column_sidecar_") {
                    let subnet = id.parse().map_err(|_| Error::ParseTopicError)?;
                    if subnet >= 128 {
                        return Err(Error::ParseTopicError);
                    }
                    Self::DataColumnSidecar(subnet)
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
        ] {
            let s: String = t.into();
            assert_eq!(GossipTopic::try_from(s.as_str()).unwrap(), t);
        }
    }

    #[test]
    fn roundtrip_subnets() {
        for i in [0u64, 1, 3] {
            for t in [
                GossipTopic::BeaconAttestation(i),
                GossipTopic::SyncCommittee(i),
                GossipTopic::DataColumnSidecar(i),
            ] {
                let s: String = t.into();
                assert_eq!(GossipTopic::try_from(s.as_str()).unwrap(), t);
            }
        }

        for i in [0u64, 1, 3, 42, 63] {
            for t in [GossipTopic::BeaconAttestation(i), GossipTopic::DataColumnSidecar(i)] {
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

    #[test]
    fn counter_slots_round_trip() {
        for slot in 0..GOSSIP_TOPIC_COUNTER_SLOTS {
            let topic = gossip_topic_for_counter_slot(slot)
                .unwrap_or_else(|| panic!("slot {slot} has no topic"));
            assert_eq!(topic.counter_slot(), slot, "{topic:?}");
        }
        assert!(gossip_topic_for_counter_slot(GOSSIP_TOPIC_COUNTER_SLOTS).is_none());

        // Out-of-range subnets clamp to their kind's last slot.
        assert_eq!(
            GossipTopic::BeaconAttestation(9999).counter_slot(),
            GossipTopic::BeaconAttestation(ATTESTATION_SUBNETS as u64 - 1).counter_slot(),
        );
    }

    #[test]
    fn gossip_size_limits() {
        assert_eq!(MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE, 10_485_760);
        assert_eq!(MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE, 12_233_418);
        assert_eq!(MAX_GOSSIP_FRAME_SIZE, 12_234_442);

        assert_eq!(GossipTopic::BeaconBlock.max_uncompressed_size(), 10_485_760);
        assert_eq!(GossipTopic::BeaconAggregateAndProof.max_uncompressed_size(), 16_829);
        assert_eq!(GossipTopic::BeaconAttestation(0).max_uncompressed_size(), 240);
        assert_eq!(GossipTopic::AttesterSlashing.max_uncompressed_size(), 2_097_616);
        assert_eq!(GossipTopic::DataColumnSidecar(0).max_uncompressed_size(), 8_782_180);
    }
}
