use std::fmt;

use raft::eraftpb::{ConfChangeV2, Entry, EntryType};
use silver_common::ssz_view::SINGLE_ATT_SIZE;

use super::{
    admission::SlashingAdmission,
    membership::{MEMBER_ADDRESS_LEN, MemberAddress, MemberRecords},
    node::ProposalId,
    wire::decode_membership_change,
};

const LOCK_COMMAND_TAG: u8 = 0;
const ADVANCE_MINIMUM_SLOT_TAG: u8 = 1;
const BLOCK_LOCK_TAG: u8 = 2;
const ANNOUNCE_ADDRESS_TAG: u8 = 3;
const ENCODED_LOCK_COMMAND_LEN: usize = 1 + 8 + 8 + 8 + SINGLE_ATT_SIZE;
const ENCODED_ADVANCE_MINIMUM_SLOT_LEN: usize = 1 + 8;
const ENCODED_BLOCK_LOCK_LEN: usize = 1 + 8 + 8 + 96;
const ENCODED_ANNOUNCE_ADDRESS_LEN: usize = 1 + 8 + MEMBER_ADDRESS_LEN;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct AttestationKey {
    pub attester_index: u64,
    pub slot: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AttestationLockCommand {
    pub key: AttestationKey,
    pub subnet: u64,
    /// Complete signed attestation selected by Raft. Validation deliberately
    /// happens only after this command commits.
    pub ssz: [u8; SINGLE_ATT_SIZE],
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct BlockKey {
    pub proposer_index: u64,
    pub slot: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockLockCommand {
    pub key: BlockKey,
    /// BLS signing is deterministic, so the signature identifies the signed
    /// block without hashing it.
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(super) enum ReplicatedCommand {
    Lock(AttestationLockCommand),
    AdvanceMinimumSlot(u64),
    BlockLock(BlockLockCommand),
    AnnounceAddress { node_id: u64, address: MemberAddress },
}

impl ReplicatedCommand {
    pub(super) fn encode(self) -> Vec<u8> {
        match self {
            Self::Lock(command) => {
                let mut encoded = Vec::with_capacity(ENCODED_LOCK_COMMAND_LEN);
                encoded.push(LOCK_COMMAND_TAG);
                encoded.extend_from_slice(&command.key.attester_index.to_le_bytes());
                encoded.extend_from_slice(&command.key.slot.to_le_bytes());
                encoded.extend_from_slice(&command.subnet.to_le_bytes());
                encoded.extend_from_slice(&command.ssz);
                encoded
            }
            Self::AdvanceMinimumSlot(slot) => {
                let mut encoded = Vec::with_capacity(ENCODED_ADVANCE_MINIMUM_SLOT_LEN);
                encoded.push(ADVANCE_MINIMUM_SLOT_TAG);
                encoded.extend_from_slice(&slot.to_le_bytes());
                encoded
            }
            Self::BlockLock(command) => {
                let mut encoded = Vec::with_capacity(ENCODED_BLOCK_LOCK_LEN);
                encoded.push(BLOCK_LOCK_TAG);
                encoded.extend_from_slice(&command.key.proposer_index.to_le_bytes());
                encoded.extend_from_slice(&command.key.slot.to_le_bytes());
                encoded.extend_from_slice(&command.signature);
                encoded
            }
            Self::AnnounceAddress { node_id, address } => {
                let mut encoded = Vec::with_capacity(ENCODED_ANNOUNCE_ADDRESS_LEN);
                encoded.push(ANNOUNCE_ADDRESS_TAG);
                encoded.extend_from_slice(&node_id.to_le_bytes());
                address.encode(&mut encoded);
                encoded
            }
        }
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, EntryError> {
        let Some((&tag, payload)) = encoded.split_first() else {
            return Err(EntryError::Empty);
        };
        let expected = match tag {
            LOCK_COMMAND_TAG => ENCODED_LOCK_COMMAND_LEN,
            ADVANCE_MINIMUM_SLOT_TAG => ENCODED_ADVANCE_MINIMUM_SLOT_LEN,
            BLOCK_LOCK_TAG => ENCODED_BLOCK_LOCK_LEN,
            ANNOUNCE_ADDRESS_TAG => ENCODED_ANNOUNCE_ADDRESS_LEN,
            _ => return Err(EntryError::UnknownTag(tag)),
        };
        if encoded.len() != expected {
            return Err(EntryError::InvalidLength { tag, expected, actual: encoded.len() });
        }

        let u64_at = |offset: usize| {
            u64::from_le_bytes(payload[offset..offset + 8].try_into().expect("slice is 8 bytes"))
        };
        Ok(match tag {
            LOCK_COMMAND_TAG => Self::Lock(AttestationLockCommand {
                key: AttestationKey { attester_index: u64_at(0), slot: u64_at(8) },
                subnet: u64_at(16),
                ssz: payload[24..].try_into().expect("slice is one single attestation"),
            }),
            BLOCK_LOCK_TAG => Self::BlockLock(BlockLockCommand {
                key: BlockKey { proposer_index: u64_at(0), slot: u64_at(8) },
                signature: payload[16..].try_into().expect("slice is one signature"),
            }),
            ANNOUNCE_ADDRESS_TAG => Self::AnnounceAddress {
                node_id: u64_at(0),
                address: MemberAddress::decode(
                    payload[8..].try_into().expect("slice is one member address"),
                )
                .map_err(|_| EntryError::InvalidAddress)?,
            },
            _ => Self::AdvanceMinimumSlot(u64_at(0)),
        })
    }
}

/// A log entry's command, with the proposal it answers. The leader proposes
/// `AdvanceMinimumSlot` and membership changes itself, so they carry none.
#[allow(clippy::large_enum_variant)]
pub(super) enum DecodedEntry<'a> {
    Lock(AttestationLockCommand, ProposalId),
    BlockLock(BlockLockCommand, ProposalId),
    AdvanceMinimumSlot(u64),
    AnnounceAddress {
        node_id: u64,
        address: MemberAddress,
        proposal_id: ProposalId,
    },
    /// A new leader's first entry.
    Empty,
    /// Empty `data` is the change that leaves a joint config. `added`, in the
    /// entry context, are the addresses of learners it adds.
    MembershipChange {
        change: ConfChangeV2,
        added: MemberRecords<'a>,
    },
}

impl<'a> DecodedEntry<'a> {
    pub(super) fn decode(entry: &'a Entry) -> Result<Self, EntryError> {
        match entry.get_entry_type() {
            EntryType::EntryNormal if entry.data.is_empty() => return Ok(Self::Empty),
            EntryType::EntryNormal => {}
            EntryType::EntryConfChangeV2 => {
                let change = decode_membership_change(&entry.data)
                    .map_err(|_| EntryError::InvalidMembershipChange)?;
                let added = MemberRecords::parse_context(&entry.context)
                    .map_err(|_| EntryError::InvalidMembershipChange)?;
                return Ok(Self::MembershipChange { change, added });
            }
            entry_type => return Err(EntryError::UnsupportedType(entry_type)),
        }
        let proposal_id =
            || ProposalId::decode(&entry.context).map_err(EntryError::ProposalContextLength);
        Ok(match ReplicatedCommand::decode(&entry.data)? {
            ReplicatedCommand::Lock(command) => Self::Lock(command, proposal_id()?),
            ReplicatedCommand::BlockLock(command) => Self::BlockLock(command, proposal_id()?),
            ReplicatedCommand::AdvanceMinimumSlot(slot) => Self::AdvanceMinimumSlot(slot),
            ReplicatedCommand::AnnounceAddress { node_id, address } => {
                Self::AnnounceAddress { node_id, address, proposal_id: proposal_id()? }
            }
        })
    }

    /// The earliest wall slot at which a correct clock proposes this entry.
    pub(super) fn earliest_wall_slot(&self) -> u64 {
        match self {
            Self::Lock(command, _) => command.key.slot,
            Self::BlockLock(command, _) => command.key.slot,
            Self::AdvanceMinimumSlot(floor) => SlashingAdmission::wall_slot_for_floor(*floor),
            Self::AnnounceAddress { .. } | Self::Empty | Self::MembershipChange { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    UnsupportedType(EntryType),
    InvalidMembershipChange,
    InvalidAddress,
    Empty,
    UnknownTag(u8),
    InvalidLength { tag: u8, expected: usize, actual: usize },
    ProposalContextLength(usize),
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedType(entry_type) => write!(f, "unsupported entry type {entry_type:?}"),
            Self::InvalidMembershipChange => f.write_str("undecodable Raft membership change"),
            Self::InvalidAddress => f.write_str("invalid cluster member address"),
            Self::Empty => f.write_str("empty Raft command"),
            Self::UnknownTag(tag) => write!(f, "unknown Raft command tag {tag}"),
            Self::InvalidLength { tag, expected, actual } => {
                write!(f, "Raft command tag {tag} has length {actual}, expected {expected}")
            }
            Self::ProposalContextLength(actual) => {
                write!(f, "proposal context has length {actual}, expected 16 or 32")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::membership::test_address;

    fn command(slot: u64, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; SINGLE_ATT_SIZE];
        ssz[0] = root;
        AttestationLockCommand {
            key: AttestationKey { attester_index: 7, slot },
            subnet: u64::from(root),
            ssz,
        }
    }

    #[test]
    fn replicated_commands_round_trip() {
        let block =
            BlockLockCommand { key: BlockKey { proposer_index: 5, slot: 42 }, signature: [9; 96] };
        for command in [
            ReplicatedCommand::Lock(command(42, 3)),
            ReplicatedCommand::AdvanceMinimumSlot(37),
            ReplicatedCommand::BlockLock(block),
            ReplicatedCommand::AnnounceAddress { node_id: 4, address: test_address(4) },
        ] {
            assert_eq!(ReplicatedCommand::decode(&command.encode()), Ok(command));
        }
    }
}
