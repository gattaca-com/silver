use std::{error::Error, fmt};

use silver_common::ssz_view::SINGLE_ATT_SIZE;

const LOCK_COMMAND_TAG: u8 = 0;
const ADVANCE_MINIMUM_SLOT_TAG: u8 = 1;
const ENCODED_LOCK_COMMAND_LEN: usize = 1 + 48 + 8 + 8 + SINGLE_ATT_SIZE;
const ENCODED_ADVANCE_MINIMUM_SLOT_LEN: usize = 1 + 8;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct AttestationKey {
    pub validator_pubkey: [u8; 48],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(super) enum ReplicatedCommand {
    Lock(AttestationLockCommand),
    AdvanceMinimumSlot(u64),
}

impl ReplicatedCommand {
    pub(super) fn encode(self) -> Vec<u8> {
        match self {
            Self::Lock(command) => {
                let mut encoded = Vec::with_capacity(ENCODED_LOCK_COMMAND_LEN);
                encoded.push(LOCK_COMMAND_TAG);
                encoded.extend_from_slice(&command.key.validator_pubkey);
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
        }
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, CommandDecodeError> {
        let Some((&tag, payload)) = encoded.split_first() else {
            return Err(CommandDecodeError::Empty);
        };

        match tag {
            LOCK_COMMAND_TAG => {
                if encoded.len() != ENCODED_LOCK_COMMAND_LEN {
                    return Err(CommandDecodeError::InvalidLength {
                        tag,
                        expected: ENCODED_LOCK_COMMAND_LEN,
                        actual: encoded.len(),
                    });
                }

                let validator_pubkey = payload[..48].try_into().expect("slice is 48 bytes");
                let slot =
                    u64::from_le_bytes(payload[48..56].try_into().expect("slice is 8 bytes"));
                let subnet =
                    u64::from_le_bytes(payload[56..64].try_into().expect("slice is 8 bytes"));
                let ssz = payload[64..64 + SINGLE_ATT_SIZE]
                    .try_into()
                    .expect("slice is one single attestation");

                Ok(Self::Lock(AttestationLockCommand {
                    key: AttestationKey { validator_pubkey, slot },
                    subnet,
                    ssz,
                }))
            }
            ADVANCE_MINIMUM_SLOT_TAG => {
                if encoded.len() != ENCODED_ADVANCE_MINIMUM_SLOT_LEN {
                    return Err(CommandDecodeError::InvalidLength {
                        tag,
                        expected: ENCODED_ADVANCE_MINIMUM_SLOT_LEN,
                        actual: encoded.len(),
                    });
                }

                let slot = u64::from_le_bytes(payload.try_into().expect("slice is 8 bytes"));
                Ok(Self::AdvanceMinimumSlot(slot))
            }
            _ => Err(CommandDecodeError::UnknownTag(tag)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandDecodeError {
    Empty,
    UnknownTag(u8),
    InvalidLength { tag: u8, expected: usize, actual: usize },
}

impl fmt::Display for CommandDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty Raft command"),
            Self::UnknownTag(tag) => write!(f, "unknown Raft command tag {tag}"),
            Self::InvalidLength { tag, expected, actual } => {
                write!(f, "Raft command tag {tag} has length {actual}, expected {expected}")
            }
        }
    }
}

impl Error for CommandDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(slot: u64, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; SINGLE_ATT_SIZE];
        ssz[0] = root;
        AttestationLockCommand {
            key: AttestationKey { validator_pubkey: [7; 48], slot },
            subnet: u64::from(root),
            ssz,
        }
    }

    #[test]
    fn replicated_commands_round_trip() {
        for command in
            [ReplicatedCommand::Lock(command(42, 3)), ReplicatedCommand::AdvanceMinimumSlot(37)]
        {
            assert_eq!(ReplicatedCommand::decode(&command.encode()), Ok(command));
        }
    }
}
