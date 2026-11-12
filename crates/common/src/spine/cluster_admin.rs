use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::BufMut;
use flux::{type_hash_derive::TypeHash, utils::ArrayVec};

use crate::{ClusterPeerStats, Enr, PeerId};

/// raft-rs computes the commit index on the stack for up to 7 voters and
/// allocates above that. etcd, whose raft raft-rs ports, also advises at most
/// 7 members.
pub const MAX_CLUSTER_VOTERS: usize = 7;
pub const PUBLIC_KEY_LEN: usize = 33;
const SOCKET_ADDR_LEN: usize = 1 + 16 + 2;
pub const MEMBER_ADDRESS_LEN: usize = PUBLIC_KEY_LEN + SOCKET_ADDR_LEN;
/// Learners have no cap, so a listing can be cut short.
const MAX_LISTED_MEMBERS: usize = 16;

/// Where a member is dialled. Its key never changes: a new key is a new
/// member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeHash)]
#[repr(C)]
pub struct MemberAddress {
    /// Compressed secp256k1.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    #[type_hash(literal = "SocketAddr")]
    pub addr: SocketAddr,
}

impl MemberAddress {
    pub fn from_enr(enr: &Enr) -> Option<Self> {
        let addr = enr.quic4_socket().or_else(|| enr.quic6_socket())?;
        Some(Self { public_key: enr.public_key().serialize(), addr })
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_secp256k1_pubkey(&self.public_key)
    }

    pub fn encode(&self, bytes: &mut impl BufMut) {
        bytes.put_slice(&self.public_key);
        let (tag, ip) = match self.addr.ip() {
            IpAddr::V4(ip) => (4, ip.to_ipv6_compatible().octets()),
            IpAddr::V6(ip) => (6, ip.octets()),
        };
        bytes.put_u8(tag);
        bytes.put_slice(&ip);
        bytes.put_slice(&self.addr.port().to_le_bytes());
    }

    pub fn decode(bytes: &[u8; MEMBER_ADDRESS_LEN]) -> io::Result<Self> {
        let (key, addr) = bytes.split_at(PUBLIC_KEY_LEN);
        let public_key = key.try_into().expect("slice is one public key");
        let ip: [u8; 16] = addr[1..17].try_into().expect("slice is 16 bytes");
        let ip = match addr[0] {
            4 if ip[..12].iter().all(|&byte| byte == 0) => {
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
            }
            6 => IpAddr::V6(Ipv6Addr::from(ip)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid cluster member address",
                ));
            }
        };
        let port = u16::from_le_bytes(addr[17..].try_into().expect("slice is 2 bytes"));
        Ok(Self { public_key, addr: SocketAddr::new(ip, port) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeHash)]
#[repr(C, u8)]
pub enum MembershipOperation {
    /// Joins as a learner, which receives the log but does not vote.
    Add {
        node_id: u64,
        address: MemberAddress,
    },
    Promote {
        node_id: u64,
    },
    /// Swaps one voter for a caught-up learner through a joint config, so a
    /// majority of the old voters keeps committing throughout.
    Replace {
        old: u64,
        new: u64,
    },
    Remove {
        node_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeHash)]
#[repr(C, u8)]
pub enum MembershipError {
    NotClustered,
    Failed,
    Removed,
    NotLeader {
        leader_id: Option<u64>,
        #[type_hash(literal = "Option<SocketAddr>")]
        leader_addr: Option<SocketAddr>,
    },
    ChangePending,
    /// A new member starts from a snapshot, and the locks no longer fit one.
    SnapshotTooLarge,
    IdReused {
        highest_node_id: u64,
    },
    KeyInUse {
        node_id: u64,
    },
    NoAddress(u64),
    NotAMember(u64),
    NotALearner(u64),
    NotAVoter(u64),
    NotCaughtUp(u64),
    TooManyVoters,
    LeaderTargeted,
    ProposalDropped,
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotClustered => f.write_str("this node runs without a cluster"),
            Self::Failed => f.write_str("Raft processing has stopped after a failure"),
            Self::Removed => f.write_str("this node was removed from the cluster"),
            Self::NotLeader { leader_id: Some(id), leader_addr: Some(addr) } => {
                write!(f, "not the leader; node {id} at {addr} is")
            }
            Self::NotLeader { leader_id: Some(id), leader_addr: None } => {
                write!(f, "not the leader; node {id} is")
            }
            Self::NotLeader { leader_id: None, .. } => f.write_str("not the leader; none is known"),
            Self::ChangePending => f.write_str("another membership change is still in progress"),
            Self::SnapshotTooLarge => {
                f.write_str("the locks are too large for the snapshot a new member starts from")
            }
            Self::IdReused { highest_node_id } => match highest_node_id.checked_add(1) {
                Some(next) => write!(f, "node ids are used in order; the next one is {next}"),
                None => f.write_str("no free node id left"),
            },
            Self::KeyInUse { node_id } => write!(f, "node {node_id} already uses this key"),
            Self::NoAddress(id) => write!(f, "node {id} is added without its address"),
            Self::NotAMember(id) => write!(f, "node {id} is not a member"),
            Self::NotALearner(id) => write!(f, "node {id} is not a learner"),
            Self::NotAVoter(id) => write!(f, "node {id} is not another voter"),
            Self::NotCaughtUp(id) => write!(f, "node {id} has not caught up with the log"),
            Self::TooManyVoters => write!(f, "a cluster has at most {MAX_CLUSTER_VOTERS} voters"),
            Self::LeaderTargeted => {
                f.write_str("the leader cannot remove itself; transfer leadership first")
            }
            Self::ProposalDropped => f.write_str("Raft dropped the proposal; retry"),
        }
    }
}

impl Error for MembershipError {}

/// Produced by `silver cluster`, consumed by Control.
#[derive(Debug, Clone, Copy, TypeHash)]
#[repr(C)]
pub struct ClusterAdminRequest {
    pub request_id: u64,
    pub command: ClusterAdminCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeHash)]
#[repr(C, u8)]
pub enum ClusterAdminCommand {
    Change(MembershipOperation),
    TransferLeader { node_id: u64 },
    Members,
}

#[derive(Debug, Clone, Copy, TypeHash)]
#[repr(C)]
pub struct ClusterAdminResponse {
    pub request_id: u64,
    pub result: ClusterAdminResult,
}

#[derive(Debug, Clone, Copy, TypeHash)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum ClusterAdminResult {
    /// The leader proposed the change; it takes effect once it commits.
    Proposed,
    Members(ClusterMembers),
    Refused(MembershipError),
}

/// The members as the answering node sees them. Only a leader knows each
/// member's progress.
#[derive(Debug, Clone, Copy, TypeHash)]
#[repr(C)]
pub struct ClusterMembers {
    pub node_id: u64,
    pub leader_id: Option<u64>,
    pub commit: u64,
    pub highest_node_id: u64,
    pub members: ArrayVec<ClusterMemberRow, MAX_LISTED_MEMBERS>,
    pub unlisted: u32,
}

impl ClusterMembers {
    pub fn push(&mut self, row: ClusterMemberRow) {
        if self.members.try_push(row).is_some() {
            self.unlisted += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, TypeHash)]
#[repr(C)]
pub struct ClusterMemberRow {
    pub node_id: u64,
    pub role: MemberRole,
    pub address: Option<MemberAddress>,
    pub caught_up: bool,
    /// `None` for the answering node itself.
    pub peer: Option<ClusterPeerStats>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TypeHash)]
#[repr(u8)]
pub enum MemberRole {
    Voter,
    /// A voter in the incoming config only, while joint.
    Joining,
    /// A voter in the outgoing config only, while joint.
    Leaving,
    Learner,
}

impl fmt::Display for MemberRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Voter => "voter",
            Self::Joining => "joining",
            Self::Leaving => "leaving",
            Self::Learner => "learner",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(addr: SocketAddr) -> MemberAddress {
        MemberAddress { public_key: [2; PUBLIC_KEY_LEN], addr }
    }

    #[test]
    fn addresses_round_trip_for_both_ip_families() {
        for addr in ["10.0.0.1:9000", "[::1]:9001"] {
            let address = address(addr.parse().unwrap());
            let mut bytes = Vec::new();
            address.encode(&mut bytes);
            assert_eq!(MemberAddress::decode(&bytes.try_into().unwrap()).unwrap(), address);
        }
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        let mut bytes = Vec::new();
        address("10.0.0.1:9000".parse().unwrap()).encode(&mut bytes);
        let mut bad_family = bytes.clone();
        bad_family[PUBLIC_KEY_LEN] = 5;
        let mut padded_v4 = bytes;
        padded_v4[PUBLIC_KEY_LEN + 1] = 1;
        for bytes in [bad_family, padded_v4] {
            assert!(MemberAddress::decode(&bytes.try_into().unwrap()).is_err());
        }
    }
}
