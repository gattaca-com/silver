use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::{BufMut, BytesMut};
use raft::eraftpb::{ConfChangeType, ConfChangeV2, ConfState};
use silver_common::PeerId;

const SNAPSHOT_MAGIC: &[u8; 8] = b"SLVMEMB\x01";
pub(super) const PUBLIC_KEY_LEN: usize = 33;
const SOCKET_ADDR_LEN: usize = 1 + 16 + 2;
pub(super) const MEMBER_ADDRESS_LEN: usize = PUBLIC_KEY_LEN + SOCKET_ADDR_LEN;
const MEMBER_LEN: usize = 8 + MEMBER_ADDRESS_LEN;

/// Where a member is dialled. Its key never changes: a new key is a new
/// member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberAddress {
    /// Compressed secp256k1.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub addr: SocketAddr,
}

impl MemberAddress {
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_secp256k1_pubkey(&self.public_key)
    }

    pub(super) fn encode(&self, bytes: &mut impl BufMut) {
        bytes.put_slice(&self.public_key);
        let (tag, ip) = match self.addr.ip() {
            IpAddr::V4(ip) => (4, ip.to_ipv6_compatible().octets()),
            IpAddr::V6(ip) => (6, ip.octets()),
        };
        bytes.put_u8(tag);
        bytes.put_slice(&ip);
        bytes.put_slice(&self.addr.port().to_le_bytes());
    }

    pub(super) fn decode(bytes: &[u8; MEMBER_ADDRESS_LEN]) -> io::Result<Self> {
        let (key, addr) = bytes.split_at(PUBLIC_KEY_LEN);
        let public_key = key.try_into().expect("slice is one public key");
        let ip: [u8; 16] = addr[1..17].try_into().expect("slice is 16 bytes");
        let ip = match addr[0] {
            4 if ip[..12].iter().all(|&byte| byte == 0) => {
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
            }
            6 => IpAddr::V6(Ipv6Addr::from(ip)),
            _ => return Err(invalid("invalid cluster member address")),
        };
        let port = u16::from_le_bytes(addr[17..].try_into().expect("slice is 2 bytes"));
        Ok(Self { public_key, addr: SocketAddr::new(ip, port) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub node_id: u64,
    pub address: MemberAddress,
}

impl Member {
    /// The entry context of a change adding this member as a learner.
    pub(super) fn change_context(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + MEMBER_LEN);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.node_id.to_le_bytes());
        self.address.encode(&mut bytes);
        bytes
    }
}

/// Encoded members, validated once and then read in place.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct MemberRecords<'a>(&'a [u8]);

impl<'a> MemberRecords<'a> {
    /// The context of an entry adding learners: their addresses.
    pub(super) fn parse_context(context: &'a [u8]) -> io::Result<Self> {
        if context.is_empty() {
            return Ok(Self::default());
        }
        match Self::parse(context)? {
            (records, []) => Ok(records),
            _ => Err(invalid("trailing cluster membership change context")),
        }
    }

    fn parse(bytes: &'a [u8]) -> io::Result<(Self, &'a [u8])> {
        let truncated = || invalid("truncated cluster member addresses");
        let (count, rest) = bytes.split_first_chunk().ok_or_else(truncated)?;
        let len = (u32::from_le_bytes(*count) as usize)
            .checked_mul(MEMBER_LEN)
            .filter(|&len| len <= rest.len())
            .ok_or_else(truncated)?;
        let (records, rest) = rest.split_at(len);
        for record in records.chunks_exact(MEMBER_LEN) {
            MemberAddress::decode(record[8..].try_into().expect("record holds one address"))?;
        }
        Ok((Self(records), rest))
    }

    fn node_ids(self) -> impl Iterator<Item = u64> + 'a {
        self.0.chunks_exact(MEMBER_LEN).map(|record| {
            u64::from_le_bytes(*record.split_first_chunk::<8>().expect("record holds an id").0)
        })
    }

    fn are_distinct_members_of(self, membership: &ConfState) -> bool {
        self.node_ids().enumerate().all(|(i, node_id)| {
            member_ids(membership).any(|id| id == node_id) &&
                self.node_ids().skip(i + 1).all(|other| other != node_id)
        })
    }

    pub(super) fn iter(self) -> impl Iterator<Item = Member> + 'a {
        self.0.chunks_exact(MEMBER_LEN).map(|record| {
            let (node_id, address) = record.split_first_chunk::<8>().expect("record holds an id");
            Member {
                node_id: u64::from_le_bytes(*node_id),
                address: MemberAddress::decode(
                    address.try_into().expect("record holds an address"),
                )
                .expect("validated when parsed"),
            }
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Members(Vec<Member>);

impl FromIterator<Member> for Members {
    fn from_iter<T: IntoIterator<Item = Member>>(members: T) -> Self {
        Self(members.into_iter().collect())
    }
}

impl Members {
    fn iter(&self) -> impl Iterator<Item = Member> + Clone + '_ {
        self.0.iter().copied()
    }

    fn address(&self, node_id: u64) -> Option<&MemberAddress> {
        self.0.iter().find(|member| member.node_id == node_id).map(|member| &member.address)
    }

    fn encoded_len(&self) -> usize {
        4 + self.0.len() * MEMBER_LEN
    }

    fn encode(&self, bytes: &mut impl BufMut) {
        bytes.put_slice(&(self.0.len() as u32).to_le_bytes());
        for member in &self.0 {
            bytes.put_slice(&member.node_id.to_le_bytes());
            member.address.encode(bytes);
        }
    }
}

/// The replicated address book. Raft's conf state holds the roles; this
/// holds where each member is dialled and the highest id ever used, since
/// an id is never reused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ClusterMembership {
    addresses: Members,
    highest_node_id: u64,
    /// Cached: raft-rs exposes the outgoing voters only by allocating.
    joint: bool,
}

impl ClusterMembership {
    pub(super) fn new(member_ids: impl Iterator<Item = u64>) -> Self {
        Self { highest_node_id: member_ids.max().unwrap_or(0), ..Self::default() }
    }

    pub(super) fn address(&self, node_id: u64) -> Option<&MemberAddress> {
        self.addresses.address(node_id)
    }

    pub(super) fn members(&self) -> impl Iterator<Item = Member> + Clone + '_ {
        self.addresses.iter()
    }

    pub(super) fn is_joint(&self) -> bool {
        self.joint
    }

    pub(super) fn highest_node_id(&self) -> u64 {
        self.highest_node_id
    }

    /// `membership` is raft-rs's result of applying `change`.
    pub(super) fn apply_change(
        &mut self,
        change: &ConfChangeV2,
        added: MemberRecords,
        membership: &ConfState,
    ) {
        for single in change.get_changes() {
            self.highest_node_id = self.highest_node_id.max(single.node_id);
        }
        for member in added.iter() {
            let is_added_learner = change.get_changes().iter().any(|single| {
                single.node_id == member.node_id &&
                    single.get_change_type() == ConfChangeType::AddLearnerNode
            });
            if is_added_learner && self.address(member.node_id).is_none() {
                self.addresses.0.push(member);
            }
        }
        self.addresses.0.retain(|member| member_ids(membership).any(|id| id == member.node_id));
        self.joint = !membership.voters_outgoing.is_empty();
    }

    /// Only a member announces its own address, and never under another key.
    pub(super) fn announce(&mut self, origin: u64, announced: Member, is_member: bool) -> bool {
        if origin != announced.node_id || !is_member {
            return false;
        }
        match self.addresses.0.iter_mut().find(|member| member.node_id == announced.node_id) {
            Some(known) if known.address.public_key != announced.address.public_key => false,
            Some(known) => {
                known.address = announced.address;
                true
            }
            None => {
                self.addresses.0.push(announced);
                true
            }
        }
    }

    pub(super) fn snapshot_len(&self) -> usize {
        SNAPSHOT_MAGIC.len() + 8 + self.addresses.encoded_len()
    }

    pub(super) fn encode_snapshot(&self, bytes: &mut BytesMut) {
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&self.highest_node_id.to_le_bytes());
        self.addresses.encode(bytes);
    }

    /// Returns the bytes that follow the membership. A snapshot cut before
    /// membership was replicated has no prefix and no addresses.
    pub(super) fn decode_snapshot<'a>(
        bytes: &'a [u8],
        members: &ConfState,
    ) -> io::Result<(Self, &'a [u8])> {
        let joint = !members.voters_outgoing.is_empty();
        let Some(prefix) = SnapshotPrefix::parse(bytes, members)? else {
            return Ok((Self { joint, ..Self::new(member_ids(members)) }, bytes));
        };
        let addresses = prefix.records.iter().collect();
        Ok((Self { addresses, highest_node_id: prefix.highest_node_id, joint }, prefix.rest))
    }

    /// As `decode_snapshot`, for a snapshot that is only checked.
    pub(super) fn skip_snapshot<'a>(bytes: &'a [u8], members: &ConfState) -> io::Result<&'a [u8]> {
        Ok(SnapshotPrefix::parse(bytes, members)?.map_or(bytes, |prefix| prefix.rest))
    }
}

struct SnapshotPrefix<'a> {
    highest_node_id: u64,
    records: MemberRecords<'a>,
    rest: &'a [u8],
}

impl<'a> SnapshotPrefix<'a> {
    fn parse(bytes: &'a [u8], members: &ConfState) -> io::Result<Option<Self>> {
        let Some(rest) = bytes.strip_prefix(SNAPSHOT_MAGIC) else {
            return Ok(None);
        };
        let (highest_node_id, rest) = rest
            .split_first_chunk()
            .ok_or_else(|| invalid("truncated cluster membership snapshot"))?;
        let highest_node_id = u64::from_le_bytes(*highest_node_id);
        let (records, rest) = MemberRecords::parse(rest)?;
        if !records.are_distinct_members_of(members) ||
            member_ids(members).any(|id| id > highest_node_id)
        {
            return Err(invalid("cluster membership snapshot disagrees with its conf state"));
        }
        Ok(Some(Self { highest_node_id, records, rest }))
    }
}

pub(super) fn member_ids(members: &ConfState) -> impl Iterator<Item = u64> + Clone + '_ {
    members
        .voters
        .iter()
        .chain(&members.voters_outgoing)
        .chain(&members.learners)
        .chain(&members.learners_next)
        .copied()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
pub(crate) fn test_address(node_id: u64) -> MemberAddress {
    let mut key = [2; PUBLIC_KEY_LEN];
    key[1..9].copy_from_slice(&node_id.to_le_bytes());
    MemberAddress {
        public_key: key,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, node_id as u8)), 9000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(node_id: u64) -> Member {
        Member { node_id, address: test_address(node_id) }
    }

    fn members(voters: &[u64], learners: &[u64]) -> ConfState {
        ConfState { voters: voters.to_vec(), learners: learners.to_vec(), ..ConfState::default() }
    }

    #[test]
    fn addresses_round_trip_for_both_ip_families() {
        let v6 = MemberAddress {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9001),
            ..test_address(2)
        };
        for address in [test_address(1), v6] {
            let mut bytes = Vec::new();
            address.encode(&mut bytes);
            assert_eq!(MemberAddress::decode(&bytes.try_into().unwrap()).unwrap(), address);
        }
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        let mut bytes = Vec::new();
        test_address(1).encode(&mut bytes);
        let mut bad_family = bytes.clone();
        bad_family[PUBLIC_KEY_LEN] = 5;
        let mut padded_v4 = bytes;
        padded_v4[PUBLIC_KEY_LEN + 1] = 1;
        for bytes in [bad_family, padded_v4] {
            assert!(MemberAddress::decode(&bytes.try_into().unwrap()).is_err());
        }
    }

    #[test]
    fn snapshot_prefix_round_trips_and_legacy_snapshots_have_none() {
        let conf = members(&[1, 2, 3], &[4]);
        let mut membership = ClusterMembership::new(member_ids(&conf));
        assert!(membership.announce(1, member(1), true));
        assert!(membership.announce(4, member(4), true));

        let mut bytes = BytesMut::new();
        membership.encode_snapshot(&mut bytes);
        bytes.extend_from_slice(b"locks");
        let (decoded, rest) = ClusterMembership::decode_snapshot(&bytes, &conf).unwrap();
        assert_eq!((decoded, rest), (membership, &b"locks"[..]));

        let (legacy, rest) = ClusterMembership::decode_snapshot(b"SLVLOCK", &conf).unwrap();
        assert_eq!(legacy, ClusterMembership {
            highest_node_id: 4,
            ..ClusterMembership::default()
        });
        assert_eq!(rest, b"SLVLOCK");
    }

    #[test]
    fn snapshot_addresses_must_belong_to_members() {
        let mut membership = ClusterMembership::new([1, 2, 3].into_iter());
        membership.announce(3, member(3), true);
        let mut bytes = BytesMut::new();
        membership.encode_snapshot(&mut bytes);
        for wrong in [members(&[1, 2], &[]), members(&[1, 2, 3, 9], &[])] {
            assert!(ClusterMembership::decode_snapshot(&bytes, &wrong).is_err());
            assert!(ClusterMembership::skip_snapshot(&bytes, &wrong).is_err());
        }
        bytes.extend_from_slice(b"locks");
        assert_eq!(
            ClusterMembership::skip_snapshot(&bytes, &members(&[1, 2, 3], &[])).unwrap(),
            b"locks"
        );
        assert_eq!(
            ClusterMembership::skip_snapshot(b"SLVLOCK", &members(&[1], &[])).unwrap(),
            b"SLVLOCK"
        );
        bytes.truncate(bytes.len() - b"locks".len());
        assert!(
            ClusterMembership::decode_snapshot(
                &bytes[..bytes.len() - 1],
                &members(&[1, 2, 3], &[])
            )
            .is_err()
        );
    }

    #[test]
    fn announcements_come_from_the_member_itself_under_its_own_key() {
        let mut membership = ClusterMembership::new([1, 2, 3].into_iter());
        assert!(!membership.announce(2, member(1), true), "announced for another");
        assert!(!membership.announce(5, member(5), false), "not a member");
        assert!(membership.announce(1, member(1), true));

        let moved = MemberAddress { addr: test_address(9).addr, ..test_address(1) };
        assert!(membership.announce(1, Member { node_id: 1, address: moved }, true));
        assert_eq!(membership.address(1), Some(&moved));
        let rekeyed = Member { node_id: 1, address: test_address(2) };
        assert!(!membership.announce(1, rekeyed, true), "another key");
        assert_eq!(membership.address(1), Some(&moved));
    }

    #[test]
    fn added_members_round_trip_through_the_entry_context() {
        let context = member(4).change_context();
        let added: Vec<_> = MemberRecords::parse_context(&context).unwrap().iter().collect();
        assert_eq!(added, [member(4)]);
        assert_eq!(MemberRecords::parse_context(&[]).unwrap().iter().count(), 0);
        let mut trailing = context.clone();
        trailing.push(0);
        assert!(MemberRecords::parse_context(&trailing).is_err());
        let mut bad_address = context;
        bad_address[4 + 8 + PUBLIC_KEY_LEN] = 5;
        assert!(MemberRecords::parse_context(&bad_address).is_err());
    }
}
