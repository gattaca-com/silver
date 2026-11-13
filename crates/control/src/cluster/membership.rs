use std::io;

use bytes::{BufMut, BytesMut};
use raft::eraftpb::{ConfChangeType, ConfChangeV2, ConfState};
use silver_common::{
    MAX_CLUSTER_VOTERS, MEMBER_ADDRESS_LEN, MemberAddress, MemberRole, MembershipError,
};

const SNAPSHOT_MAGIC: &[u8; 8] = b"SLVMEMB\x01";
const MEMBER_LEN: usize = 8 + MEMBER_ADDRESS_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub node_id: u64,
    pub address: MemberAddress,
}

impl Member {
    pub(super) fn encode(&self, bytes: &mut impl BufMut) {
        bytes.put_slice(&self.node_id.to_le_bytes());
        self.address.encode(bytes);
    }

    pub(super) fn decode_added_learner(added_learner: &[u8]) -> io::Result<Option<Self>> {
        if added_learner.is_empty() {
            return Ok(None);
        }
        let added_learner =
            added_learner.try_into().map_err(|_| invalid("malformed added cluster member"))?;
        Self::decode(added_learner).map(Some)
    }

    pub(super) fn decode(bytes: &[u8; MEMBER_LEN]) -> io::Result<Self> {
        let (node_id, address) = bytes.split_first_chunk().expect("a member starts with its id");
        Ok(Self {
            node_id: u64::from_le_bytes(*node_id),
            address: MemberAddress::decode(address.try_into().expect("an address follows"))?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct ClusterMembership {
    roles: ConfState,
    addresses: Vec<Member>,
    highest_node_id: u64,
}

impl ClusterMembership {
    pub(super) fn new(initial_voters: &[u64]) -> Self {
        Self::without_addresses(ConfState {
            voters: initial_voters.to_vec(),
            ..ConfState::default()
        })
    }

    fn without_addresses(roles: ConfState) -> Self {
        Self {
            highest_node_id: member_ids(&roles).max().unwrap_or(0),
            roles,
            addresses: Vec::new(),
        }
    }

    /// A joining node knows no members until its first snapshot.
    pub(super) fn is_empty(&self) -> bool {
        self.member_ids().next().is_none()
    }

    pub(super) fn member_ids(&self) -> impl Iterator<Item = u64> + Clone + '_ {
        member_ids(&self.roles)
    }

    pub(super) fn is_member(&self, node_id: u64) -> bool {
        self.member_ids().any(|id| id == node_id)
    }

    pub(super) fn is_voter(&self, node_id: u64) -> bool {
        self.roles.voters.contains(&node_id) || self.roles.voters_outgoing.contains(&node_id)
    }

    fn is_learner(&self, node_id: u64) -> bool {
        self.roles.learners.contains(&node_id)
    }

    /// Each member once, though `member_ids` yields a voter of both joint
    /// halves twice.
    pub(super) fn roles(&self) -> impl Iterator<Item = (u64, MemberRole)> + '_ {
        let ids = self.member_ids();
        ids.clone()
            .enumerate()
            .filter(move |&(seen, node_id)| !ids.clone().take(seen).any(|id| id == node_id))
            .filter_map(|(_, node_id)| Some((node_id, self.role(node_id)?)))
    }

    /// Members of both halves of a joint config are plain voters.
    pub(super) fn role(&self, node_id: u64) -> Option<MemberRole> {
        let incoming = self.roles.voters.contains(&node_id);
        let outgoing = self.roles.voters_outgoing.contains(&node_id);
        match (incoming, outgoing) {
            (true, true) => Some(MemberRole::Voter),
            (true, false) if self.is_joint() => Some(MemberRole::Joining),
            (true, false) => Some(MemberRole::Voter),
            (false, true) => Some(MemberRole::Leaving),
            (false, false) if self.is_member(node_id) => Some(MemberRole::Learner),
            (false, false) => None,
        }
    }

    pub(super) fn highest_node_id(&self) -> u64 {
        self.highest_node_id
    }

    pub(super) fn is_joint(&self) -> bool {
        !self.roles.voters_outgoing.is_empty()
    }

    pub(super) fn address(&self, node_id: u64) -> Option<MemberAddress> {
        self.addresses.iter().find(|member| member.node_id == node_id).map(|member| member.address)
    }

    /// The rules for a change, from replicated state alone: the leader
    /// checks them before proposing it and every node again when it applies,
    /// so all of them accept or skip it alike.
    pub(super) fn check(
        &self,
        change: &ConfChangeV2,
        added_learner: Option<Member>,
    ) -> Result<(), MembershipError> {
        let mut voters = self.roles.voters.len();
        for single in change.get_changes() {
            let node_id = single.node_id;
            match single.get_change_type() {
                ConfChangeType::AddLearnerNode => self.check_learner(node_id, added_learner)?,
                ConfChangeType::AddNode if !self.is_learner(node_id) => {
                    return Err(MembershipError::NotALearner(node_id));
                }
                ConfChangeType::AddNode => voters += 1,
                ConfChangeType::RemoveNode if self.is_voter(node_id) => voters -= 1,
                ConfChangeType::RemoveNode if !self.is_learner(node_id) => {
                    return Err(MembershipError::NotAMember(node_id));
                }
                ConfChangeType::RemoveNode => {}
            }
        }
        if voters > MAX_CLUSTER_VOTERS {
            return Err(MembershipError::TooManyVoters);
        }
        Ok(())
    }

    fn check_learner(
        &self,
        node_id: u64,
        added_learner: Option<Member>,
    ) -> Result<(), MembershipError> {
        let highest_node_id = self.highest_node_id;
        if highest_node_id.checked_add(1) != Some(node_id) {
            return Err(MembershipError::IdReused { highest_node_id });
        }
        let Some(learner) = added_learner.filter(|member| member.node_id == node_id) else {
            return Err(MembershipError::NoAddress(node_id));
        };
        let key = learner.address.public_key;
        match self.addresses.iter().find(|member| member.address.public_key == key) {
            Some(owner) => Err(MembershipError::KeyInUse { node_id: owner.node_id }),
            None => Ok(()),
        }
    }

    pub(super) fn apply_change(
        &mut self,
        change: &ConfChangeV2,
        added_learner: Option<Member>,
        resulting_roles: ConfState,
    ) {
        // Only a learner the change adds has an id never used before.
        self.addresses.extend(added_learner.filter(|member| member.node_id > self.highest_node_id));
        for single in change.get_changes() {
            self.highest_node_id = self.highest_node_id.max(single.node_id);
        }
        self.roles = resulting_roles;
        let roles = &self.roles;
        self.addresses.retain(|member| member_ids(roles).any(|id| id == member.node_id));
    }

    pub(super) fn announce(&mut self, node_id: u64, address: MemberAddress) -> bool {
        if !self.is_member(node_id) {
            return false;
        }
        match self.addresses.iter_mut().find(|member| member.node_id == node_id) {
            Some(known) if known.address.public_key != address.public_key => false,
            Some(known) => {
                known.address = address;
                true
            }
            None => {
                self.addresses.push(Member { node_id, address });
                true
            }
        }
    }

    pub(super) fn snapshot_len(&self) -> usize {
        SNAPSHOT_MAGIC.len() + 8 + 4 + self.addresses.len() * MEMBER_LEN
    }

    pub(super) fn encode_snapshot(&self, bytes: &mut BytesMut) {
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&self.highest_node_id.to_le_bytes());
        bytes.extend_from_slice(&(self.addresses.len() as u32).to_le_bytes());
        for member in &self.addresses {
            member.encode(bytes);
        }
    }

    /// A snapshot cut before membership was replicated has no prefix and no
    /// addresses.
    pub(super) fn split_from_snapshot<'a>(
        bytes: &'a [u8],
        roles: &ConfState,
    ) -> io::Result<(Self, &'a [u8])> {
        let Some(rest) = bytes.strip_prefix(SNAPSHOT_MAGIC) else {
            return Ok((Self::without_addresses(roles.clone()), bytes));
        };
        let (highest_node_id, rest) = rest.split_first_chunk().ok_or_else(truncated)?;
        let (addresses, rest) = split_members(rest)?;
        let highest_node_id = u64::from_le_bytes(*highest_node_id);
        let membership = Self { roles: roles.clone(), addresses, highest_node_id };
        if !membership.addresses_match_roles() {
            return Err(invalid("cluster membership snapshot disagrees with its conf state"));
        }
        Ok((membership, rest))
    }

    fn addresses_match_roles(&self) -> bool {
        let ids = || self.addresses.iter().map(|member| member.node_id);
        let distinct = ids().enumerate().all(|(i, id)| ids().skip(i + 1).all(|other| other != id));
        distinct &&
            ids().all(|id| self.is_member(id)) &&
            self.member_ids().all(|id| id <= self.highest_node_id)
    }
}

/// Splits a counted list of members from the bytes that follow it.
fn split_members(bytes: &[u8]) -> io::Result<(Vec<Member>, &[u8])> {
    let (count, rest) = bytes.split_first_chunk().ok_or_else(truncated)?;
    let len = (u32::from_le_bytes(*count) as usize)
        .checked_mul(MEMBER_LEN)
        .filter(|&len| len <= rest.len())
        .ok_or_else(truncated)?;
    let (members, rest) = rest.split_at(len);
    let members = members
        .chunks_exact(MEMBER_LEN)
        .map(|member| Member::decode(member.try_into().expect("chunk is one member")))
        .collect::<io::Result<_>>()?;
    Ok((members, rest))
}

fn truncated() -> io::Error {
    invalid("truncated cluster membership snapshot")
}

pub(super) fn member_ids(roles: &ConfState) -> impl Iterator<Item = u64> + Clone + '_ {
    roles
        .voters
        .iter()
        .chain(&roles.voters_outgoing)
        .chain(&roles.learners)
        .chain(&roles.learners_next)
        .copied()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
pub(crate) fn test_address(node_id: u64) -> MemberAddress {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use silver_common::PUBLIC_KEY_LEN;

    let mut key = [2; PUBLIC_KEY_LEN];
    key[1..9].copy_from_slice(&node_id.to_le_bytes());
    MemberAddress {
        public_key: key,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, node_id as u8)), 9000),
    }
}

#[cfg(test)]
mod tests {
    use silver_common::MembershipOperation;

    use super::*;
    use crate::cluster::membership_operation::{conf_change, membership_change};

    fn member(node_id: u64) -> Member {
        Member { node_id, address: test_address(node_id) }
    }

    fn roles(voters: &[u64], learners: &[u64]) -> ConfState {
        ConfState { voters: voters.to_vec(), learners: learners.to_vec(), ..ConfState::default() }
    }

    /// Members 1 to 3 vote; learner 4 was added with its address.
    fn membership() -> ClusterMembership {
        let mut membership = ClusterMembership::new(&[1, 2, 3]);
        let (change, added_learner) =
            conf_change(MembershipOperation::Add { node_id: 4, address: test_address(4) });
        membership.check(&change, added_learner).unwrap();
        membership.apply_change(&change, added_learner, roles(&[1, 2, 3], &[4]));
        membership
    }

    #[test]
    fn snapshot_round_trips_and_legacy_snapshots_have_no_addresses() {
        let membership = membership();
        let roles = roles(&[1, 2, 3], &[4]);
        let mut bytes = BytesMut::new();
        membership.encode_snapshot(&mut bytes);
        assert_eq!(bytes.len(), membership.snapshot_len());
        bytes.extend_from_slice(b"locks");
        let (decoded, rest) = ClusterMembership::split_from_snapshot(&bytes, &roles).unwrap();
        assert_eq!((decoded, rest), (membership, &b"locks"[..]));

        let (legacy, rest) = ClusterMembership::split_from_snapshot(b"SLVLOCK", &roles).unwrap();
        assert_eq!((legacy.address(4), legacy.highest_node_id), (None, 4));
        assert_eq!(rest, b"SLVLOCK");
    }

    #[test]
    fn snapshot_addresses_must_belong_to_members() {
        let mut bytes = BytesMut::new();
        membership().encode_snapshot(&mut bytes);
        for wrong in [roles(&[1, 2, 3], &[]), roles(&[1, 2, 3, 9], &[4])] {
            assert!(ClusterMembership::split_from_snapshot(&bytes, &wrong).is_err());
        }
        let truncated = &bytes[..bytes.len() - 1];
        assert!(
            ClusterMembership::split_from_snapshot(truncated, &roles(&[1, 2, 3], &[4])).is_err()
        );
    }

    #[test]
    fn member_announces_only_under_its_own_key() {
        let mut membership = membership();
        assert!(!membership.announce(5, test_address(5)), "not a member");

        let moved = MemberAddress { addr: test_address(9).addr, ..test_address(4) };
        assert!(membership.announce(4, moved));
        assert_eq!(membership.address(4), Some(moved));
        assert!(!membership.announce(4, test_address(2)), "another key");
        assert_eq!(membership.address(4), Some(moved));
    }

    #[test]
    fn changes_are_refused_with_a_reason() {
        let membership = membership();
        let check = |operation: MembershipOperation| {
            let (change, added_learner) = conf_change(operation);
            membership.check(&change, added_learner)
        };
        let add = |node_id, key| MembershipOperation::Add { node_id, address: test_address(key) };

        assert_eq!(check(add(4, 5)), Err(MembershipError::IdReused { highest_node_id: 4 }));
        assert_eq!(check(add(u64::MAX, 5)), Err(MembershipError::IdReused { highest_node_id: 4 }));
        assert_eq!(check(add(5, 4)), Err(MembershipError::KeyInUse { node_id: 4 }));
        assert_eq!(
            check(MembershipOperation::Promote { node_id: 2 }),
            Err(MembershipError::NotALearner(2))
        );
        assert_eq!(
            check(MembershipOperation::Remove { node_id: 9 }),
            Err(MembershipError::NotAMember(9))
        );
        assert_eq!(check(MembershipOperation::Replace { old: 1, new: 4 }), Ok(()));

        let learner = membership_change(Default::default(), &[(ConfChangeType::AddLearnerNode, 5)]);
        assert_eq!(membership.check(&learner, None), Err(MembershipError::NoAddress(5)));
        assert_eq!(membership.check(&learner, Some(member(6))), Err(MembershipError::NoAddress(5)));

        let mut full = ClusterMembership::new(&[1, 2, 3, 4, 5, 6, 7]);
        full.roles.learners = vec![8];
        let (promote, _) = conf_change(MembershipOperation::Promote { node_id: 8 });
        assert_eq!(full.check(&promote, None), Err(MembershipError::TooManyVoters));
    }

    #[test]
    fn roles_tell_joint_halves_apart() {
        let mut joint = membership();
        joint.roles.voters = vec![1, 2, 4];
        joint.roles.voters_outgoing = vec![1, 2, 3];
        joint.roles.learners.clear();
        let roles: Vec<_> = (1..=5).map(|id| joint.role(id)).collect();
        assert_eq!(roles, [
            Some(MemberRole::Voter),
            Some(MemberRole::Voter),
            Some(MemberRole::Leaving),
            Some(MemberRole::Joining),
            None,
        ]);
        assert_eq!(membership().role(4), Some(MemberRole::Learner));
    }

    #[test]
    fn removed_member_takes_its_address_and_keeps_its_id_used() {
        let mut membership = membership();
        let (remove, _) = conf_change(MembershipOperation::Remove { node_id: 4 });
        membership.apply_change(&remove, Some(member(2)), roles(&[1, 2, 3], &[]));
        assert_eq!((membership.address(4), membership.address(2)), (None, None));
        assert_eq!(membership.highest_node_id, 4);
        assert!(!membership.is_member(4));
    }
}
