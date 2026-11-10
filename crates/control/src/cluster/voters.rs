use std::{fmt, ops::Deref};

use flux::utils::ArrayVec;

/// raft-rs computes the commit index on the stack for up to 7 voters and
/// allocates above that. etcd, whose raft raft-rs ports, also advises at most
/// 7 members.
pub(super) const MAX_VOTERS: usize = 7;

/// A static voter set that includes its local node: distinct non-zero ids,
/// sorted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Voters(ArrayVec<u64, MAX_VOTERS>);

impl Voters {
    pub fn new(node_id: u64, ids: impl IntoIterator<Item = u64>) -> Result<Self, &'static str> {
        let mut voters = ArrayVec::new();
        for id in ids {
            if voters.try_push(id).is_some() {
                return Err("a Raft cluster has at most 7 voters");
            }
        }
        voters.sort_unstable();
        if voters.contains(&0) {
            return Err("Raft voter ids must be non-zero");
        }
        if voters.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("Raft voter ids must be unique");
        }
        if node_id == 0 || !voters.contains(&node_id) {
            return Err("local Raft node is not in voter set");
        }
        Ok(Self(voters))
    }
}

impl Deref for Voters {
    type Target = [u64];

    fn deref(&self) -> &[u64] {
        &self.0
    }
}

impl fmt::Debug for Voters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
