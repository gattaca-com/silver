use std::{fmt, ops::Deref};

use flux::utils::ArrayVec;
use silver_common::MAX_CLUSTER_VOTERS;

/// The voters a journal starts with: distinct non-zero ids, sorted, among them
/// the local node. Empty for a node that joins a running cluster, whose
/// membership arrives with its first snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Voters(ArrayVec<u64, MAX_CLUSTER_VOTERS>);

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
        if node_id == 0 || !(voters.is_empty() || voters.contains(&node_id)) {
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
