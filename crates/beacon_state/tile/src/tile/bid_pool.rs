use std::collections::hash_map::Entry;

use rustc_hash::{FxHashMap, FxHashSet};
use silver_beacon_state_data::{B256, ExecutionPayloadBid, Slot};

/// The branch a bid extends: a parent beacon block and, through its full or
/// empty payload, a parent execution payload. Bids compete within a branch.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) struct BidBranch {
    pub slot: Slot,
    pub parent_root: B256,
    pub parent_hash: B256,
}

impl From<&ExecutionPayloadBid> for BidBranch {
    fn from(bid: &ExecutionPayloadBid) -> Self {
        Self {
            slot: bid.slot,
            parent_root: bid.parent_block_root,
            parent_hash: bid.parent_block_hash,
        }
    }
}

/// What the proposer is paid: in-protocol `value` plus an out-of-protocol
/// `execution_payment`. Widened so peer-supplied fields cannot overflow.
fn payout(bid: &ExecutionPayloadBid) -> u128 {
    bid.value as u128 + bid.execution_payment as u128
}

struct BidPoolEntry {
    bid: ExecutionPayloadBid,
    signature: [u8; 96],
}

/// Highest-payout verified bid per branch, and the builders already heard
/// from on each branch.
#[derive(Default)]
pub(super) struct BidPool {
    slot: Slot,
    best: FxHashMap<BidBranch, BidPoolEntry>,
    seen: FxHashSet<(BidBranch, u64)>,
}

impl BidPool {
    /// The builder's first bid on its branch, and above the branch's best.
    pub fn is_candidate(&self, bid: &ExecutionPayloadBid) -> bool {
        let branch = BidBranch::from(bid);
        !self.seen.contains(&(branch, bid.builder_index)) &&
            self.best.get(&branch).is_none_or(|best| payout(bid) > payout(&best.bid))
    }

    /// `bid` passed validation and its signature verified.
    pub fn add(&mut self, bid: ExecutionPayloadBid, signature: [u8; 96]) {
        let branch = BidBranch::from(&bid);
        self.seen.insert((branch, bid.builder_index));
        match self.best.entry(branch) {
            Entry::Occupied(mut best) => {
                if payout(&bid) > payout(&best.get().bid) {
                    best.insert(BidPoolEntry { bid, signature });
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(BidPoolEntry { bid, signature });
            }
        }
    }

    /// Left in place: a retried request commits to the same bid.
    pub fn best(&self, branch: &BidBranch) -> Option<(&ExecutionPayloadBid, &[u8; 96])> {
        self.best.get(branch).map(|BidPoolEntry { bid, signature }| (bid, signature))
    }

    /// Next-slot bids arrive during the current slot, so they are kept.
    pub fn on_slot(&mut self, slot: Slot) {
        if slot > self.slot {
            self.slot = slot;
            self.best.retain(|branch, _| branch.slot >= slot);
            self.seen.retain(|(branch, _)| branch.slot >= slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(slot: Slot, parent: u8, hash: u8, builder: u64, value: u64) -> ExecutionPayloadBid {
        ExecutionPayloadBid {
            slot,
            parent_block_root: [parent; 32],
            parent_block_hash: [hash; 32],
            builder_index: builder,
            value,
            ..Default::default()
        }
    }

    fn branch(slot: Slot, parent: u8, hash: u8) -> BidBranch {
        BidBranch::from(&bid(slot, parent, hash, 0, 0))
    }

    #[test]
    fn a_builder_is_heard_once_per_branch() {
        let mut pool = BidPool::default();
        pool.add(bid(5, 1, 1, 7, 10), [0; 96]);
        assert!(!pool.is_candidate(&bid(5, 1, 1, 7, 20)), "same builder, same branch");
        assert!(
            pool.is_candidate(&bid(5, 1, 2, 7, 20)),
            "same builder, the parent's other payload"
        );
        assert!(pool.is_candidate(&bid(5, 2, 1, 7, 20)), "same builder, another parent");
    }

    #[test]
    fn only_a_strictly_higher_payout_competes() {
        let mut pool = BidPool::default();
        pool.add(bid(5, 1, 1, 7, 10), [0; 96]);
        assert!(!pool.is_candidate(&bid(5, 1, 1, 8, 10)), "a tie is not higher");
        assert!(pool.is_candidate(&bid(5, 1, 1, 8, 11)));
        pool.add(bid(5, 1, 1, 8, 11), [1; 96]);
        let (best, signature) = pool.best(&branch(5, 1, 1)).unwrap();
        assert_eq!((best.builder_index, *signature), (8, [1; 96]));
    }

    #[test]
    fn execution_payment_counts_without_overflow() {
        let mut pool = BidPool::default();
        pool.add(bid(5, 1, 1, 7, 10), [0; 96]);
        let mut paid = bid(5, 1, 1, 8, 5);
        paid.execution_payment = 6;
        assert!(pool.is_candidate(&paid), "5 + 6 beats 10");

        let mut extreme = bid(5, 1, 1, 9, u64::MAX);
        extreme.execution_payment = u64::MAX;
        assert!(pool.is_candidate(&extreme));
        pool.add(extreme, [2; 96]);
        assert_eq!(pool.best(&branch(5, 1, 1)).unwrap().0.builder_index, 9);
    }

    #[test]
    fn a_new_slot_keeps_next_slot_bids() {
        let mut pool = BidPool::default();
        pool.add(bid(5, 1, 1, 7, 10), [0; 96]);
        pool.add(bid(6, 1, 1, 7, 10), [0; 96]);
        pool.on_slot(6);
        assert!(pool.best(&branch(5, 1, 1)).is_none());
        assert!(!pool.is_candidate(&bid(6, 1, 1, 7, 20)), "slot 6's seen set survives");
        assert!(pool.best(&branch(6, 1, 1)).is_some());
    }
}
