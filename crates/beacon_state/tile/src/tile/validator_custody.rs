use silver_common::{
    BALANCE_PER_ADDITIONAL_CUSTODY_GROUP, BeaconStateEvent, NUMBER_OF_CUSTODY_GROUPS, NodeId,
    VALIDATOR_CUSTODY_REQUIREMENT,
};

pub struct ValidatorCustody {
    node_id: NodeId,
    custody_group_count: u64,
}

impl ValidatorCustody {
    pub fn new(node_id: NodeId, custody_group_count: u64) -> Self {
        Self { node_id, custody_group_count }
    }

    pub(super) fn raise(
        &mut self,
        attached_balances: impl Iterator<Item = u64>,
        from_slot: u64,
    ) -> Option<BeaconStateEvent> {
        let (attached, total_balance) =
            attached_balances.fold((0usize, 0u64), |(n, sum), balance| (n + 1, sum + balance));
        if attached == 0 {
            return None;
        }
        let required = (total_balance / BALANCE_PER_ADDITIONAL_CUSTODY_GROUP)
            .clamp(VALIDATOR_CUSTODY_REQUIREMENT, NUMBER_OF_CUSTODY_GROUPS as u64);
        if required <= self.custody_group_count {
            return None;
        }
        silver_log::info!(
            from = self.custody_group_count,
            to = required,
            attached,
            total_balance,
            from_slot,
            "validator custody raised"
        );
        self.custody_group_count = required;
        Some(BeaconStateEvent::CustodyChange {
            custody_group_count: required,
            columns: self.node_id.custody_groups(required as u8),
            from_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH: u64 = 1_000_000_000;

    fn raised(custody: &mut ValidatorCustody, balances: &[u64]) -> Option<u64> {
        match custody.raise(balances.iter().copied(), 64)? {
            BeaconStateEvent::CustodyChange { custody_group_count, columns, from_slot } => {
                assert_eq!(columns.count_ones() as u64, custody_group_count);
                assert_eq!(from_slot, 64);
                Some(custody_group_count)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn requirement_follows_attached_balance_and_never_falls() {
        let mut custody = ValidatorCustody::new(NodeId::new(&[7; 32]), 8);
        assert_eq!(raised(&mut custody, &[]), None, "no validators attached");
        assert_eq!(raised(&mut custody, &[32 * ETH; 8]), None, "the minimum is already met");
        assert_eq!(raised(&mut custody, &[32 * ETH; 100]), Some(100));
        assert_eq!(raised(&mut custody, &[32 * ETH; 50]), None, "custody never falls");
        assert_eq!(raised(&mut custody, &[2048 * ETH; 3]), Some(128), "capped at every group");
        assert_eq!(raised(&mut custody, &[2048 * ETH; 4]), None);
    }
}
