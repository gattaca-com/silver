use std::collections::BTreeMap;

use silver_common::{
    PoolChange,
    ssz_view::{
        SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, SignedBlsToExecutionChangeView,
        SignedVoluntaryExitView,
    },
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
};

/// Beacon State's operation pools, rebuilt from its `PoolChange` events and
/// kept in validator order.
#[derive(Default)]
pub(crate) struct OperationPools {
    exits: BTreeMap<u32, [u8; SIGNED_VOLUNTARY_EXIT_SIZE]>,
    bls_changes: BTreeMap<u32, [u8; SIGNED_BLS_CHANGE_SIZE]>,
}

impl OperationPools {
    pub(crate) fn apply(&mut self, change: PoolChange) {
        match change {
            PoolChange::ExitAdded(ssz) => {
                let validator_index = SignedVoluntaryExitView::validator_index(&ssz) as u32;
                self.exits.insert(validator_index, ssz);
            }
            PoolChange::ExitRemoved { validator_index } => {
                self.exits.remove(&validator_index);
            }
            PoolChange::BlsChangeAdded(ssz) => {
                let validator_index = SignedBlsToExecutionChangeView::validator_index(&ssz) as u32;
                self.bls_changes.insert(validator_index, ssz);
            }
            PoolChange::BlsChangeRemoved { validator_index } => {
                self.bls_changes.remove(&validator_index);
            }
        }
    }
}

pub(crate) fn get_voluntary_exits(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json_body(|json| {
        json.data_envelope(|json| {
            json.begin_array();
            for ssz in ctx.pools.exits.values() {
                json.voluntary_exit(ssz);
            }
            json.end_array();
        })
    });
}

pub(crate) fn get_bls_to_execution_changes(
    _req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    resp.json_body(|json| {
        json.data_envelope(|json| {
            json.begin_array();
            for ssz in ctx.pools.bls_changes.values() {
                json.bls_to_execution_change(ssz);
            }
            json.end_array();
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ctx::anchor_ctx,
        testing::{answer, json, request},
    };

    fn exit(validator_index: u64) -> [u8; SIGNED_VOLUNTARY_EXIT_SIZE] {
        let mut ssz = [0x44; SIGNED_VOLUNTARY_EXIT_SIZE];
        ssz[0..8].copy_from_slice(&7u64.to_le_bytes());
        ssz[8..16].copy_from_slice(&validator_index.to_le_bytes());
        ssz
    }

    fn bls_change(validator_index: u64) -> [u8; SIGNED_BLS_CHANGE_SIZE] {
        let mut ssz = [0x44; SIGNED_BLS_CHANGE_SIZE];
        ssz[0..8].copy_from_slice(&validator_index.to_le_bytes());
        ssz[8..56].fill(0x55);
        ssz[56..76].fill(0x66);
        ssz
    }

    fn pool(ctx: &ApiCtx, path: &str) -> Vec<serde_json::Value> {
        json(&answer(ctx, &request("GET", path)))["data"].as_array().unwrap().clone()
    }

    #[test]
    fn pools_list_their_entries_in_validator_order_until_removed() {
        let mut ctx = anchor_ctx();
        for change in [
            PoolChange::ExitAdded(exit(9)),
            PoolChange::ExitAdded(exit(2)),
            PoolChange::BlsChangeAdded(bls_change(5)),
        ] {
            ctx.pools.apply(change);
        }

        let exits = pool(&ctx, "/eth/v1/beacon/pool/voluntary_exits");
        let indices: Vec<_> =
            exits.iter().map(|e| e["message"]["validator_index"].clone()).collect();
        assert_eq!(indices, ["2", "9"]);
        assert_eq!(exits[0]["message"]["epoch"], "7");
        assert_eq!(exits[0]["signature"], format!("0x{}", "44".repeat(96)));

        let changes = pool(&ctx, "/eth/v1/beacon/pool/bls_to_execution_changes");
        let [change] = &changes[..] else { panic!("one change: {changes:?}") };
        assert_eq!(change["message"]["validator_index"], "5");
        assert_eq!(change["message"]["from_bls_pubkey"], format!("0x{}", "55".repeat(48)));
        assert_eq!(change["message"]["to_execution_address"], format!("0x{}", "66".repeat(20)));

        ctx.pools.apply(PoolChange::ExitRemoved { validator_index: 2 });
        ctx.pools.apply(PoolChange::BlsChangeRemoved { validator_index: 5 });
        assert_eq!(pool(&ctx, "/eth/v1/beacon/pool/voluntary_exits").len(), 1);
        assert!(pool(&ctx, "/eth/v1/beacon/pool/bls_to_execution_changes").is_empty());
    }
}
