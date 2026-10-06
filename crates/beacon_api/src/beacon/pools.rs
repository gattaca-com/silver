use std::collections::BTreeMap;

use silver_common::{
    PoolChange, TCacheRead,
    ssz_view::{
        PROPOSER_SLASHING_SIZE, SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE,
        SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
    },
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
};

/// Beacon State's operation pools, rebuilt from its `PoolChange` events.
/// Exits and BLS changes are in validator order, slashings in admission order.
#[derive(Default)]
pub(crate) struct OperationPools {
    exits: BTreeMap<u32, [u8; SIGNED_VOLUNTARY_EXIT_SIZE]>,
    bls_changes: BTreeMap<u32, [u8; SIGNED_BLS_CHANGE_SIZE]>,
    proposer_slashings: BTreeMap<u64, [u8; PROPOSER_SLASHING_SIZE]>,
    attester_slashings: BTreeMap<u64, Box<[u8]>>,
}

impl OperationPools {
    /// `handed_off` copies a slashing's bytes out of the handoff tcache, or
    /// `None` once they are overwritten; the mirror then misses that proof.
    pub(crate) fn apply(
        &mut self,
        change: PoolChange,
        handed_off: impl FnOnce(TCacheRead) -> Option<Box<[u8]>>,
    ) {
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
            PoolChange::ProposerSlashingAdded { id, ssz } => {
                if let Some(ssz) = handed_off(ssz).and_then(|bytes| (*bytes).try_into().ok()) {
                    self.proposer_slashings.insert(id, ssz);
                }
            }
            PoolChange::ProposerSlashingRemoved { id } => {
                self.proposer_slashings.remove(&id);
            }
            PoolChange::AttesterSlashingAdded { id, ssz } => {
                if let Some(ssz) = handed_off(ssz) {
                    self.attester_slashings.insert(id, ssz);
                }
            }
            PoolChange::AttesterSlashingRemoved { id } => {
                self.attester_slashings.remove(&id);
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

pub(crate) fn get_proposer_slashings(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json_body(|json| {
        json.data_envelope(|json| {
            json.begin_array();
            for ssz in ctx.pools.proposer_slashings.values() {
                json.proposer_slashing(ssz);
            }
            json.end_array();
        })
    });
}

pub(crate) fn get_attester_slashings(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let version = ctx.spec.fork_at_slot(ctx.node_status.wall_slot).name();
    resp.versioned_json(version, |json| {
        json.begin_array();
        for ssz in ctx.pools.attester_slashings.values() {
            json.attester_slashing(ssz);
        }
        json.end_array();
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
    use silver_common::TCacheProducer;

    use super::*;
    use crate::{
        ctx::anchor_ctx,
        testing::{answer, json, request, submissions},
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

    fn proposer_slashing(proposer_index: u64) -> [u8; PROPOSER_SLASHING_SIZE] {
        let mut ssz = [0x44; PROPOSER_SLASHING_SIZE];
        for header in [0, PROPOSER_SLASHING_SIZE / 2] {
            ssz[header..header + 8].copy_from_slice(&9u64.to_le_bytes());
            ssz[header + 8..header + 16].copy_from_slice(&proposer_index.to_le_bytes());
            ssz[header + 16..header + 112].fill(0x11);
        }
        ssz
    }

    fn indexed_attestation(indices: &[u64]) -> Vec<u8> {
        let mut ssz = 228u32.to_le_bytes().to_vec();
        ssz.extend_from_slice(&[0u8; 128]);
        ssz.extend_from_slice(&[0x44; 96]);
        ssz.extend(indices.iter().flat_map(|index| index.to_le_bytes()));
        ssz
    }

    fn attester_slashing(first: &[u64], second: &[u64]) -> Vec<u8> {
        let (first, second) = (indexed_attestation(first), indexed_attestation(second));
        let mut ssz = 8u32.to_le_bytes().to_vec();
        ssz.extend_from_slice(&(8 + first.len() as u32).to_le_bytes());
        ssz.extend(first);
        ssz.extend(second);
        ssz
    }

    #[test]
    fn slashings_list_in_admission_order_until_removed() {
        let mut ctx = anchor_ctx();
        let mut handoff = submissions();
        let mut hand_off = |bytes: &[u8]| {
            handoff.write_with(bytes.len(), |out| out.copy_from_slice(bytes)).unwrap()
        };
        let changes = [
            PoolChange::AttesterSlashingAdded {
                id: 4,
                ssz: hand_off(&attester_slashing(&[2], &[2, 7])),
            },
            PoolChange::ProposerSlashingAdded { id: 3, ssz: hand_off(&proposer_slashing(6)) },
            PoolChange::AttesterSlashingAdded {
                id: 1,
                ssz: hand_off(&attester_slashing(&[5], &[5])),
            },
        ];
        for change in changes {
            ctx.pools.apply(change, |ssz| Some(handoff.read_buffer(ssz).unwrap().into()));
        }

        let proposers = pool(&ctx, "/eth/v1/beacon/pool/proposer_slashings");
        let [slashing] = &proposers[..] else { panic!("one proposer slashing: {proposers:?}") };
        let header = &slashing["signed_header_2"];
        assert_eq!(header["message"]["proposer_index"], "6");
        assert_eq!(header["message"]["slot"], "9");
        assert_eq!(header["message"]["body_root"], format!("0x{}", "11".repeat(32)));
        assert_eq!(header["signature"], format!("0x{}", "44".repeat(96)));

        let path = "/eth/v2/beacon/pool/attester_slashings";
        let response = answer(&ctx, &request("GET", path));
        let version = ctx.spec.fork_at_slot(ctx.node_status.wall_slot).name();
        let header = format!("Eth-Consensus-Version: {version}\r\n");
        assert!(std::str::from_utf8(&response).unwrap().contains(&header));
        let body = json(&response);
        assert_eq!(body["version"], version);
        let first_indices: Vec<_> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slashing| slashing["attestation_1"]["attesting_indices"][0].clone())
            .collect();
        assert_eq!(first_indices, ["5", "2"], "admission order");
        assert_eq!(
            body["data"][1]["attestation_2"]["attesting_indices"],
            serde_json::json!(["2", "7"])
        );

        ctx.pools.apply(PoolChange::AttesterSlashingRemoved { id: 1 }, |_| None);
        ctx.pools.apply(PoolChange::ProposerSlashingRemoved { id: 3 }, |_| None);
        assert_eq!(pool(&ctx, path).len(), 1);
        assert!(pool(&ctx, "/eth/v1/beacon/pool/proposer_slashings").is_empty());
    }

    #[test]
    fn a_slashing_overwritten_before_mirroring_is_missed() {
        let mut ctx = anchor_ctx();
        let mut handoff = submissions();
        let ssz = handoff.write_with(4, |out| out.fill(0)).unwrap();
        ctx.pools.apply(PoolChange::ProposerSlashingAdded { id: 0, ssz }, |_| None);
        assert!(pool(&ctx, "/eth/v1/beacon/pool/proposer_slashings").is_empty());
    }

    #[test]
    fn pools_list_their_entries_in_validator_order_until_removed() {
        let mut ctx = anchor_ctx();
        for change in [
            PoolChange::ExitAdded(exit(9)),
            PoolChange::ExitAdded(exit(2)),
            PoolChange::BlsChangeAdded(bls_change(5)),
        ] {
            ctx.pools.apply(change, |_| None);
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

        ctx.pools.apply(PoolChange::ExitRemoved { validator_index: 2 }, |_| None);
        ctx.pools.apply(PoolChange::BlsChangeRemoved { validator_index: 5 }, |_| None);
        assert_eq!(pool(&ctx, "/eth/v1/beacon/pool/voluntary_exits").len(), 1);
        assert!(pool(&ctx, "/eth/v1/beacon/pool/bls_to_execution_changes").is_empty());
    }
}
