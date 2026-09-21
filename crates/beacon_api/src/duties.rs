use silver_beacon_state_data::Epoch;

use crate::{
    ids::{ValidatorIndex, body_entries, parse_uint64},
    response::Response,
    router::Request,
};

pub(crate) fn epoch_param(req: &Request<'_>, resp: &mut Response<'_>) -> Option<Epoch> {
    let epoch = req.params.get("epoch").expect("{epoch} in the route pattern");
    let parsed = parse_uint64(epoch);
    if parsed.is_none() {
        resp.error(400, "invalid epoch");
    }
    parsed
}

pub(crate) fn requested_indices(
    req: &Request<'_>,
    resp: &mut Response<'_>,
) -> Option<Vec<ValidatorIndex>> {
    let mut indices: Vec<ValidatorIndex> = body_entries(req.body, resp)?;
    if indices.is_empty() {
        resp.error(400, "the body must name at least one validator");
        return None;
    }
    indices.sort_unstable();
    indices.dedup();
    Some(indices)
}

#[cfg(test)]
pub(crate) mod test_state {
    use silver_beacon_state_data::{B256, BlockRootsGroup, SLOTS_PER_HISTORICAL_ROOT};

    /// The block root the ring holds for `slot`, distinct per slot.
    pub(crate) fn ring_root(slot: u64) -> B256 {
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&slot.to_le_bytes());
        root
    }

    /// A ring whose every entry is [`ring_root`] of the slot it holds, for a
    /// state at `state_slot`.
    pub(crate) fn block_roots_ring(state_slot: u64) -> BlockRootsGroup {
        let ring_len = SLOTS_PER_HISTORICAL_ROOT as u64;
        let roots: Vec<u8> =
            (0..ring_len).flat_map(|i| ring_root(state_slot - state_slot % ring_len + i)).collect();
        BlockRootsGroup::vector(&roots).unwrap()
    }
}
