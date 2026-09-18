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
    use silver_beacon_state_data::{B256, BLSPubkey, BlockRootsGroup, SLOTS_PER_HISTORICAL_ROOT};
    use silver_httpcore::ParsedRequest;

    use crate::{
        router::{Outcome, Router},
        routes::{ApiCtx, ROUTES},
    };

    /// The pubkey a test registry holds for `validator_index`, which spells
    /// the index itself so a body can be read back from a response.
    pub(crate) fn pubkey(validator_index: u64) -> BLSPubkey {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&validator_index.to_le_bytes());
        pubkey
    }

    /// The `[\"1\",\"2\"]` array of quoted `Uint64`s every duties POST takes.
    pub(crate) fn indices_body(indices: impl Iterator<Item = u64>) -> String {
        let quoted: Vec<_> = indices.map(|index| format!("\"{index}\"")).collect();
        format!("[{}]", quoted.join(","))
    }

    pub(crate) fn post_duties(ctx: &ApiCtx, path: &str, body: &str) -> Vec<u8> {
        let req = ParsedRequest {
            method: "POST",
            path,
            query: "",
            body: body.as_bytes(),
            accept: None,
            content_type: Some("application/json"),
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        assert_eq!(Router::new(ROUTES).dispatch(&req, ctx, &mut out), Outcome::Response);
        out
    }

    pub(crate) fn status_code(response: &[u8]) -> &str {
        std::str::from_utf8(response).unwrap().split(' ').nth(1).unwrap()
    }

    /// The body of a 200, parsed.
    pub(crate) fn json(response: &[u8]) -> serde_json::Value {
        let text = std::str::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        serde_json::from_str(&text[text.find("\r\n\r\n").unwrap() + 4..]).unwrap()
    }

    /// A quoted `Uint64` field, as every duty spells its numbers.
    pub(crate) fn field(value: &serde_json::Value, name: &str) -> u64 {
        value[name].as_str().unwrap().parse().unwrap()
    }

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
