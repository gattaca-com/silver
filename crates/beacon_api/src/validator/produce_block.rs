use flux_profiler::timed;
use silver_beacon_state_data::{Slot, SpecConfig};
use silver_common::{
    BeaconApiRequest, PayloadFrame, ProduceBlockFailure, ProducedBlock, TCacheReader,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{parse_hex, parse_uint64},
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

pub(crate) fn produce_block_v3(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    let slot = req.params.get("slot").expect("{slot} in the route pattern");
    let Some(slot) = parse_uint64(slot) else {
        return resp.error(400, "invalid slot");
    };
    let Some(randao_reveal) = req.query_value("randao_reveal").and_then(|text| parse_hex(&text))
    else {
        return resp.error(400, "randao_reveal is a required BLSSignature query parameter");
    };
    let graffiti = match req.query_value("graffiti") {
        None => [0; 32],
        Some(text) => match parse_graffiti(&text) {
            Some(graffiti) => graffiti,
            None => return resp.error(400, "invalid graffiti"),
        },
    };

    resp.defer(Outcome::AwaitingProducedBlock(ProduceBlockRequest {
        slot,
        randao_reveal,
        graffiti,
    }));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProduceBlockRequest {
    slot: Slot,
    randao_reveal: [u8; 96],
    graffiti: [u8; 32],
}

impl ProduceBlockRequest {
    pub(crate) fn state_request(self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::ProduceBlock {
            request_id,
            slot: self.slot,
            randao_reveal: self.randao_reveal,
            graffiti: self.graffiti,
        }
    }

    #[timed]
    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        block: Result<ProducedBlock, ProduceBlockFailure>,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let block = match block {
            Ok(block) => block,
            Err(ProduceBlockFailure::SlotNotProposable) => {
                return resp.error(400, "the slot does not follow the head");
            }
            Err(ProduceBlockFailure::InvalidRandaoReveal) => {
                return resp.error(400, "randao_reveal is not the proposer's signature");
            }
            Err(ProduceBlockFailure::NoFeeRecipient) => {
                return resp.error(400, "no fee recipient was prepared for the slot's proposer");
            }
            Err(ProduceBlockFailure::PayloadUnavailable) => {
                return resp.error(503, "the execution client built no payload");
            }
            Err(ProduceBlockFailure::Invalid | ProduceBlockFailure::Internal) => {
                return resp.error(500, "the block could not be produced");
            }
        };
        let header = reader.acquire(block.header);
        let payload = reader.acquire(block.payload);
        let (Ok((head, _)), Ok((payload, _))) = (header.buffer(), payload.buffer()) else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let Some(payload) = PayloadFrame::parse(payload) else {
            silver_log::error!(slot = self.slot, "produced block's payload frame is misframed");
            return resp.error(500, "the block could not be read");
        };
        let Some((before_payload, bls_changes)) = head.split_at_checked(block.payload_at as usize)
        else {
            silver_log::error!(
                slot = self.slot,
                "produced block is shorter than its payload offset"
            );
            return resp.error(500, "the block could not be read");
        };
        let payload_value = wei_decimal(&block.execution_payload_value);
        let headers = [
            ("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name()),
            ("Eth-Execution-Payload-Blinded", "false"),
            ("Eth-Execution-Payload-Value", payload_value.as_str()),
            // TODO: The body packs nothing that pays the proposer yet.
            ("Eth-Consensus-Block-Value", "0"),
        ];
        let parts = [before_payload, payload.execution_payload, bls_changes, payload.after_payload];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &parts);
    }
}

/// Prysm sends graffiti from proposer settings unpadded; the block carries
/// it zero-padded on the right.
fn parse_graffiti(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("0x")?;
    let mut graffiti = [0; 32];
    hex::decode_to_slice(hex, graffiti.get_mut(..hex.len() / 2)?).ok()?;
    Some(graffiti)
}

fn wei_decimal(little_endian: &[u8; 32]) -> String {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(little_endian.chunks_exact(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
    }
    let mut digits = Vec::new();
    loop {
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let current = (remainder << 64) | u128::from(*limb);
            *limb = (current / 10) as u64;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
        if limbs == [0; 4] {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, ctx},
        testing::{dispatch, request, status_code},
    };

    fn get(query: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        let path = format!("/eth/v3/validator/blocks/{}", SLOT + 1);
        dispatch(&ctx(), &ParsedRequest { query, accept, ..request("GET", &path) })
    }

    fn randao() -> String {
        format!("randao_reveal=0x{}", "11".repeat(96))
    }

    #[test]
    fn request_defers_to_the_state_tile_with_the_query() {
        let query = format!("{}&graffiti=0x{}", randao(), "22".repeat(32));
        let (outcome, out) = get(&query, Some(SSZ_MEDIA_TYPE));
        assert!(out.is_empty());
        assert_eq!(
            outcome,
            Outcome::AwaitingProducedBlock(ProduceBlockRequest {
                slot: SLOT + 1,
                randao_reveal: [0x11; 96],
                graffiti: [0x22; 32],
            })
        );
    }

    #[test]
    fn graffiti_defaults_to_zero() {
        let (outcome, _) = get(&randao(), Some(SSZ_MEDIA_TYPE));
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        assert_eq!(request.graffiti, [0; 32]);
    }

    #[test]
    fn json_only_client_is_a_406() {
        let (outcome, out) = get(&randao(), Some("application/json"));
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "406");
    }

    #[test]
    fn short_graffiti_is_zero_padded() {
        let (outcome, _) = get(&format!("{}&graffiti=0x6869", randao()), Some(SSZ_MEDIA_TYPE));
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        let mut expected = [0; 32];
        expected[..2].copy_from_slice(b"hi");
        assert_eq!(request.graffiti, expected);
    }

    #[test]
    fn missing_or_malformed_parameters_are_400() {
        for query in [
            String::new(),
            "randao_reveal=0x11".to_owned(),
            format!("{}&graffiti=0x222", randao()),
            format!("{}&graffiti=0x{}", randao(), "22".repeat(33)),
        ] {
            let (outcome, out) = get(&query, Some(SSZ_MEDIA_TYPE));
            assert_eq!(outcome, Outcome::Response(None), "{query}");
            assert_eq!(status_code(&out), "400", "{query}");
        }
    }

    #[test]
    fn wei_decimal_renders_every_limb() {
        assert_eq!(wei_decimal(&[0; 32]), "0");
        let mut two_ether = [0; 32];
        two_ether[..8].copy_from_slice(&2_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(wei_decimal(&two_ether), "2000000000000000000");
        let mut two_to_64 = [0; 32];
        two_to_64[8] = 1;
        assert_eq!(wei_decimal(&two_to_64), "18446744073709551616");
    }
}
