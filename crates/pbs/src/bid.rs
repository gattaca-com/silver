use blst::{
    BLST_ERROR,
    min_pk::{PublicKey, Signature},
};
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot, SpecConfig};
use silver_common::SidecarBidRequest;
use silver_ssz::{
    merkle::{ZERO_HASH, hash_concat},
    ssz_hash::{hash_builder_bid_fulu, hash_tree_root_fork_data},
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, BuilderBidFuluView, ExecutionPayloadHeaderFuluView,
        SignedBuilderBidFuluView,
    },
};

use crate::FULU;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const DOMAIN_APPLICATION_BUILDER: [u8; 4] = [0, 0, 0, 1];

const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1024;

pub(crate) fn builder_domain(genesis_fork_version: [u8; 4]) -> B256 {
    let mut domain = hash_tree_root_fork_data(genesis_fork_version, &ZERO_HASH);
    domain.copy_within(..28, 4);
    domain[..4].copy_from_slice(&DOMAIN_APPLICATION_BUILDER);
    domain
}

pub(crate) struct BidRequest {
    pub(crate) slot: Slot,
    pub(crate) parent_hash: B256,
    prev_randao: B256,
    timestamp: u64,
    block_number: u64,
    withdrawals_root: B256,
    gas_limit: u64,
    max_blobs: usize,
}

#[derive(Debug)]
pub(crate) enum BidRefusal {
    Fork,
    Malformed,
    ParentHash,
    PrevRandao,
    Timestamp,
    BlockNumber,
    WithdrawalsRoot,
    GasLimit,
    BlobCount,
    RelayPubkey,
    Signature,
}

impl BidRequest {
    pub(crate) fn new(
        request: &SidecarBidRequest,
        registered_gas_limit: u64,
        spec: &SpecConfig,
        genesis_time: u64,
    ) -> Self {
        let slot = request.slot;
        Self {
            slot,
            parent_hash: request.parent_hash,
            prev_randao: request.prev_randao,
            timestamp: genesis_time + slot * spec.seconds_per_slot(),
            block_number: request.block_number,
            withdrawals_root: request.withdrawals_root,
            gas_limit: expected_gas_limit(request.parent_gas_limit, registered_gas_limit),
            max_blobs: spec.blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block as usize,
        }
    }

    pub(crate) fn check(
        &self,
        signed_bid: &[u8],
        consensus_version: Option<&[u8]>,
        builder_domain: &B256,
    ) -> Result<(), BidRefusal> {
        if consensus_version != Some(FULU.as_bytes()) {
            return Err(BidRefusal::Fork);
        }
        if !SignedBuilderBidFuluView::check_canonical(signed_bid) {
            return Err(BidRefusal::Malformed);
        }
        let bid = SignedBuilderBidFuluView::message(signed_bid);
        let header = BuilderBidFuluView::header(bid);
        if *ExecutionPayloadHeaderFuluView::parent_hash(header) != self.parent_hash {
            return Err(BidRefusal::ParentHash);
        }
        if *ExecutionPayloadHeaderFuluView::prev_randao(header) != self.prev_randao {
            return Err(BidRefusal::PrevRandao);
        }
        if ExecutionPayloadHeaderFuluView::timestamp(header) != self.timestamp {
            return Err(BidRefusal::Timestamp);
        }
        if ExecutionPayloadHeaderFuluView::block_number(header) != self.block_number {
            return Err(BidRefusal::BlockNumber);
        }
        if *ExecutionPayloadHeaderFuluView::withdrawals_root(header) != self.withdrawals_root {
            return Err(BidRefusal::WithdrawalsRoot);
        }
        if ExecutionPayloadHeaderFuluView::gas_limit(header) != self.gas_limit {
            return Err(BidRefusal::GasLimit);
        }
        let blobs = BuilderBidFuluView::blob_kzg_commitments(bid).len() / BYTES_PER_KZG_COMMITMENT;
        if blobs > self.max_blobs {
            return Err(BidRefusal::BlobCount);
        }

        let Ok(relay) = PublicKey::key_validate(BuilderBidFuluView::pubkey(bid)) else {
            return Err(BidRefusal::RelayPubkey);
        };
        let Ok(signature) = Signature::from_bytes(SignedBuilderBidFuluView::signature(signed_bid))
        else {
            return Err(BidRefusal::Signature);
        };
        let signing_root = hash_concat(&hash_builder_bid_fulu(bid), builder_domain);
        if signature.verify(true, &signing_root, DST, &[], &relay, false) !=
            BLST_ERROR::BLST_SUCCESS
        {
            return Err(BidRefusal::Signature);
        }
        Ok(())
    }
}

/// The furthest the EL may move the gas limit from `parent` toward the
/// registration's `target` in one block.
fn expected_gas_limit(parent: u64, target: u64) -> u64 {
    let max_step = (parent / GAS_LIMIT_ADJUSTMENT_FACTOR).saturating_sub(1);
    if target > parent {
        parent + (target - parent).min(max_step)
    } else {
        parent - (parent - target).min(max_step)
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;
    use silver_httpcore::ClientResponse;
    use silver_ssz::ssz_view::{BUILDER_BID_FULU_FIXED, EXECUTION_PAYLOAD_HEADER_FIXED};

    use super::*;
    use crate::json_bid::JsonBid;

    const FULU: Option<&[u8]> = Some(b"fulu");
    const PARENT_HASH: B256 = [0x11; 32];
    const PREV_RANDAO: B256 = [0x44; 32];
    const TIMESTAMP: u64 = 1_700_000_012;
    const BLOCK_NUMBER: u64 = 9;
    const WITHDRAWALS_ROOT: B256 = [0x55; 32];
    const PARENT_GAS_LIMIT: u64 = 30_000_000;

    /// The registration targets the parent's gas limit, so the bid keeps it.
    fn request() -> BidRequest {
        let request = SidecarBidRequest {
            slot: 1,
            parent_hash: PARENT_HASH,
            prev_randao: PREV_RANDAO,
            withdrawals_root: WITHDRAWALS_ROOT,
            block_number: BLOCK_NUMBER,
            parent_gas_limit: PARENT_GAS_LIMIT,
            proposer_pubkey: [0; 48],
        };
        let spec = SpecConfig::mainnet();
        BidRequest::new(&request, PARENT_GAS_LIMIT, &spec, TIMESTAMP - spec.seconds_per_slot())
    }

    fn domain() -> B256 {
        builder_domain([0; 4])
    }

    fn unsigned_bid() -> Vec<u8> {
        let header_start = 100 + BUILDER_BID_FULU_FIXED;
        let requests_start = (BUILDER_BID_FULU_FIXED + EXECUTION_PAYLOAD_HEADER_FIXED) as u32;
        let mut ssz = vec![0; header_start + EXECUTION_PAYLOAD_HEADER_FIXED];
        ssz[..4].copy_from_slice(&100u32.to_le_bytes());
        let bid = &mut ssz[100..];
        bid[..4].copy_from_slice(&(BUILDER_BID_FULU_FIXED as u32).to_le_bytes());
        bid[4..8].copy_from_slice(&requests_start.to_le_bytes());
        bid[8..12].copy_from_slice(&requests_start.to_le_bytes());
        bid[12] = 7;
        let header = &mut bid[BUILDER_BID_FULU_FIXED..];
        header[..32].copy_from_slice(&PARENT_HASH);
        header[372..404].copy_from_slice(&PREV_RANDAO);
        header[404..412].copy_from_slice(&BLOCK_NUMBER.to_le_bytes());
        header[412..420].copy_from_slice(&PARENT_GAS_LIMIT.to_le_bytes());
        header[428..436].copy_from_slice(&TIMESTAMP.to_le_bytes());
        header[536..568].copy_from_slice(&WITHDRAWALS_ROOT);
        header[436..440].copy_from_slice(&(EXECUTION_PAYLOAD_HEADER_FIXED as u32).to_le_bytes());
        ssz.extend_from_slice(&[12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0]);
        ssz
    }

    fn unsigned_bid_with_blobs(blobs: usize) -> Vec<u8> {
        let mut ssz = unsigned_bid();
        let commitments_at = 100 + BUILDER_BID_FULU_FIXED + EXECUTION_PAYLOAD_HEADER_FIXED;
        let commitments = blobs * BYTES_PER_KZG_COMMITMENT;
        ssz.splice(commitments_at..commitments_at, std::iter::repeat_n(0xc0, commitments));
        let requests_at = (commitments_at - 100 + commitments) as u32;
        ssz[108..112].copy_from_slice(&requests_at.to_le_bytes());
        ssz
    }

    fn signed(mut ssz: Vec<u8>) -> Vec<u8> {
        let key = SecretKey::key_gen(&[0x33; 32], &[]).unwrap();
        ssz[100 + 44..100 + BUILDER_BID_FULU_FIXED].copy_from_slice(&key.sk_to_pk().to_bytes());
        let root = hash_concat(&hash_builder_bid_fulu(&ssz[100..]), &domain());
        ssz[4..100].copy_from_slice(&key.sign(&root, DST, &[]).to_bytes());
        ssz
    }

    fn signed_json(bid: &[u8]) -> Vec<u8> {
        let hex = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));
        serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": hex(&PARENT_HASH),
                        "fee_recipient": hex(&[0; 20]),
                        "state_root": hex(&[0; 32]),
                        "receipts_root": hex(&[0; 32]),
                        "logs_bloom": hex(&[0; 256]),
                        "prev_randao": hex(&PREV_RANDAO),
                        "block_number": BLOCK_NUMBER.to_string(),
                        "gas_limit": PARENT_GAS_LIMIT.to_string(),
                        "gas_used": "0",
                        "timestamp": TIMESTAMP.to_string(),
                        "extra_data": "0x",
                        "base_fee_per_gas": "0",
                        "block_hash": hex(&[0; 32]),
                        "transactions_root": hex(&[0; 32]),
                        "withdrawals_root": hex(&WITHDRAWALS_ROOT),
                        "blob_gas_used": "0",
                        "excess_blob_gas": "0"
                    },
                    "blob_kzg_commitments": [],
                    "execution_requests": {"deposits": [], "withdrawals": [], "consolidations": []},
                    "value": "7",
                    "pubkey": hex(BuilderBidFuluView::pubkey(&bid[100..]))
                },
                "signature": hex(SignedBuilderBidFuluView::signature(bid))
            }
        }))
        .unwrap()
    }

    #[test]
    fn signed_response_ssz_control() {
        let expected = signed(unsigned_bid());
        let mut body = expected.clone();
        let response = ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\nEth-Consensus-Version: fulu\r\n\r\n",
            body: &mut body,
        };
        let mut decoder = JsonBid::new();
        let decoded = decoder.ssz_bid(response);
        assert_eq!(decoded.bytes, expected);
        request().check(decoded.bytes, decoded.version, &domain()).unwrap();
    }

    #[test]
    fn signed_response_headerless_json() {
        let expected = signed(unsigned_bid());
        let mut body = signed_json(&expected);
        let response = ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
            body: &mut body,
        };
        let mut decoder = JsonBid::new();
        let decoded = decoder.ssz_bid(response);
        assert_eq!(decoded.bytes, expected);
        request().check(decoded.bytes, decoded.version, &domain()).unwrap();
    }

    #[test]
    fn signed_json_http_version_is_authoritative() {
        let expected = signed(unsigned_bid());
        let json = String::from_utf8(signed_json(&expected)).unwrap();
        let mut decoder = JsonBid::new();
        for (http, json_version, accepted) in [
            ("fulu", r#""fulu""#, true),
            ("fulu", r#""gloas""#, true),
            ("gloas", r#""fulu""#, false),
            ("electra", r#""fulu""#, false),
            ("", r#""fulu""#, false),
            ("fulu", "null", true),
            ("fulu", r#"{},"version":42"#, true),
        ] {
            let mut body = json
                .replace(r#""version":"fulu""#, &format!(r#""version":{json_version}"#))
                .into_bytes();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nEth-Consensus-Version: {http}\r\n\r\n"
            );
            let decoded = decoder.ssz_bid(ClientResponse {
                status: 200,
                headers: headers.as_bytes(),
                body: &mut body,
            });
            assert_eq!(decoded.bytes, expected);
            assert_eq!(decoded.version, Some(http.as_bytes()));
            let checked = request().check(decoded.bytes, decoded.version, &domain());
            if accepted {
                checked.unwrap();
            } else {
                assert!(matches!(checked, Err(BidRefusal::Fork)));
            }
        }
    }

    #[test]
    fn signed_json_metadata_and_decoder_reuse() {
        let expected = signed(unsigned_bid());
        let json = String::from_utf8(signed_json(&expected)).unwrap();
        let data = serde_json::from_str::<serde_json::Value>(&json).unwrap()["data"].to_string();
        let mut decoder = JsonBid::new();
        for valid in [
            json.clone(),
            format!(r#"{{"version":"fulu","data":{data}}}"#),
            format!(r#"{{"data":{data},"version":"f\u0075lu"}}"#),
        ] {
            let mut body = valid.into_bytes();
            let decoded = decoder.ssz_bid(ClientResponse {
                status: 200,
                headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
                body: &mut body,
            });
            assert_eq!(decoded.bytes, expected);
            request().check(decoded.bytes, decoded.version, &domain()).unwrap();
        }
        for metadata in [
            "",
            r#","version":"""#,
            r#","version":"unknown""#,
            r#","version":"electra""#,
            r#","version":"gloas""#,
            r#","version":null"#,
            r#","version":42"#,
            r#","version":{}"#,
            r#","version":"fulu","version":"fulu""#,
        ] {
            let mut body = format!(r#"{{"data":{data}{metadata}}}"#).into_bytes();
            let decoded = decoder.ssz_bid(ClientResponse {
                status: 200,
                headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
                body: &mut body,
            });
            assert!(matches!(
                request().check(decoded.bytes, decoded.version, &domain()),
                Err(BidRefusal::Fork)
            ));
        }
        for invalid in [
            r#"{"version":"fulu","data":{"message":{"header":{}}}}"#,
            r#"{"version":"fulu","data":"#,
        ] {
            let mut body = invalid.as_bytes().to_vec();
            let decoded = decoder.ssz_bid(ClientResponse {
                status: 200,
                headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
                body: &mut body,
            });
            assert!(decoded.bytes.is_empty());
            assert!(decoded.version.is_none());
        }
        let mut body = signed_json(&expected);
        let decoded = decoder.ssz_bid(ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
            body: &mut body,
        });
        request().check(decoded.bytes, decoded.version, &domain()).unwrap();
        let mut body = expected.clone();
        let decoded = decoder.ssz_bid(ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\n\r\n",
            body: &mut body,
        });
        assert_eq!(decoded.bytes, expected);
        assert!(decoded.version.is_none());
        assert!(matches!(
            request().check(decoded.bytes, decoded.version, &domain()),
            Err(BidRefusal::Fork)
        ));
    }

    #[test]
    fn signed_json_fallback_preserves_validation() {
        let expected = signed(unsigned_bid());
        let mut decoder = JsonBid::new();
        let mut body = signed_json(&expected);
        let decoded = decoder.ssz_bid(ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
            body: &mut body,
        });
        let check = |request: BidRequest| request.check(decoded.bytes, decoded.version, &domain());
        assert!(matches!(
            check(BidRequest { parent_hash: [1; 32], ..request() }),
            Err(BidRefusal::ParentHash)
        ));
        assert!(matches!(
            check(BidRequest { timestamp: TIMESTAMP + 1, ..request() }),
            Err(BidRefusal::Timestamp)
        ));
        assert!(matches!(
            check(BidRequest { gas_limit: PARENT_GAS_LIMIT + 1, ..request() }),
            Err(BidRefusal::GasLimit)
        ));
        assert!(matches!(
            request().check(decoded.bytes, decoded.version, &builder_domain([1; 4])),
            Err(BidRefusal::Signature)
        ));
        let mut altered = expected;
        altered[4] ^= 1;
        let mut body = signed_json(&altered);
        let decoded = decoder.ssz_bid(ClientResponse {
            status: 200,
            headers: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
            body: &mut body,
        });
        assert!(matches!(
            request().check(decoded.bytes, decoded.version, &domain()),
            Err(BidRefusal::Signature)
        ));
    }

    #[test]
    fn header_fetch_returns_signed_json_and_ssz() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
            time::{Duration, Instant},
        };

        use silver_config::PbsConfig;
        use silver_httpcore::{Readiness, TokenRange};

        use crate::header_fetch::HeaderFetch;

        let expected = signed(unsigned_bid());
        for (body, metadata) in [
            (signed_json(&expected), "Content-Type: application/json\r\n"),
            (expected.clone(), "Eth-Consensus-Version: fulu\r\n"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let config = PbsConfig::new(format!("http://{}", listener.local_addr().unwrap()));
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                assert!(request.starts_with(b"GET /eth/v1/builder/header/1/"));
                let head =
                    format!("HTTP/1.1 200 OK\r\n{metadata}Content-Length: {}\r\n\r\n", body.len());
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            });
            let spec = SpecConfig::mainnet();
            let mut readiness = Readiness::new(16);
            let mut fetch = HeaderFetch::new(
                TokenRange::whole(),
                &config,
                &spec,
                TIMESTAMP - spec.seconds_per_slot(),
            );
            let request = SidecarBidRequest {
                slot: 1,
                parent_hash: PARENT_HASH,
                prev_randao: PREV_RANDAO,
                withdrawals_root: WITHDRAWALS_ROOT,
                block_number: BLOCK_NUMBER,
                parent_gas_limit: PARENT_GAS_LIMIT,
                proposer_pubkey: [0; 48],
            };
            assert!(fetch.fetch(&request, PARENT_GAS_LIMIT, readiness.registry()));
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut answer = None;
            while answer.is_none() {
                assert!(Instant::now() < deadline, "no header response");
                readiness.wait(Duration::from_millis(5));
                fetch.spin(readiness.events(), readiness.registry(), &mut |request, bid| {
                    assert_eq!(request.slot, 1);
                    assert_eq!(request.parent_hash, PARENT_HASH);
                    answer = Some(bid.unwrap().to_vec());
                });
            }
            assert_eq!(answer.unwrap(), expected);
            server.join().unwrap();
        }
    }

    #[test]
    fn mainnet_builder_domain() {
        assert_eq!(
            hex::encode(domain()),
            "00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
        );
    }

    #[test]
    fn signed_bid_passes() {
        let bid = signed(unsigned_bid());
        request().check(&bid, FULU, &domain()).unwrap();
    }

    #[test]
    fn bid_altered_after_signing_is_refused() {
        let mut bid = signed(unsigned_bid());
        bid[100 + 12] += 1;
        assert!(matches!(request().check(&bid, FULU, &domain()), Err(BidRefusal::Signature)));
    }

    #[test]
    fn bid_signed_under_another_domain_is_refused() {
        let bid = signed(unsigned_bid());
        let sepolia = builder_domain([0x90, 0x00, 0x00, 0x69]);
        assert!(matches!(request().check(&bid, FULU, &sepolia), Err(BidRefusal::Signature)));
    }

    #[test]
    fn bid_for_another_parent_or_slot_is_refused() {
        let bid = signed(unsigned_bid());
        let other_parent = BidRequest { parent_hash: [0x12; 32], ..request() };
        assert!(matches!(other_parent.check(&bid, FULU, &domain()), Err(BidRefusal::ParentHash)));
        let other_slot = BidRequest { timestamp: TIMESTAMP + 12, ..request() };
        assert!(matches!(other_slot.check(&bid, FULU, &domain()), Err(BidRefusal::Timestamp)));
    }

    #[test]
    fn bid_whose_header_misstates_the_payload_attributes_is_refused() {
        let bid = signed(unsigned_bid());
        let check = |request: BidRequest| request.check(&bid, FULU, &domain());
        let other_randao = BidRequest { prev_randao: [0x45; 32], ..request() };
        assert!(matches!(check(other_randao), Err(BidRefusal::PrevRandao)));
        let other_number = BidRequest { block_number: BLOCK_NUMBER + 1, ..request() };
        assert!(matches!(check(other_number), Err(BidRefusal::BlockNumber)));
        let other_withdrawals = BidRequest { withdrawals_root: [0x56; 32], ..request() };
        assert!(matches!(check(other_withdrawals), Err(BidRefusal::WithdrawalsRoot)));
        let other_gas_limit = BidRequest { gas_limit: PARENT_GAS_LIMIT + 1, ..request() };
        assert!(matches!(check(other_gas_limit), Err(BidRefusal::GasLimit)));
    }

    #[test]
    fn bid_over_the_slot_s_blob_limit_is_refused() {
        let max = request().max_blobs;
        let at_limit = signed(unsigned_bid_with_blobs(max));
        request().check(&at_limit, FULU, &domain()).unwrap();
        let over = signed(unsigned_bid_with_blobs(max + 1));
        assert!(matches!(request().check(&over, FULU, &domain()), Err(BidRefusal::BlobCount)));
    }

    #[test]
    fn gas_limit_moves_toward_the_target_by_at_most_a_1024th() {
        let parent = 30_000_000;
        let step = parent / 1024 - 1;
        assert_eq!(expected_gas_limit(parent, parent), parent);
        assert_eq!(expected_gas_limit(parent, 60_000_000), parent + step);
        assert_eq!(expected_gas_limit(parent, parent + 10), parent + 10);
        assert_eq!(expected_gas_limit(parent, 0), parent - step);
        assert_eq!(expected_gas_limit(1023, 0), 1023);
    }

    #[test]
    fn bid_for_another_fork_or_none_named_is_refused() {
        let bid = signed(unsigned_bid());
        for version in [Some(b"electra".as_ref()), Some(b"gloas"), None] {
            assert!(matches!(request().check(&bid, version, &domain()), Err(BidRefusal::Fork)));
        }
    }

    #[test]
    fn non_canonical_bid_is_refused() {
        let mut bid = signed(unsigned_bid());
        bid.push(0);
        assert!(matches!(request().check(&bid, FULU, &domain()), Err(BidRefusal::Malformed)));
        assert!(matches!(
            request().check(&bid[..150], FULU, &domain()),
            Err(BidRefusal::Malformed)
        ));
    }
}
