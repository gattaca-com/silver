//! SSZ-shape and bounds validation for inbound RPC payloads. Crypto-level
//! checks (BLS proposer signature, KZG proofs, root match against the
//! request) are deferred to whichever consumer of `RpcMsgIn` cares —
//! typically the beacon-state tile.

use silver_common::{
    RpcSeverity,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, GOODBYE_SIZE, MAX_REQUEST_BLOCKS_DENEB, METADATA_SIZE, PING_SIZE,
        STATUS_V1_SIZE, STATUS_V2_SIZE,
    },
};

/// Outcome of validating an inbound RPC payload before it crosses the
/// spine boundary as `RpcMsgIn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Payload size doesn't match the spec for the negotiated protocol.
    BadSize,
    /// A list field exceeds its spec-defined cap (e.g. count >
    /// `MAX_REQUEST_BLOCKS_DENEB`).
    OutOfBounds,
    /// Response chunk's leading status byte is not a recognised value
    /// (0/1/2/3 per the eth2 RPC spec).
    BadResultCode,
    /// Per-protocol shape check failed (e.g. step != 1 in v2 BlocksByRange).
    BadShape,
}

impl ValidationError {
    /// Map to the severity level the peer manager should apply via
    /// `PeerEvent::RpcMisbehaviour`. All shape-level errors are
    /// `LowTolerance` — they're cheap protocol violations, not cryptographic
    /// forgeries. (Crypto violations live in the consumer and use `Fatal`.)
    pub fn severity(self) -> RpcSeverity {
        RpcSeverity::LowTolerance
    }
}

/// Verify a Status payload (v1 or v2) is exactly the spec'd size.
#[inline]
pub fn check_status(buf: &[u8]) -> Result<(), ValidationError> {
    if buf.len() == STATUS_V1_SIZE || buf.len() == STATUS_V2_SIZE {
        Ok(())
    } else {
        Err(ValidationError::BadSize)
    }
}

/// Ping & Goodbye share the same wire shape (uint64); both expect 8 bytes.
#[inline]
pub fn check_uint64_payload(buf: &[u8]) -> Result<(), ValidationError> {
    if buf.len() == PING_SIZE { Ok(()) } else { Err(ValidationError::BadSize) }
}

#[inline]
pub fn check_ping(buf: &[u8]) -> Result<(), ValidationError> {
    debug_assert_eq!(PING_SIZE, GOODBYE_SIZE);
    check_uint64_payload(buf)
}

#[inline]
pub fn check_goodbye(buf: &[u8]) -> Result<(), ValidationError> {
    check_uint64_payload(buf)
}

#[inline]
pub fn check_metadata(buf: &[u8]) -> Result<(), ValidationError> {
    if buf.len() == METADATA_SIZE { Ok(()) } else { Err(ValidationError::BadSize) }
}

/// Verify a `BeaconBlocksByRangeRequest` payload: exact 24-byte size and
/// `count` within spec cap. Step must be 1 in v2 of the protocol.
pub fn check_blocks_by_range_request(buf: &[u8]) -> Result<(), ValidationError> {
    if buf.len() != BLOCKS_BY_RANGE_REQ_SIZE {
        return Err(ValidationError::BadSize);
    }
    let count = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    if (count as usize) > MAX_REQUEST_BLOCKS_DENEB {
        return Err(ValidationError::OutOfBounds);
    }
    let step = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    if step != 1 {
        return Err(ValidationError::BadShape);
    }
    Ok(())
}

/// Verify a `BeaconBlocksByRootRequest` payload: list of 32-byte roots,
/// total length must be a multiple of 32, count within spec cap.
pub fn check_blocks_by_root_request(buf: &[u8]) -> Result<(), ValidationError> {
    if !buf.len().is_multiple_of(32) {
        return Err(ValidationError::BadSize);
    }
    let count = buf.len() / 32;
    if count > MAX_REQUEST_BLOCKS_DENEB {
        return Err(ValidationError::OutOfBounds);
    }
    Ok(())
}

/// Verify a response chunk's leading status byte. Spec values:
///   0 = success, 1 = invalid request, 2 = server error,
///   3 = resource unavailable.
#[inline]
pub fn check_result_code(code: u8) -> Result<(), ValidationError> {
    if code <= 3 { Ok(()) } else { Err(ValidationError::BadResultCode) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_size_check() {
        assert!(check_status(&[0u8; STATUS_V1_SIZE]).is_ok());
        assert!(check_status(&[0u8; STATUS_V2_SIZE]).is_ok());
        assert_eq!(check_status(&[0u8; 50]), Err(ValidationError::BadSize));
        assert_eq!(check_status(&[0u8; 100]), Err(ValidationError::BadSize));
    }

    #[test]
    fn ping_goodbye_size() {
        assert!(check_ping(&[0u8; PING_SIZE]).is_ok());
        assert!(check_goodbye(&[0u8; GOODBYE_SIZE]).is_ok());
        assert_eq!(check_ping(&[0u8; 7]), Err(ValidationError::BadSize));
    }

    #[test]
    fn metadata_size() {
        assert!(check_metadata(&[0u8; METADATA_SIZE]).is_ok());
        assert_eq!(check_metadata(&[0u8; 24]), Err(ValidationError::BadSize));
    }

    #[test]
    fn blocks_by_range_count_cap() {
        let mut buf = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        buf[8..16].copy_from_slice(&(MAX_REQUEST_BLOCKS_DENEB as u64).to_le_bytes());
        buf[16..24].copy_from_slice(&1u64.to_le_bytes());
        assert!(check_blocks_by_range_request(&buf).is_ok());

        buf[8..16].copy_from_slice(&((MAX_REQUEST_BLOCKS_DENEB as u64) + 1).to_le_bytes());
        assert_eq!(check_blocks_by_range_request(&buf), Err(ValidationError::OutOfBounds));
    }

    #[test]
    fn blocks_by_range_step_must_be_one() {
        let mut buf = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        buf[16..24].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(check_blocks_by_range_request(&buf), Err(ValidationError::BadShape));
    }

    #[test]
    fn blocks_by_root_size() {
        let buf = vec![0u8; 32 * 4]; // 4 roots, valid
        assert!(check_blocks_by_root_request(&buf).is_ok());
        let bad = vec![0u8; 33]; // not multiple of 32
        assert_eq!(check_blocks_by_root_request(&bad), Err(ValidationError::BadSize));
        let too_many = vec![0u8; 32 * (MAX_REQUEST_BLOCKS_DENEB + 1)];
        assert_eq!(check_blocks_by_root_request(&too_many), Err(ValidationError::OutOfBounds));
    }

    #[test]
    fn result_code_range() {
        for c in 0..=3u8 {
            assert!(check_result_code(c).is_ok(), "code {c} should be valid");
        }
        assert_eq!(check_result_code(4), Err(ValidationError::BadResultCode));
        assert_eq!(check_result_code(255), Err(ValidationError::BadResultCode));
    }
}
