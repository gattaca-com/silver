use crate::{
    RpcRequest, StreamProtocol, TCacheError,
    ssz_view::{
        BeaconBlocksByRangeRequestView, DataColumnSidecarsByRangeRequestView,
        ExecutionPayloadEnvelopesByRangeRequestView,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataKind {
    Block = 0,
    Columns = 1,
    Envelope = 2,
}

impl DataKind {
    pub const ALL: [DataKind; 3] = [Self::Block, Self::Columns, Self::Envelope];

    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    Live = 0,
    Backfill = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Range { start: u64, count: u64 },
    Root([u8; 32]),
}

#[derive(Clone, Copy, Debug)]
pub struct SyncRequest {
    pub kind: DataKind,
    pub origin: Origin,
    pub scope: Scope,
    /// The columns wanted. Read only when `kind` is [`DataKind::Columns`],
    /// where it is never empty.
    pub columns: u128,
}

impl SyncRequest {
    pub fn protocol(&self) -> StreamProtocol {
        match (self.kind, self.scope) {
            (DataKind::Block, Scope::Range { .. }) => StreamProtocol::BeaconBlocksByRange,
            (DataKind::Block, Scope::Root(_)) => StreamProtocol::BeaconBlocksByRoot,
            (DataKind::Columns, Scope::Range { .. }) => StreamProtocol::DataColumnSidecarsByRange,
            (DataKind::Columns, Scope::Root(_)) => StreamProtocol::DataColumnSidecarsByRoot,
            (DataKind::Envelope, Scope::Range { .. }) => {
                StreamProtocol::ExecutionPayloadEnvelopesByRange
            }
            (DataKind::Envelope, Scope::Root(_)) => StreamProtocol::ExecutionPayloadEnvelopesByRoot,
        }
    }

    /// Rate-limit cost, in the units a peer's own inbound limiter charges — see
    /// [`RpcRequest::rate_limit_tokens`](crate::RpcRequest::rate_limit_tokens),
    /// which derives the same number from the encoded bytes and must agree.
    ///
    /// Needed here rather than there because the cost has to be known before a
    /// peer is chosen, and for columns it depends on *which* peer: only the
    /// subset that peer custodies gets asked for.
    pub fn tokens(&self) -> u64 {
        let slots = match self.scope {
            Scope::Range { count, .. } => count,
            Scope::Root(_) => 1,
        };
        match self.kind {
            DataKind::Block | DataKind::Envelope => slots,
            DataKind::Columns => slots.saturating_mul(self.columns.count_ones() as u64),
        }
        .max(1)
    }
}

/// The same cost, charged the other way round: what a peer's request costs
/// *them* with us, derived from the bytes they sent. Must agree with
/// [`SyncRequest::tokens`] — `tokens_agree_with_what_the_encoded_request_costs`
/// pins that. The two cannot be one function: a peer may ask for many roots
/// where we only ever ask for one, and the by-root arms deliberately count from
/// the payload length rather than acquire it in the hot path.
impl RpcRequest {
    pub fn rate_limit_tokens(&self) -> Result<u64, TCacheError> {
        let tokens = match self {
            RpcRequest::StatusV1(_) |
            RpcRequest::StatusV2(_) |
            RpcRequest::Ping(_) |
            RpcRequest::Goodbye(_) |
            RpcRequest::MetaData => 1,
            RpcRequest::BlocksByRange(ssz) => BeaconBlocksByRangeRequestView::count(ssz),
            RpcRequest::BlockByRoot(read) => fixed_width_list_tokens(read.len()?, 32),
            RpcRequest::DataColumnsByRange { ssz, len } => {
                let Some(buf) = ssz.get(..*len) else { return Ok(1) };
                if !DataColumnSidecarsByRangeRequestView::check_size(buf) {
                    1
                } else {
                    let count = DataColumnSidecarsByRangeRequestView::count(buf);
                    let columns = DataColumnSidecarsByRangeRequestView::columns(buf).len() / 8;
                    count.saturating_mul(columns as u64)
                }
            }
            RpcRequest::DataColumnsByRoot(read) => {
                data_columns_by_root_tokens_from_len(read.len()?)
            }
            RpcRequest::ExecutionPayloadEnvelopesByRange(ssz) => {
                ExecutionPayloadEnvelopesByRangeRequestView::count(ssz)
            }
            RpcRequest::ExecutionPayloadEnvelopesByRoot(read) => {
                fixed_width_list_tokens(read.len()?, 32)
            }
        };
        Ok(tokens.max(1))
    }
}

fn fixed_width_list_tokens(len: usize, width: usize) -> u64 {
    len.div_ceil(width) as u64
}

/// One `DataColumnsByRootIdentifier`: 4B outer-list offset + 32B block root +
/// 4B inner-list offset + N*8B column indices.
fn data_columns_by_root_tokens_from_len(len: usize) -> u64 {
    len.saturating_sub(4 + 32 + 4).div_ceil(8) as u64
}

/// A request's correlation id — `application_id` on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId {
    pub kind: DataKind,
    pub origin: Origin,
    pub seq: u64,
}

impl RequestId {
    const KIND_SHIFT: u32 = 32;
    const ORIGIN_SHIFT: u32 = 40;

    pub fn is(self, kind: DataKind, origin: Origin) -> bool {
        (self.kind, self.origin) == (kind, origin)
    }

    pub fn next(kind: DataKind, origin: Origin, seq: &mut u64) -> u64 {
        let id = Self { kind, origin, seq: *seq }.into();
        *seq += 1;
        id
    }
}

impl From<RequestId> for u64 {
    fn from(id: RequestId) -> Self {
        // `seq` is truncated to 32 bits: a long-lived node does wrap it, and an
        // overflow reaching the fields above would re-label the response and
        // route it to the wrong tile.
        u64::from(id.seq as u32) |
            (id.kind as u64) << RequestId::KIND_SHIFT |
            (id.origin as u64) << RequestId::ORIGIN_SHIFT
    }
}

impl From<u64> for RequestId {
    fn from(raw: u64) -> Self {
        let kind = match (raw >> Self::KIND_SHIFT) & 0xff {
            0 => DataKind::Block,
            1 => DataKind::Columns,
            2 => DataKind::Envelope,
            other => {
                debug_assert!(false, "request id {raw:#x} carries no data kind ({other})");
                DataKind::Block
            }
        };
        let origin = match (raw >> Self::ORIGIN_SHIFT) & 0xff {
            0 => Origin::Live,
            1 => Origin::Backfill,
            other => {
                debug_assert!(false, "request id {raw:#x} carries no origin ({other})");
                Origin::Live
            }
        };
        Self { kind, origin, seq: u64::from(raw as u32) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RpcRequest, TCache};

    /// The two token formulas — ours from the ask, the peer's from our bytes —
    /// must agree, or we either throttle sync for no reason or get rate-limited
    /// off peers that charged more than we budgeted.
    #[test]
    fn tokens_agree_with_what_the_encoded_request_costs() {
        let mut producer = TCache::multi_producer("token_agreement", 1 << 16);
        let columns = (1u128 << 3) | (1u128 << 7) | (1u128 << 40);

        for scope in [Scope::Range { start: 1000, count: 64 }, Scope::Root([0xAB; 32])] {
            for kind in DataKind::ALL {
                let request = SyncRequest { kind, origin: Origin::Live, scope, columns };
                let encoded = match (kind, scope) {
                    (DataKind::Block, Scope::Range { start, count }) => {
                        RpcRequest::blocks_by_range(start, count)
                    }
                    (DataKind::Envelope, Scope::Range { start, count }) => {
                        RpcRequest::envelopes_by_range(start, count)
                    }
                    (DataKind::Columns, Scope::Range { start, count }) => {
                        RpcRequest::data_columns_by_range(start, count, columns)
                    }
                    (DataKind::Block, Scope::Root(root)) => {
                        RpcRequest::BlockByRoot(RpcRequest::by_root(&mut producer, &root).unwrap())
                    }
                    (DataKind::Envelope, Scope::Root(root)) => {
                        RpcRequest::ExecutionPayloadEnvelopesByRoot(
                            RpcRequest::by_root(&mut producer, &root).unwrap(),
                        )
                    }
                    (DataKind::Columns, Scope::Root(root)) => RpcRequest::DataColumnsByRoot(
                        RpcRequest::data_columns_by_root(&mut producer, &root, columns).unwrap(),
                    ),
                };

                assert_eq!(
                    encoded.protocol(),
                    request.protocol(),
                    "{kind:?} {scope:?} encoded onto another protocol"
                );
                assert_eq!(
                    encoded.rate_limit_tokens().unwrap(),
                    request.tokens(),
                    "{kind:?} {scope:?} costs differ"
                );
            }
        }
    }

    #[test]
    fn kind_and_origin_survive_a_wrapped_sequence() {
        // The counter is shared across kinds and never reset, so a long-lived
        // node reaches this. Carrying the overflow upward would rewrite the kind
        // and route responses to another tile.
        for kind in DataKind::ALL {
            for origin in [Origin::Live, Origin::Backfill] {
                for seq in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
                    let raw = u64::from(RequestId { kind, origin, seq });
                    let back = RequestId::from(raw);
                    assert_eq!((back.kind, back.origin), (kind, origin), "{kind:?}/{origin:?}");
                    assert_eq!(back.seq, seq & u32::MAX as u64);
                }
            }
        }
    }

    #[test]
    fn data_columns_by_range_encodes_the_mask_as_an_index_list() {
        // Custody columns {3, 7} over [42, 42+5).
        let columns = (1u128 << 3) | (1u128 << 7);
        let RpcRequest::DataColumnsByRange { ssz, len } =
            RpcRequest::data_columns_by_range(42, 5, columns)
        else {
            panic!("built onto another variant")
        };

        // start_slot | count | offset(=20) | [3u64, 7u64]
        assert_eq!(len, 20 + 2 * 8);
        assert_eq!(u64::from_le_bytes(ssz[0..8].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(ssz[8..16].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(ssz[16..20].try_into().unwrap()), 20);
        assert_eq!(u64::from_le_bytes(ssz[20..28].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(ssz[28..36].try_into().unwrap()), 7);

        // Empty custody set → header only, no column list.
        let RpcRequest::DataColumnsByRange { len, .. } = RpcRequest::data_columns_by_range(0, 1, 0)
        else {
            panic!("built onto another variant")
        };
        assert_eq!(len, 20);
    }

    #[test]
    fn index_round_trips_every_kind() {
        for kind in DataKind::ALL {
            assert_eq!(DataKind::ALL[kind.index()], kind);
        }
    }
}
