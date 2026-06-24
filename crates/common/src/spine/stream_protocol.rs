use crate::rpc_rate_limit::RpcQuota;

pub const MULTISTREAM_V1: &[u8] = b"\x13/multistream/1.0.0\n";
pub const REJECT_RESPONSE: &[u8] = b"\x13/multistream/1.0.0\n\x03na\n";

const MAX_SIDECAR_RATE_LIMIT_TOKENS: u64 = 16384;
const MAX_BLOCK_RATE_LIMIT_TOKENS: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamProtocol {
    GossipSub,
    Identity,
    StatusV1,
    StatusV2,
    Ping,
    Goodbye,
    Metadata,
    BeaconBlocksByRange,
    BeaconBlocksByRoot,
    DataColumnSidecarsByRange,
    DataColumnSidecarsByRoot,
    Unset,
}

pub const ALL_PROTOCOLS: &[StreamProtocol] = &[
    StreamProtocol::GossipSub,
    StreamProtocol::Identity,
    StreamProtocol::StatusV1,
    StreamProtocol::StatusV2,
    StreamProtocol::Ping,
    StreamProtocol::Goodbye,
    StreamProtocol::Metadata,
    StreamProtocol::BeaconBlocksByRange,
    StreamProtocol::BeaconBlocksByRoot,
    StreamProtocol::DataColumnSidecarsByRange,
    StreamProtocol::DataColumnSidecarsByRoot,
];

pub const RPC_PROTOCOLS: &[StreamProtocol] = &[
    StreamProtocol::StatusV1,
    StreamProtocol::StatusV2,
    StreamProtocol::Ping,
    StreamProtocol::Goodbye,
    StreamProtocol::Metadata,
    StreamProtocol::BeaconBlocksByRange,
    StreamProtocol::BeaconBlocksByRoot,
    StreamProtocol::DataColumnSidecarsByRange,
    StreamProtocol::DataColumnSidecarsByRoot,
];

impl StreamProtocol {
    pub const fn is_request_response(&self) -> bool {
        !matches!(self, Self::GossipSub | Self::Identity)
    }

    pub const fn has_multipart_response(&self) -> bool {
        matches!(
            self,
            Self::BeaconBlocksByRange |
                Self::BeaconBlocksByRoot |
                Self::DataColumnSidecarsByRange |
                Self::DataColumnSidecarsByRoot
        )
    }

    /// Inbound quotas bound the work we are willing to do for a peer. These
    /// mirror Lighthouse's default RPC limiter quotas.
    pub const fn inbound_rpc_quota(self) -> Option<RpcQuota> {
        match self {
            Self::GossipSub | Self::Identity | Self::Unset => None,
            Self::StatusV1 | Self::StatusV2 => Some(RpcQuota::n_every(5, 15)),
            Self::Ping => Some(RpcQuota::n_every(2, 10)),
            Self::Goodbye => Some(RpcQuota::one_every(10)),
            Self::Metadata => Some(RpcQuota::n_every(2, 5)),
            Self::BeaconBlocksByRange | Self::BeaconBlocksByRoot => {
                Some(RpcQuota::n_every(MAX_BLOCK_RATE_LIMIT_TOKENS, 10))
            }
            Self::DataColumnSidecarsByRange | Self::DataColumnSidecarsByRoot => {
                Some(RpcQuota::n_every(MAX_SIDECAR_RATE_LIMIT_TOKENS, 10))
            }
        }
    }

    /// Outbound quotas self-throttle requests we send to one peer. Keep these
    /// more conservative than inbound quotas so Silver does not trip remote
    /// peer scoring while still allowing a max-sized legal request as one
    /// burst.
    pub const fn outbound_rpc_quota(self) -> Option<RpcQuota> {
        match self {
            Self::GossipSub | Self::Identity | Self::Unset => None,
            Self::StatusV1 | Self::StatusV2 => Some(RpcQuota::n_every(5, 15)),
            Self::Ping => Some(RpcQuota::n_every(2, 10)),
            Self::Goodbye => Some(RpcQuota::one_every(10)),
            Self::Metadata => Some(RpcQuota::n_every(2, 5)),
            Self::BeaconBlocksByRange | Self::BeaconBlocksByRoot => {
                Some(RpcQuota::n_every(MAX_BLOCK_RATE_LIMIT_TOKENS, 30)) // 30s appears to be the default period of Prysm. Lighthouse is 10s. 
            }
            Self::DataColumnSidecarsByRange | Self::DataColumnSidecarsByRoot => {
                Some(RpcQuota::n_every(MAX_SIDECAR_RATE_LIMIT_TOKENS, 15))
            }
        }
    }

    /// Next protocol to try if the initial proposal is rejected.
    pub const fn next(&self) -> Option<Self> {
        match self {
            Self::StatusV2 => Some(Self::StatusV1),
            _ => None,
        }
    }

    /// Varint-length-prefixed protocol line (including trailing \n).
    pub const fn multiselect(&self) -> &[u8] {
        match self {
            StreamProtocol::Unset => panic!("should never call multiselect on negotiating stream"),
            StreamProtocol::GossipSub => b"\x0f/meshsub/1.2.0\n",
            StreamProtocol::Identity => b"\x0f/ipfs/id/1.0.0\n",
            StreamProtocol::StatusV1 => b"\x2b/eth2/beacon_chain/req/status/1/ssz_snappy\n",
            StreamProtocol::StatusV2 => b"\x2b/eth2/beacon_chain/req/status/2/ssz_snappy\n",
            StreamProtocol::Ping => b"\x29/eth2/beacon_chain/req/ping/1/ssz_snappy\n",
            StreamProtocol::Goodbye => b"\x2c/eth2/beacon_chain/req/goodbye/1/ssz_snappy\n",
            StreamProtocol::Metadata => b"\x2d/eth2/beacon_chain/req/metadata/3/ssz_snappy\n",
            StreamProtocol::BeaconBlocksByRange => {
                b"\x3b/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy\n"
            }
            StreamProtocol::BeaconBlocksByRoot => {
                b"\x3a/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy\n"
            }
            StreamProtocol::DataColumnSidecarsByRange => {
                b"\x42/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy\n"
            }
            StreamProtocol::DataColumnSidecarsByRoot => {
                b"\x41/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy\n"
            }
        }
    }

    pub fn multiselect_string(&self) -> String {
        let ms = self.multiselect();
        String::from_utf8_lossy(&ms[1..ms.len() - 1]).to_string()
    }

    /// Match a varint-prefixed protocol line against known protocols.
    pub fn from_multiselect(data: &[u8]) -> Option<Self> {
        ALL_PROTOCOLS.iter().find(|p| p.multiselect() == data).copied()
    }

    pub fn from_multiselect_str(data: &str) -> Option<Self> {
        ALL_PROTOCOLS
            .iter()
            .find(|p| {
                let bytes = p.multiselect();
                data.as_bytes() == &bytes[1..(bytes.len() - 1)]
            })
            .copied()
    }

    pub const fn ordinal(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::StreamProtocol;

    #[test]
    fn test_len() {
        assert_eq!(
            StreamProtocol::GossipSub.multiselect().len(),
            (StreamProtocol::GossipSub.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::Identity.multiselect().len(),
            (StreamProtocol::Identity.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::StatusV1.multiselect().len(),
            (StreamProtocol::StatusV1.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::StatusV2.multiselect().len(),
            (StreamProtocol::StatusV2.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::Ping.multiselect().len(),
            (StreamProtocol::Ping.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::Goodbye.multiselect().len(),
            (StreamProtocol::Goodbye.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::Metadata.multiselect().len(),
            (StreamProtocol::Metadata.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::BeaconBlocksByRange.multiselect().len(),
            (StreamProtocol::BeaconBlocksByRange.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::BeaconBlocksByRoot.multiselect().len(),
            (StreamProtocol::BeaconBlocksByRoot.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::DataColumnSidecarsByRange.multiselect().len(),
            (StreamProtocol::DataColumnSidecarsByRange.multiselect()[0] + 1) as usize
        );
        assert_eq!(
            StreamProtocol::DataColumnSidecarsByRoot.multiselect().len(),
            (StreamProtocol::DataColumnSidecarsByRoot.multiselect()[0] + 1) as usize
        );
    }

    #[test]
    fn from_str() {
        assert_eq!(
            StreamProtocol::DataColumnSidecarsByRange,
            StreamProtocol::from_multiselect_str(
                "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
            )
            .unwrap()
        );
    }
}
