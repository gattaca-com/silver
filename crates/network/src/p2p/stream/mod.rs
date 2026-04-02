mod snappy;
mod state;
mod stream;

const MULTISTREAM_V1: &[u8] = b"\x13/multistream/1.0.0\n";
const REJECT_RESPONSE: &[u8] = b"\x13/multistream/1.0.0\n\x03na\n";
const PROTOCOL_LEN_OFFSET: usize = 20;

enum StreamProtocol {
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
}

impl StreamProtocol {
    const fn is_request_response(&self) -> bool {
        match self {
            Self::GossipSub => false,
            _ => true,
        }
    }

    /// Next protocol to try if the intial proposal is rejected.
    const fn next(&self) -> Option<Self> {
        match self {
            Self::StatusV2 => Some(Self::StatusV1),
            _ => None,
        }
    }

    /// Returns the mutliselect prefix lines (used for both request and
    /// response)
    const fn multiselect(&self) -> &[u8] {
        match self {
            StreamProtocol::GossipSub => b"\x0f/meshsub/1.1.0\n",
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
}

#[cfg(test)]
mod tests {
    use crate::p2p::stream::StreamProtocol;

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
}
