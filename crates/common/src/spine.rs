use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};
pub use stream_id::P2pStreamId;
pub use stream_protocol::{ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol};

mod stream_id;
mod stream_protocol;

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    // TODO: placeholder queue
    #[queue(size(2usize.pow(8)))]
    pub base: SpineQueue<()>,
}
