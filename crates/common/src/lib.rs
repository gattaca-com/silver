use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    // TODO: placeholder queue
    #[queue(size(2usize.pow(8)))]
    pub base: SpineQueue<()>,
}
