use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};

pub use crate::{
    error::Error,
    id::{Keypair, PeerId, decode_protobuf_pubkey, encode_secp256k1_protobuf},
    util::create_self_signed_certificate,
};

mod enr;
mod error;
mod id;
mod util;

pub use enr::{Enr, NodeId};

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    // TODO: placeholder queue
    #[queue(size(2usize.pow(8)))]
    pub base: SpineQueue<()>,
}
