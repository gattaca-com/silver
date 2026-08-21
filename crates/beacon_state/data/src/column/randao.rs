use super::{ColumnGroup, ColumnReader, ColumnSpec, ColumnWriteView};
use crate::{
    ring::Id,
    types::{B256, EPOCHS_PER_HISTORICAL_VECTOR, Epoch, MIN_SEED_LOOKAHEAD},
};

/// `Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]`, written pointwise: the
/// current epoch's bucket absorbs one reveal per block, and the epoch boundary
/// copies it into the next.
pub struct RandaoMixes;
impl ColumnSpec for RandaoMixes {
    type Val = B256;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = EPOCHS_PER_HISTORICAL_VECTOR;
    const IS_LIST: bool = false;
}

pub type RandaoMixesGroup = ColumnGroup<RandaoMixes>;
pub type RandaoMixesId = Id<RandaoMixesGroup>;

pub type RandaoMixesView<'a> = ColumnReader<'a, RandaoMixes>;
pub type RandaoMixesWriteView<'a> = ColumnWriteView<'a, RandaoMixes>;

#[inline]
fn bucket(epoch: Epoch) -> usize {
    epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR
}

impl RandaoMixesView<'_> {
    /// Spec `get_randao_mix`.
    #[inline]
    pub fn at_epoch(&self, epoch: Epoch) -> B256 {
        self.get(bucket(epoch))
    }

    /// The mix `get_seed(epoch)` draws on: a full period back less the
    /// lookahead, which is what makes it already settled when read.
    #[inline]
    pub fn seed_mix(&self, epoch: Epoch) -> B256 {
        self.at_epoch(epoch + EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD - 1)
    }
}

impl RandaoMixesWriteView<'_> {
    #[inline]
    pub fn at_epoch(&self, epoch: Epoch) -> B256 {
        self.reader().at_epoch(epoch)
    }

    /// Spec `process_randao`'s write: XOR the reveal's hash into `epoch`'s mix.
    pub fn mix_in_reveal(&mut self, epoch: Epoch, reveal_hash: &B256) {
        let mut mix = self.at_epoch(epoch);
        for (b, &r) in mix.iter_mut().zip(reveal_hash.iter()) {
            *b ^= r;
        }
        self.set(bucket(epoch) as u32, mix);
    }

    /// Spec `process_randao_mixes_reset`: the finished epoch's mix seeds the
    /// next one, which then accumulates on top of it.
    pub fn copy_to_next_epoch(&mut self, epoch: Epoch) {
        self.set(bucket(epoch + 1) as u32, self.at_epoch(epoch));
    }
}
