use std::{io::Error, path::Path};

use silver_beacon_state_data::SpecConfig;
use silver_common::{DataKind, Prefill, SyncNeed, merkle::B256};

use super::{
    Payload,
    block_index::BlockIndex,
    coverage::{Block, Coverage, Floors},
};

pub(super) struct Finalized {
    blocks: BlockIndex,
    coverage: Coverage,
    scratch: Vec<u8>,
}

impl Finalized {
    pub(super) fn load(store_dir: &str, custody: u128, spec: &SpecConfig) -> Result<Self, Error> {
        let blocks_dir = Path::new(store_dir).join(Payload::Block.finalized_dir_name());
        let blocks = BlockIndex::load(&blocks_dir)?;
        let coverage = match Coverage::load(store_dir, custody)? {
            Some(coverage) => coverage,
            None => {
                let mut coverage = Coverage::new(custody);
                coverage.rebuild(&blocks, store_dir, spec);
                coverage
            }
        };
        Ok(Self { blocks, coverage, scratch: Vec::new() })
    }

    pub(super) fn persist(&mut self, store_dir: &str) -> Result<(), Error> {
        self.coverage.persist_if_changed(store_dir, &mut self.scratch)
    }

    pub(super) fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    pub(super) fn custody(&self) -> u128 {
        self.coverage.custody()
    }

    pub(super) fn slot_of(&self, root: &B256) -> Option<u64> {
        self.blocks.slot_of(root)
    }

    pub(super) fn contains(&self, root: &B256) -> bool {
        self.blocks.contains(root)
    }

    #[cfg(test)]
    pub(super) fn holds(&self, slot: u64) -> bool {
        self.blocks.holds(slot)
    }

    pub(super) fn written(&self, root: &B256, slot: u64) -> bool {
        self.blocks.written(root, slot)
    }

    pub(super) fn slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.blocks.slots()
    }

    /// Promotion queued: the root is known before its file is.
    pub(super) fn index(&mut self, root: B256, slot: u64) {
        self.blocks.index(root, slot);
    }

    /// The block's file is down in `dir`.
    pub(super) fn landed(&mut self, dir: &Path, block: Block) -> Result<(), Error> {
        self.blocks.landed(dir, block.facts.block_root, block.facts.slot)?;
        self.relinked(block);
        Ok(())
    }

    /// A held block served again, so the chain can link through it.
    pub(super) fn relinked(&mut self, block: Block) {
        self.coverage.note_block(block, &self.blocks);
    }

    pub(super) fn column_landed(&mut self, slot: u64, column: u64) {
        self.coverage.note_columns(slot, 1u128 << column);
    }

    pub(super) fn envelope_landed(&mut self, slot: u64) {
        self.coverage.note_envelope(slot);
    }

    pub(super) fn truncated(&mut self, payload: Payload, earliest_slot: u64) {
        self.coverage.drop_below(payload, earliest_slot);
    }

    pub(super) fn describe(
        &self,
        start: u64,
        floors: Floors,
        finalized_slot: u64,
    ) -> (Prefill, bool) {
        self.coverage.describe(&self.blocks, start, floors, finalized_slot)
    }

    pub(super) fn examine_next_group(
        &mut self,
        floors: Floors,
        spec: &SpecConfig,
        store_dir: &str,
        finalized_block: Option<(u64, Option<B256>)>,
        block: &mut Vec<u8>,
    ) {
        self.coverage.examine_next_group(
            &self.blocks,
            floors,
            spec,
            store_dir,
            finalized_block,
            block,
        );
    }

    pub(super) fn persisted(
        &self,
        kind: DataKind,
        slot: u64,
        parent_slot: Option<u64>,
    ) -> SyncNeed {
        let columns = match kind {
            DataKind::Columns => self.coverage.custody() & !self.coverage.columns_missing(slot),
            DataKind::Block | DataKind::Envelope => 0,
        };
        SyncNeed::Persisted { kind, slot, columns, parent_slot }
    }
}
