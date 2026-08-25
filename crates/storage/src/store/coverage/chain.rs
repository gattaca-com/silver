use silver_common::merkle::B256;

use super::Block;
use crate::store::block_index::BlockIndex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Span {
    pub(super) from: u64,
    pub(super) to: u64,
    pub(super) wanted_parent: B256,
    /// The lowest block's bid `parent_block_hash`. The block below whose bid
    /// `block_hash` is not this one had its payload withheld.
    pub(super) wanted_payload: B256,
}

impl Span {
    pub(super) fn alone(slot: u64) -> Self {
        Self { from: slot, to: slot, wanted_parent: [0u8; 32], wanted_payload: [0u8; 32] }
    }

    pub(super) fn contains(&self, slot: u64) -> bool {
        (self.from..=self.to).contains(&slot)
    }
}

/// Ascending, disjoint spans of finalized history proven complete: every
/// slot holds a block or was skipped by the block above it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Chain(Vec<Span>);

impl Chain {
    pub(super) fn from_ascending(spans: Vec<Span>) -> Self {
        debug_assert!(spans.windows(2).all(|pair| pair[0].to < pair[1].from));
        Self(spans)
    }

    pub(super) fn spans(&self) -> &[Span] {
        &self.0
    }

    pub(super) fn contains(&self, slot: u64) -> bool {
        self.0.iter().any(|span| span.contains(slot))
    }

    pub(super) fn bits(&self, start: u64) -> u32 {
        let end = start + 32;
        let mut bits = 0u32;
        for span in &self.0 {
            if span.to < start || span.from >= end {
                continue;
            }
            let low = span.from.max(start) - start;
            let high = span.to.min(end - 1) - start;
            bits |= (u32::MAX >> (31 - high)) & (u32::MAX << low);
        }
        bits
    }

    pub(super) fn same_span(&self, a: u64, b: u64) -> bool {
        self.0.iter().any(|span| span.contains(a) && span.contains(b))
    }

    pub(super) fn top(&self, finalized_slot: u64) -> Option<&Span> {
        self.0.last().filter(|top| top.to >= finalized_slot)
    }

    /// Set when the block built on `block_root` is the lowest held.
    pub(super) fn child_payload(&self, block_root: B256) -> Option<B256> {
        self.0.last().filter(|top| top.wanted_parent == block_root).map(|top| top.wanted_payload)
    }

    /// A block landed in the flat store. It extends the span that wanted it
    /// as a parent, or opens one of its own. False for a block inside a span,
    /// which is recorded nowhere.
    pub(super) fn note(&mut self, block: &Block, blocks: &BlockIndex) -> bool {
        let facts = block.facts;
        let slot = facts.slot;
        let at = match self.0.iter().position(|span| span.wanted_parent == facts.block_root) {
            Some(at) => {
                self.0[at].from = slot;
                at
            }
            None if self.contains(slot) => {
                tracing::error!(slot, "block noted inside history already held");
                return false;
            }
            None => {
                let at = self.0.partition_point(|span| span.to < slot);
                let to = self.last_proven_empty_above(at, slot, block.to, blocks);
                self.0.insert(at, Span { to, ..Span::alone(slot) });
                at
            }
        };
        self.0[at].wanted_parent = facts.parent_root;
        self.0[at].wanted_payload = facts.payload.parent_payload_hash;
        self.merge_down(at, blocks);
        true
    }

    fn last_proven_empty_above(
        &self,
        at: usize,
        slot: u64,
        claimed: u64,
        blocks: &BlockIndex,
    ) -> u64 {
        let to = match self.0.get(at) {
            None => claimed,
            Some(above) => blocks
                .unwritten(&above.wanted_parent)
                .map_or(slot, |failed| failed.saturating_sub(1)),
        };
        to.max(slot)
    }

    /// Join the span at `at` to the one its wanted parent sits in, taking
    /// everything between them along.
    fn merge_down(&mut self, at: usize, blocks: &BlockIndex) {
        let Some(slot) = blocks.slot_of(&self.0[at].wanted_parent) else { return };
        let Some(lower) = self.0[..at].iter().position(|span| span.contains(slot)) else { return };
        self.0[at] = Span { to: self.0[at].to, ..self.0[lower] };
        self.0.drain(lower..at);
    }

    pub(super) fn drop_below(&mut self, earliest_slot: u64) -> bool {
        let before = self.0.len();
        self.0.retain(|span| span.to >= earliest_slot);
        let mut cut = self.0.len() != before;
        for span in &mut self.0 {
            if span.from < earliest_slot {
                span.from = earliest_slot;
                span.wanted_parent = [0u8; 32];
                span.wanted_payload = [0u8; 32];
                cut = true;
            }
        }
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backfill::{BlockFacts, Needs, PayloadFacts};

    fn root(slot: u64) -> B256 {
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&slot.to_le_bytes());
        root
    }

    fn block(slot: u64, parent: u64, finalized: u64) -> Block {
        let facts = BlockFacts {
            slot,
            block_root: root(slot),
            parent_root: root(parent),
            payload: PayloadFacts::default(),
        };
        Block::new(facts, Needs { columns: false, envelope: false }, finalized, root(finalized))
    }

    fn bounds(chain: &Chain) -> Vec<(u64, u64)> {
        chain.spans().iter().map(|span| (span.from, span.to)).collect()
    }

    /// Promotion drains top-down and a write in the middle fails. The blocks
    /// under it open one span, not one span each, and the re-served block
    /// joins the two.
    #[test]
    fn blocks_under_a_failed_promote_share_one_span() {
        let mut blocks = BlockIndex::default();
        let mut chain = Chain::default();
        blocks.index(root(96), 96);
        for slot in [100, 92, 88] {
            blocks.hold(root(slot), slot);
            assert!(chain.note(&block(slot, slot - 4, 100), &blocks));
        }
        assert_eq!(bounds(&chain), vec![(88, 95), (100, 100)], "96 is the hole");
        assert_eq!(chain.spans()[0].wanted_parent, root(84));
        assert_eq!(chain.spans()[1].wanted_parent, root(96));

        blocks.hold(root(96), 96);
        assert!(chain.note(&block(96, 92, 100), &blocks));
        assert_eq!(bounds(&chain), vec![(88, 100)]);
        assert_eq!(chain.spans()[0].wanted_parent, root(84));
    }

    #[test]
    fn window_bits_clip_spans() {
        let chain = Chain::from_ascending(vec![
            Span { from: 90, to: 101, ..Span::alone(0) },
            Span { from: 110, to: 112, ..Span::alone(0) },
            Span { from: 130, to: 140, ..Span::alone(0) },
        ]);
        let bits = chain.bits(100);
        for slot in 100..132 {
            assert_eq!(bits >> (slot - 100) & 1 == 1, chain.contains(slot), "slot {slot}");
        }
        assert_eq!(chain.bits(150), 0);
    }
}
