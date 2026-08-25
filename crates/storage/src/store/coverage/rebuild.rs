use std::io::{Error, ErrorKind, Read};

use silver_beacon_state_data::SpecConfig;
use silver_common::{
    merkle::B256,
    ssz_view::{NUMBER_OF_COLUMNS, SignedBeaconBlockView},
};

use super::{
    Coverage, Floors, Missing,
    chain::{Chain, Span},
};
use crate::store::{
    Payload, SLOTS_PER_DIR, backfill::PayloadFacts, block_index::BlockIndex, block_path,
    io::open_file_read, slot_dir,
};

const _: () = assert!(SLOTS_PER_DIR <= 128, "a group's presence is kept in one u128");

impl Coverage {
    pub(in crate::store) fn rebuild(
        &mut self,
        blocks: &BlockIndex,
        store_dir: &str,
        spec: &SpecConfig,
    ) {
        self.chain = chain(blocks, store_dir, spec);
        self.missing.clear();
        self.examined_below =
            self.chain.spans().last().map_or(0, |top| (top.to / SLOTS_PER_DIR + 1) * SLOTS_PER_DIR);
        self.touch();
        tracing::info!(
            spans = self.chain.spans().len(),
            examined_below = self.examined_below,
            "rebuilt coverage from the block files"
        );
    }

    #[cfg(test)]
    pub(in crate::store) fn examined_below(&self) -> u64 {
        self.examined_below
    }

    pub(in crate::store) fn unexamined_above(&self, missing_from: u64) -> bool {
        self.examined_below > missing_from
    }

    /// `finalized_block` is the finalized block's slot and the bid parent hash
    /// of its child in the fork tree, the one child no block file can tell.
    pub(in crate::store) fn examine_next_group(
        &mut self,
        blocks: &BlockIndex,
        floors: Floors,
        spec: &SpecConfig,
        store_dir: &str,
        finalized_block: Option<(u64, Option<B256>)>,
        block: &mut Vec<u8>,
    ) {
        let group = self.examined_below.saturating_sub(SLOTS_PER_DIR);
        let mut present_columns = [0u128; SLOTS_PER_DIR as usize];
        let mut present_envelopes = 0u128;
        if let Err(e) = list_present(store_dir, Payload::Column, group, |offset, column| {
            present_columns[offset] |= 1u128 << column
        }) {
            tracing::error!(?e, group, "column listing failed; its columns are missing");
        }
        if let Err(e) = list_present(store_dir, Payload::Envelope, group, |offset, _| {
            present_envelopes |= 1u128 << offset
        }) {
            tracing::error!(?e, group, "envelope listing failed; its envelopes are missing");
        }

        let mut child_read: Option<(u64, B256)> = None;
        for offset in (0..SLOTS_PER_DIR).rev() {
            let slot = group + offset;
            if !blocks.holds(slot) {
                continue;
            }
            // The listing settles the common case without opening the block:
            // nothing can be missing for a slot that has everything.
            let present = present_columns[offset as usize];
            let columns_absent = slot >= floors.columns && self.custody & !present != 0;
            let envelope_absent = slot >= floors.envelopes && present_envelopes >> offset & 1 == 0;
            if !columns_absent && !envelope_absent {
                child_read = None;
                continue;
            }
            let is_gloas = spec.is_gloas_at_slot(slot);
            // The child's bid says whether this payload was revealed. The
            // child was read on the previous turn of this loop when it was
            // missing something too; otherwise it is read now, ahead of this
            // block, so the one buffer serves both.
            let child = match (is_gloas, self.child_slot(blocks, slot)) {
                (false, _) => None,
                (true, Some(child)) => match child_read {
                    Some((read, payload_parent)) if read == child => Some(payload_parent),
                    _ => read_block(store_dir, child, block).then(|| {
                        PayloadFacts::of(block, spec.is_gloas_at_slot(child)).parent_payload_hash
                    }),
                },
                (true, None) => finalized_block
                    .and_then(|(finalized, child)| (finalized == slot).then_some(child))
                    .flatten(),
            };
            if !read_block(store_dir, slot, block) {
                tracing::error!(slot, "held block unreadable; taken as missing nothing");
                child_read = None;
                continue;
            }
            let facts = PayloadFacts::of(block, is_gloas);
            child_read = Some((slot, facts.parent_payload_hash));

            let needs = facts.needs(is_gloas, child);
            let columns = match needs.columns && columns_absent {
                true => self.custody & !present,
                false => 0,
            };
            self.set_missing(slot, Missing {
                columns,
                envelope: needs.envelope && envelope_absent,
            });
        }
        self.examined_below = group;
        self.touch();
    }
}

/// The spans the block files prove. Adjacent held slots link by definition;
/// a hole is closed by one header read of the block above it.
fn chain(blocks: &BlockIndex, store_dir: &str, spec: &SpecConfig) -> Chain {
    let mut block = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut above: Option<u64> = None;
    for slot in blocks.held_descending() {
        let mut parent_of_above = None;
        let linked = match above {
            None => false,
            Some(above) if above == slot + 1 => true,
            Some(above) => {
                parent_of_above = read_parent_root(store_dir, above);
                parent_of_above.is_some_and(|parent| blocks.slot_of(&parent) == Some(slot))
            }
        };
        if linked {
            spans.last_mut().expect("linked to the span above").from = slot;
        } else {
            if let (Some(above), Some(span)) = (above, spans.last_mut()) {
                close_bottom(span, above, parent_of_above, store_dir, spec, &mut block);
            }
            spans.push(Span::alone(slot));
        }
        above = Some(slot);
    }
    if let (Some(bottom), Some(span)) = (above, spans.last_mut()) {
        close_bottom(span, bottom, None, store_dir, spec, &mut block);
    }
    spans.reverse();
    Chain::from_ascending(spans)
}

/// Record what the span's lowest block wants. Before gloas there is no bid
/// to want a payload from, so a parent root already read is all it takes.
fn close_bottom(
    span: &mut Span,
    slot: u64,
    parent_root: Option<B256>,
    store_dir: &str,
    spec: &SpecConfig,
    block: &mut Vec<u8>,
) {
    let is_gloas = spec.is_gloas_at_slot(slot);
    if let (false, Some(parent_root)) = (is_gloas, parent_root) {
        span.wanted_parent = parent_root;
        return;
    }
    if !read_block(store_dir, slot, block) {
        tracing::error!(slot, "held block unreadable; nothing links below it");
        return;
    }
    span.wanted_parent = *SignedBeaconBlockView::parent_root(block);
    span.wanted_payload = PayloadFacts::of(block, is_gloas).parent_payload_hash;
}

fn read_parent_root(store_dir: &str, slot: u64) -> Option<B256> {
    let mut prefix = [0u8; 148];
    open_file_read(block_path(store_dir, slot)).ok()?.read_exact(&mut prefix).ok()?;
    Some(prefix[116..148].try_into().expect("32"))
}

pub(in crate::store) fn read_block(store_dir: &str, slot: u64, block: &mut Vec<u8>) -> bool {
    block.clear();
    let Ok(mut file) = open_file_read(block_path(store_dir, slot)) else { return false };
    file.read_to_end(block).is_ok() && SignedBeaconBlockView::check_size(block)
}

/// Every `<slot>_<index>.ssz` of `group`'s directory as (offset in the group,
/// index); an envelope's index reads as zero.
fn list_present(
    store_dir: &str,
    payload: Payload,
    group: u64,
    mut present: impl FnMut(usize, u64),
) -> Result<(), Error> {
    let entries = match std::fs::read_dir(slot_dir(store_dir, payload, group)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let name = entry?.file_name();
        let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".ssz")) else { continue };
        let Some((slot, index)) = stem.split_once('_') else { continue };
        let Ok(slot) = slot.parse::<u64>() else { continue };
        let Some(offset) = slot.checked_sub(group).filter(|&offset| offset < SLOTS_PER_DIR) else {
            continue;
        };
        let index = match payload {
            Payload::Column => match index.parse::<u64>() {
                Ok(index) if index < NUMBER_OF_COLUMNS as u64 => index,
                _ => continue,
            },
            Payload::Envelope => 0,
            Payload::Block => continue,
        };
        present(offset as usize, index);
    }
    Ok(())
}
