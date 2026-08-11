use silver_ssz::ssz_view::{AttestationDataView, SignedAggregateAndProofView};

use crate::{B256, Epoch, SLOTS_PER_EPOCH};

pub struct ParsedAggregateAndProof<'a> {
    pub outer_sig: &'a [u8; 96],
    pub aggregator_index: usize,
    pub selection_proof: &'a [u8; 96],
    pub agg_slot: u64,
    pub agg_data_index: u64,
    pub beacon_block_root: B256,
    pub target_epoch: Epoch,
    pub committee_bits: u64,
    pub agg_sig: &'a [u8; 96],
    pub agg_data: AttestationDataView<'a>,
    pub aggregation_bits: &'a [u8],
    pub aggregate_bytes: &'a [u8],
    pub att_epoch: Epoch,
}

impl<'a> ParsedAggregateAndProof<'a> {
    pub fn try_from(data: &'a [u8]) -> Option<Self> {
        if !SignedAggregateAndProofView::check_size(data) {
            return None;
        }
        let agg_slot = SignedAggregateAndProofView::agg_slot(data);
        Some(Self {
            outer_sig: SignedAggregateAndProofView::signature(data),
            aggregator_index: SignedAggregateAndProofView::aggregator_index(data) as usize,
            selection_proof: SignedAggregateAndProofView::selection_proof(data),
            agg_slot,
            agg_data_index: SignedAggregateAndProofView::agg_data_index(data),
            beacon_block_root: *SignedAggregateAndProofView::agg_beacon_block_root(data),
            target_epoch: SignedAggregateAndProofView::agg_target_epoch(data),
            committee_bits: u64::from_le_bytes(*SignedAggregateAndProofView::agg_committee_bits(
                data,
            )),
            agg_sig: SignedAggregateAndProofView::agg_signature(data),
            agg_data: SignedAggregateAndProofView::agg_data(data),
            aggregation_bits: SignedAggregateAndProofView::agg_aggregation_bits(data),
            aggregate_bytes: SignedAggregateAndProofView::aggregate(data),
            att_epoch: agg_slot / SLOTS_PER_EPOCH,
        })
    }
}
