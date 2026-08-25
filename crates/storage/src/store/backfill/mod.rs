mod pending;

pub(super) use pending::{Pending, VerifiedColumns, envelope_block_root, sidecar_head};
use silver_beacon_state_data::SpecConfig;
use silver_common::{
    column_util,
    merkle::B256,
    ssz_view::{ExecutionPayloadBidView, SignedBeaconBlockView},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PayloadFacts {
    pub(super) has_blobs: bool,
    pub(super) payload_hash: B256,
    pub(super) parent_payload_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Needs {
    pub(super) columns: bool,
    pub(super) envelope: bool,
}

impl PayloadFacts {
    pub(in crate::store) fn of(block: &[u8], is_gloas: bool) -> Self {
        if !is_gloas {
            let has_blobs = SignedBeaconBlockView::has_data_columns_fulu(block);
            return Self { has_blobs, ..Self::default() };
        }

        if !SignedBeaconBlockView::check_gloas_size(block) {
            tracing::error!(
                slot = SignedBeaconBlockView::slot(block),
                "gloas block bid out of bounds; taken as missing nothing"
            );
            return Self::default();
        }
        let bid = SignedBeaconBlockView::gloas_bid(block);
        Self {
            has_blobs: !ExecutionPayloadBidView::blob_kzg_commitments(bid).is_empty(),
            payload_hash: *ExecutionPayloadBidView::block_hash(bid),
            parent_payload_hash: *ExecutionPayloadBidView::parent_block_hash(bid),
        }
    }

    pub(in crate::store) fn needs(
        &self,
        is_gloas: bool,
        child_payload_parent: Option<B256>,
    ) -> Needs {
        let revealed =
            !is_gloas || child_payload_parent.is_none_or(|parent| parent == self.payload_hash);
        Needs { columns: self.has_blobs && revealed, envelope: is_gloas && revealed }
    }
}

/// What a block's bytes say about it, kept once the bytes are gone.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockFacts {
    pub(super) slot: u64,
    pub(super) block_root: B256,
    pub(super) parent_root: B256,
    pub(super) payload: PayloadFacts,
}

impl BlockFacts {
    pub(in crate::store) fn of(buffer: &[u8], spec: &SpecConfig) -> Option<Self> {
        if !SignedBeaconBlockView::check_size(buffer) {
            tracing::warn!(len = buffer.len(), "backfill block has invalid size");
            return None;
        }
        let slot = SignedBeaconBlockView::slot(buffer);
        let is_gloas = spec.is_gloas_at_slot(slot);
        Some(Self {
            slot,
            block_root: column_util::block_root(buffer, is_gloas),
            parent_root: *SignedBeaconBlockView::parent_root(buffer),
            payload: PayloadFacts::of(buffer, is_gloas),
        })
    }

    pub(in crate::store) fn needs(
        &self,
        spec: &SpecConfig,
        child_payload_parent: Option<B256>,
    ) -> Needs {
        self.payload.needs(spec.is_gloas_at_slot(self.slot), child_payload_parent)
    }
}

#[cfg(test)]
pub(in crate::store) mod fixtures {
    use std::{
        io::Write,
        sync::{Arc, LazyLock},
    };

    use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
    use silver_common::{
        TCache, TCacheProducer, TRead, column_util,
        merkle::B256,
        ssz_hash::kzg_commitments_inclusion_proof,
        ssz_view::{EXECUTION_PAYLOAD_FIXED_GLOAS, NUMBER_OF_COLUMNS},
    };

    pub(in crate::store) const GLOAS_FORK_EPOCH: u64 = 1;
    pub(in crate::store) const GLOAS_FORK_SLOT: u64 = GLOAS_FORK_EPOCH * SLOTS_PER_EPOCH;

    pub(in crate::store) const BID_BLOCK_HASH: B256 = [0xB1; 32];
    pub(in crate::store) const BID_PREV_RANDAO: B256 = [0xD1; 32];
    pub(in crate::store) const BID_GAS_LIMIT: u64 = 30_000_000;
    pub(in crate::store) const BID_BUILDER_INDEX: u64 = 77;

    const BODY_FIXED: usize = 396;
    const BID_FIXED: usize = 224;
    /// The bid message inside a `gloas_block_bytes` block: body at 184, the
    /// signed bid at the end of the fixed part, its message after the
    /// 100-byte signed prefix.
    const BID_AT: usize = 184 + BODY_FIXED + 100;

    pub(in crate::store) fn spec() -> Arc<SpecConfig> {
        crate::store::test_spec(GLOAS_FORK_EPOCH)
    }

    /// Synthetic `SignedBeaconBlock`: message at 100, slot at [100..108),
    /// parent_root at [116..148), body at 184.
    pub(in crate::store) fn block_bytes(slot: u64, parent_root: B256) -> Vec<u8> {
        let mut b = vec![0u8; 784];
        b[0..4].copy_from_slice(&100u32.to_le_bytes());
        b[100..108].copy_from_slice(&slot.to_le_bytes());
        b[116..148].copy_from_slice(&parent_root);
        b[180..184].copy_from_slice(&84u32.to_le_bytes());
        b
    }

    /// Gloas block carrying `commitments` in its bid: body offsets place a
    /// `SignedExecutionPayloadBid` (fixed 100 + bid fixed 224 + commitments)
    /// between `signed_execution_payload_bid_offset` and
    /// `payload_attestations_offset`.
    pub(in crate::store) fn gloas_block_bytes(slot: u64, commitments: &[u8]) -> Vec<u8> {
        let mut bid = vec![0u8; BID_FIXED];
        bid[188..192].copy_from_slice(&(BID_FIXED as u32).to_le_bytes());
        bid[64..96].copy_from_slice(&BID_BLOCK_HASH); // block_hash
        bid[96..128].copy_from_slice(&BID_PREV_RANDAO); // prev_randao
        bid[148..156].copy_from_slice(&BID_GAS_LIMIT.to_le_bytes()); // gas_limit
        bid[156..164].copy_from_slice(&BID_BUILDER_INDEX.to_le_bytes()); // builder_index
        bid.extend_from_slice(commitments);

        let mut signed_bid = vec![0u8; 100];
        signed_bid[0..4].copy_from_slice(&100u32.to_le_bytes());
        signed_bid.extend_from_slice(&bid);

        let mut body = vec![0u8; BODY_FIXED];
        let after_bid = BODY_FIXED + signed_bid.len();
        for at in [200usize, 204, 208, 212, 216, 380] {
            body[at..at + 4].copy_from_slice(&(BODY_FIXED as u32).to_le_bytes());
        }
        body[384..388].copy_from_slice(&(BODY_FIXED as u32).to_le_bytes());
        for at in [388usize, 392] {
            body[at..at + 4].copy_from_slice(&(after_bid as u32).to_le_bytes());
        }
        body.extend_from_slice(&signed_bid);

        let mut b = vec![0u8; 184];
        b[0..4].copy_from_slice(&100u32.to_le_bytes());
        b[100..108].copy_from_slice(&slot.to_le_bytes());
        b[180..184].copy_from_slice(&84u32.to_le_bytes());
        b.extend_from_slice(&body);
        b
    }

    /// A gloas block in a chain: its parent is `parent_root`, and its bid
    /// builds on `BID_BLOCK_HASH`, which every gloas block here reveals, so a
    /// child says its parent's payload was revealed.
    pub(in crate::store) fn gloas_chain_block(
        slot: u64,
        parent_root: B256,
        commitments: &[u8],
    ) -> Vec<u8> {
        let mut b = gloas_block_bytes(slot, commitments);
        b[116..148].copy_from_slice(&parent_root);
        b[BID_AT..BID_AT + 32].copy_from_slice(&BID_BLOCK_HASH);
        b
    }

    pub(in crate::store) fn fulu_blob_block(
        slot: u64,
        parent_root: B256,
        commitments: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![0u8; BODY_FIXED + commitments.len()];
        for pos in [200usize, 204, 208, 212, 216, 380, 384, 388] {
            body[pos..pos + 4].copy_from_slice(&(BODY_FIXED as u32).to_le_bytes());
        }
        body[392..396].copy_from_slice(&((BODY_FIXED + commitments.len()) as u32).to_le_bytes());
        body[BODY_FIXED..].copy_from_slice(commitments);

        let mut block = vec![0u8; 184];
        block[0..4].copy_from_slice(&100u32.to_le_bytes());
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[116..148].copy_from_slice(&parent_root);
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        block.extend_from_slice(&body);
        block
    }

    /// Two zero blobs through c-kzg once: their commitments, and per column
    /// the concatenated cells and proofs. Every blob block in the tests
    /// carries these, so one computation serves them all.
    pub(in crate::store) struct Kzg {
        pub(in crate::store) commitments: Vec<u8>,
        cells: Vec<Vec<u8>>,
        proofs: Vec<Vec<u8>>,
    }

    pub(in crate::store) static KZG: LazyLock<Kzg> = LazyLock::new(|| {
        let settings = c_kzg::ethereum_kzg_settings(0);
        let blob = c_kzg::Blob::new([0u8; 131072]);
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap().to_bytes().into_inner();
        let (blob_cells, blob_proofs) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
        let mut commitments = Vec::new();
        let mut cells = vec![Vec::new(); NUMBER_OF_COLUMNS];
        let mut proofs = vec![Vec::new(); NUMBER_OF_COLUMNS];
        for _ in 0..2 {
            commitments.extend_from_slice(&commitment);
            for j in 0..NUMBER_OF_COLUMNS {
                cells[j].extend_from_slice(&blob_cells[j].to_bytes());
                proofs[j].extend_from_slice(&blob_proofs[j].to_bytes().into_inner());
            }
        }
        Kzg { commitments, cells, proofs }
    });

    impl Kzg {
        /// The fulu sidecar of `column` for `block`, whose header is the
        /// block's own so `block_root_from_sidecar` matches.
        pub(in crate::store) fn fulu_sidecar(&self, block: &[u8], column: u64) -> Vec<u8> {
            let body = &block[184..];
            let mut header = [0u8; 208];
            header[..80].copy_from_slice(&block[100..180]);
            header[80..112].copy_from_slice(&column_util::body_root(body));
            header[112..].copy_from_slice(&block[4..100]);
            let n = self.commitments.len() / 48;
            let mut out = Vec::new();
            column_util::push_data_column_sidecar_prefix(
                &mut out,
                column,
                n,
                &header,
                &kzg_commitments_inclusion_proof(body),
            );
            out.extend_from_slice(&self.cells[column as usize]);
            out.extend_from_slice(&self.commitments);
            out.extend_from_slice(&self.proofs[column as usize]);
            out
        }
    }

    /// `SignedExecutionPayloadEnvelope`: fixed 100B prefix, then the envelope,
    /// payload offset at [0..4), builder_index at [8..16), beacon_block_root at
    /// [16..48). The payload itself carries prev_randao/gas_limit/block_hash.
    pub(in crate::store) fn envelope_bytes(
        block_root: B256,
        builder_index: u64,
        block_hash: B256,
    ) -> Vec<u8> {
        const ENVELOPE_FIXED: usize = 80;

        let mut payload = vec![0u8; EXECUTION_PAYLOAD_FIXED_GLOAS];
        payload[372..404].copy_from_slice(&BID_PREV_RANDAO);
        payload[412..420].copy_from_slice(&BID_GAS_LIMIT.to_le_bytes());
        payload[472..504].copy_from_slice(&block_hash);

        let mut envelope = vec![0u8; ENVELOPE_FIXED];
        envelope[0..4].copy_from_slice(&(ENVELOPE_FIXED as u32).to_le_bytes());
        envelope[4..8].copy_from_slice(&((ENVELOPE_FIXED + payload.len()) as u32).to_le_bytes());
        envelope[8..16].copy_from_slice(&builder_index.to_le_bytes());
        envelope[16..48].copy_from_slice(&block_root);
        envelope.extend_from_slice(&payload);

        let mut signed = vec![0u8; 100];
        signed[0..4].copy_from_slice(&100u32.to_le_bytes());
        signed.extend_from_slice(&envelope);
        signed
    }

    pub(in crate::store) fn envelope_for(block_root: B256) -> Vec<u8> {
        envelope_bytes(block_root, BID_BUILDER_INDEX, BID_BLOCK_HASH)
    }

    /// Producer + random-access consumer pair turning bytes into acquired
    /// `TRead`s. Declared consumer-after-producer so parked reads (which
    /// dereference the consumer on release) drop first.
    pub(in crate::store) struct Tc {
        producer: silver_common::TProducer,
        consumer: silver_common::TRandomAccess,
    }

    impl Tc {
        pub(in crate::store) fn new(name: &'static str, size: usize) -> Self {
            let producer = TCache::producer(name, size);
            let consumer = producer.cache_ref().random_access(name, true).unwrap();
            Self { producer, consumer }
        }

        pub(in crate::store) fn tread(&mut self, bytes: &[u8]) -> TRead {
            let mut res = self.producer.reserve(bytes.len(), true).unwrap();
            res.write_all(bytes).unwrap();
            res.flush().unwrap();
            let handle = res.read();
            self.consumer.acquire(handle)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fixtures::{BID_BLOCK_HASH, GLOAS_FORK_SLOT, block_bytes, gloas_block_bytes},
        *,
    };

    /// A builder that never revealed its payload left no envelope and no
    /// columns behind. The child's bid builds on the last revealed payload, so
    /// it is what says which. Without a child the payload is taken as revealed.
    #[test]
    fn withheld_payload_needs_neither_envelope_nor_columns() {
        let commitments = [0x11u8; 48];
        let facts = PayloadFacts::of(&gloas_block_bytes(GLOAS_FORK_SLOT, &commitments), true);
        assert_eq!(facts.payload_hash, BID_BLOCK_HASH);
        assert!(facts.has_blobs);

        let revealed = Needs { columns: true, envelope: true };
        let withheld = Needs { columns: false, envelope: false };
        assert_eq!(facts.needs(true, Some(BID_BLOCK_HASH)), revealed, "the child builds on it");
        assert_eq!(facts.needs(true, Some([0xFF; 32])), withheld, "the child builds past it");
        assert_eq!(facts.needs(true, None), revealed, "no child to ask");

        let fulu = PayloadFacts::of(&block_bytes(1, [0; 32]), false);
        assert!(!fulu.needs(false, None).envelope, "no envelopes before the fork");
    }
}
