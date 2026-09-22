use silver_common::{
    cell_store::{AssemblyRequest, ColumnGroupKey, HeaderValidationRequest},
    ssz_view::partial_column::{bitlist_bytes, write_bitlist_u128},
};
use silver_gossip::{ColumnIngress, PartialInbound};

use super::*;

fn payload(format: ForkName, count: usize, rows: u128, header: Option<&[u8]>) -> Vec<u8> {
    let fixed = if format == ForkName::Fulu { 16 } else { 12 };
    let cells = fixed + bitlist_bytes(count);
    let proofs = cells + rows.count_ones() as usize * BYTES_PER_CELL;
    let end = proofs + rows.count_ones() as usize * BYTES_PER_KZG_PROOF;
    let mut bytes = vec![0; end];
    bytes[..4].copy_from_slice(&(fixed as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&(cells as u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&(proofs as u32).to_le_bytes());
    if format == ForkName::Fulu {
        bytes[12..16].copy_from_slice(&(end as u32).to_le_bytes());
    }
    write_bitlist_u128(rows, count, &mut bytes[fixed..cells]);
    bytes[cells..proofs].fill(0x11);
    bytes[proofs..end].fill(0x22);
    if let Some(header) = header {
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(header);
    }
    bytes
}

impl Rig {
    fn partial(
        &mut self,
        count: usize,
        rows: u128,
        header: Option<&[u8]>,
        peer: usize,
    ) -> (Vec<CellValidationRequest>, Vec<HeaderValidationRequest>) {
        let bytes = payload(self.context.format, count, rows, header);
        self.control.receive_partial(
            PartialInbound {
                stream_id: P2pStreamId::new(peer, 0, StreamProtocol::GossipSubV13, true),
                group: ColumnGroupKey {
                    domain: GossipDomain::new([0; 4], self.context.format),
                    block_root: ROOT,
                    column: 0,
                },
                slot: (self.context.format == ForkName::Gloas).then_some(self.context.slot),
                received: Nanos(peer as u64),
                payload: &bytes,
            },
            &self.adapters[0].producers,
        );
        // Calls into ingress use the real monotonic clock.
        self.now = Instant::now();
        let mut cells = Vec::new();
        let mut headers = Vec::new();
        self.adapters[1].consume(|event: CellStoreEvent, _| match event {
            CellStoreEvent::Validate(request) => cells.push(request),
            CellStoreEvent::Header(request) => headers.push(request),
            _ => {}
        });
        (cells, headers)
    }
}

#[test]
fn optimistic_cells_reuse_final_positions_after_context_in_both_forks() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        let first = rig.partial(2, 1, None, 1).0[0];
        let head = rig.control.producer_mut().next_seq();
        assert!(rig.partial(2, 1, None, 2).0.is_empty());
        assert_eq!(rig.control.producer_mut().next_seq(), head);
        let second = rig.partial(2, 2, None, 2).0[0];
        let seq = first.pending.data.reservation().read().seq();
        assert_eq!(second.pending.data.reservation().read().seq(), seq);
        assert!(rig.store.context(&ROOT).is_none());
        if format == ForkName::Fulu {
            assert!(matches!(
                first.pending.data.acquire(&mut rig.columns),
                Err(SubReservationError::Incomplete)
            ));
        }

        rig.admit();
        let columns = rig.reservations();
        assert_eq!(columns[0].reservation.read().seq(), seq);
        for pending in [first.pending, second.pending] {
            let validation = pending.data.acquire(&mut rig.columns).unwrap();
            assert_eq!(validation.buffers(), [&[0x11; BYTES_PER_CELL][..], &PROOF[..]]);
            validation.accept().unwrap();
        }
        let complete = rig.store.refresh_column(&ROOT, 0, &mut rig.columns).unwrap();
        assert!(complete.column_completed);
        let read = rig.columns.acquire_strict(complete.complete_read.unwrap()).unwrap();
        assert_eq!(read.buffer().unwrap().0.len(), rig.full_bytes(0).len());
    }
}

#[test]
fn conflicting_first_contact_suppresses_cells_until_trusted_replacement() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        let old = rig.partial(1, 1, None, 1).0[0];
        let head = rig.control.producer_mut().next_seq();
        assert!(rig.partial(2, 2, None, 2).0.is_empty());
        assert!(rig.partial(1, 1, None, 3).0.is_empty());
        assert_eq!(rig.control.producer_mut().next_seq(), head);
        rig.admit();
        let columns = rig.reservations();
        assert_ne!(
            columns[0].reservation.read().seq(),
            old.pending.data.reservation().read().seq()
        );
        assert!(matches!(
            old.pending.data.acquire(&mut rig.columns),
            Err(SubReservationError::Closed)
        ));
        let next = rig.partial(2, 1, None, 2).0[0];
        assert!(!rig.control.cancel(old.pending, rig.now));
        let validation = next.pending.data.acquire(&mut rig.columns).unwrap();
        validation.accept().unwrap();
    }
}

#[test]
fn trusted_agreement_unlatches_conflict_without_rewriting_candidate_cells() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        let first = rig.partial(2, 1, None, 1).0[0];
        assert!(rig.partial(1, 1, None, 2).0.is_empty());
        assert!(rig.partial(2, 2, None, 3).0.is_empty());
        rig.admit();
        let columns = rig.reservations();
        assert_eq!(
            columns[0].reservation.read().seq(),
            first.pending.data.reservation().read().seq()
        );
        first.pending.data.acquire(&mut rig.columns).unwrap().accept().unwrap();
        assert_eq!(rig.partial(2, 2, None, 3).0.len(), 1);
    }
}

#[test]
fn headers_still_reach_validation_after_a_conflicting_first_contact() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.partial(1, 1, None, 1);
    rig.partial(2, 2, None, 2);
    let mut signed = [0x33; 208];
    signed[..8].copy_from_slice(&0u64.to_le_bytes());
    let data = ContextData::Fulu {
        signed_header: &signed,
        inclusion_proof: &[0x33; 128],
        commitments: &[0x33; 96],
    };
    let mut bytes = vec![0; data.encoded_len()];
    data.write(&mut bytes);
    // A header-only message need not use a bitmap matching its commitments.
    let (cells, headers) = rig.partial(0, 0, Some(&bytes), 3);
    assert!(cells.is_empty());
    assert_eq!(headers.len(), 1);
    rig.admit();
    rig.reservations();
    assert_eq!(rig.partial(2, 1, None, 3).0.len(), 1);
}

#[test]
fn expiry_closes_unconfirmed_cells_without_leaking_the_retained_tail() {
    let mut rig = Rig::new(ForkName::Fulu);
    let pending = rig.partial(2, 1, None, 1).0[0].pending;
    rig.now = rig.start + SLOT;
    let event = rig.expire();
    rig.network_boundaries();
    assert!(event.retain_from > pending.data.reservation().read().seq());
    assert!(pending.data.acquire(&mut rig.columns).is_err());
    rig.fill();
}

#[test]
fn speculative_budget_is_cumulative_and_preserves_trusted_replacement_capacity() {
    let mut rig = Rig::new(ForkName::Gloas);
    let domain = GossipDomain::new([0; 4], ForkName::Gloas);
    let context = rig.context;
    let allocator = rig.control.allocator_mut();
    allocator.optimistic(context, domain, None, 1).unwrap();
    let head = allocator.producer().next_seq();
    let other = CommitmentContext { block_root: [2; 32], ..context };
    assert!(matches!(allocator.optimistic(other, domain, None, 1), Err(StoreError::Full)));
    assert_eq!(allocator.producer().next_seq(), head);
    allocator.reject(&ROOT);
    assert!(matches!(allocator.optimistic(context, domain, None, 1), Err(StoreError::Full)));
    allocator.optimistic(other, domain, None, 2).unwrap();
    allocator
        .optimistic(CommitmentContext { block_root: [3; 32], ..context }, domain, None, 3)
        .unwrap();
    assert!(matches!(
        allocator.optimistic(CommitmentContext { block_root: [4; 32], ..context }, domain, None, 4),
        Err(StoreError::Full)
    ));
    let trusted = allocator
        .allocate(AssemblyRequest { id: 1, context, domain, columns: 7, source: None }, None)
        .unwrap();
    assert_eq!(trusted.request.context, context);
    rig.now = rig.start + SLOT;
    rig.expire();
    rig.network_boundaries();
    rig.control
        .allocator_mut()
        .optimistic(CommitmentContext { slot: 1, ..context }, domain, None, 1)
        .unwrap();
}

#[test]
fn failed_fulu_promotion_closes_every_partially_initialized_column_before_retry() {
    let mut rig = Rig::new(ForkName::Fulu);
    let pending = rig.partial(2, 1, None, 1).0[0].pending;
    let allocator = rig.control.allocator_mut();
    let column = allocator.column(CellKey { column: 1, ..pending.key }).unwrap();
    allocator.producer().view_sub_reservation(column.reservation).unwrap().close();
    rig.admit();
    let mut request = None;
    rig.adapters[1].consume(|event: CellStoreEvent, _| {
        if let CellStoreEvent::Allocated { request: failed, set } = event {
            assert!(set.is_none());
            request = Some(failed);
        }
    });
    assert!(matches!(pending.data.acquire(&mut rig.columns), Err(SubReservationError::Closed)));
    let set = rig.control.allocator_mut().allocate(request.unwrap(), None).unwrap();
    assert!(
        set.reservations
            .view(rig.control.allocator_mut().producer())
            .unwrap()
            .all(|reference| reference.read().seq() > pending.data.reservation().read().seq())
    );
}
