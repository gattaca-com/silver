use silver_common::{
    ColumnOrigin, DataKind, SszCache,
    cell_store::CellKey,
    ssz_view::{DataColumnSidecarFuluView, DataColumnSidecarGloasView},
};

use super::*;
use crate::partial_exchange::acquisition::Acquisition;

impl Rig {
    pub(super) fn enable_requests(&mut self) {
        self.exchange.acquisition = Some(Acquisition::new(&self.config, 0, self.now));
    }

    pub(super) fn demand(&mut self, columns: u128) {
        self.exchange.context(
            AssemblyRequest { columns, ..self.request },
            self.ingress.slot_window().1,
            self.now,
        );
    }

    pub(super) fn availability(&mut self, column: usize, rows: u128) {
        let mut available = self.store.availability(&ROOT, column).unwrap();
        available.available = rows;
        self.ingress.update_availability(available, self.now);
        self.exchange.available(available, &self.peers, self.now, false);
    }

    fn offer(&mut self, peer: usize, column: u64, rows: u128) {
        let mut message = self.message(peer, rows, 0);
        message.group.column = column;
        self.exchange.metadata(message, &self.ingress, &self.peers, self.now);
    }

    fn acquire(&mut self) -> Vec<SyncNeed> {
        let mut recovered = Vec::new();
        self.exchange.advance(
            &self.ingress,
            &self.peers,
            &mut self.output,
            self.now,
            &mut |_| {},
            &mut |need| recovered.push(need),
        );
        self.exchange
            .acquire(&self.ingress, &self.peers, self.now, &mut |need| recovered.push(need));
        recovered
    }

    fn requests(&mut self) -> Vec<(usize, u64, u128, u128)> {
        self.spin()
            .into_iter()
            .map(|(peer, frame)| {
                let wire = self.wire(frame);
                let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
                let partial = rpc.partial.as_option().unwrap();
                let (available, requests) = PartialDataColumnPartsMetadataView::check_size(
                    partial.parts_metadata.unwrap(),
                    ROWS,
                )
                .unwrap();
                let topic = std::str::from_utf8(partial.topic_id.unwrap()).unwrap();
                let GossipTopic::DataColumnSidecar(column) =
                    GossipTopic::from_wire(topic, "00000000").unwrap()
                else {
                    panic!("unexpected topic")
                };
                (peer, column, available, requests)
            })
            .collect()
    }

    pub(super) fn complete(&mut self, column: u64) {
        // Acquisition uses the completion identity, not the RPC sidecar bytes.
        let mut ssz = self.output.reserve(0, false).unwrap();
        ssz.flush().unwrap();
        self.exchange.validated(
            DataColumnsEvent::Validated {
                block_root: ROOT,
                column_index: column,
                slot: self.ingress.slot_window().0,
                origin: ColumnOrigin::Rpc,
                ssz: ssz.read(),
                ssz_cache: SszCache::Rpc,
            },
            self.now,
        );
    }
}

#[test]
fn only_trusted_context_requests_missing_rows_and_rpc_completion_cancels_demand() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.enable_requests();
        rig.connect(1, false, false);
        rig.connect(2, false, true);
        rig.offer(1, 1, 0b0110);
        rig.offer(2, 1, 0b0010);
        assert!(rig.acquire().is_empty());
        assert!(rig.requests().iter().all(|request| request.3 == 0));
        // This mirrors Columns' installed, validated-context handoff. The
        // metadata and speculative allocation alone cannot start acquisition.
        rig.availability(1, 0b1001);
        assert!(rig.acquire().is_empty());
        assert!(rig.requests().iter().all(|request| request.3 == 0));
        rig.demand(2);
        assert!(rig.acquire().is_empty());
        let requests = rig.requests();
        assert!(requests.contains(&(1, 1, 0b1001, 0b0110)), "{requests:?}");
        assert!(requests.iter().all(|request| request.0 == 1 || request.3 == 0));

        rig.availability(1, 0b1011);
        rig.acquire();
        assert!(rig.requests().contains(&(1, 1, 0b1011, 0b0100)));
        rig.complete(1);
        rig.acquire();
        assert!(rig.requests().contains(&(1, 1, 0b1011, 0)));
        // Losing sendable bytes must not turn an RPC-completed column into demand.
        rig.availability(1, 0);
        rig.demand(2);
        rig.now += Duration::from_secs(1);
        assert!(rig.acquire().is_empty());
        assert!(rig.requests().iter().all(|request| request.3 == 0));
    }
}

#[test]
fn verified_partial_rows_finish_the_canonical_sidecar_and_cancel_requests() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.enable_requests();
        rig.connect(1, false, true);
        rig.availability(1, 0);
        rig.demand(2);
        rig.offer(1, 1, 15);
        rig.acquire();
        assert!(rig.requests().contains(&(1, 1, 0, 15)));
        let mut complete = None;
        for row in 0..ROWS {
            let pending = rig
                .ingress
                .stage_cell(
                    CellKey { block_root: ROOT, column: 1, row },
                    &[row as u8; BYTES_PER_CELL],
                    &[row as u8; BYTES_PER_KZG_PROOF],
                    rig.now,
                )
                .unwrap()
                .unwrap();
            // The validator's successful KZG handoff is the boundary under test.
            pending.data.acquire(&mut rig.columns).unwrap().accept().unwrap();
            let update = rig.store.refresh_column(&ROOT, 1, &mut rig.columns).unwrap();
            complete = update.complete_read;
            let available = rig.store.availability(&ROOT, 1).unwrap();
            rig.ingress.update_availability(available, rig.now);
            rig.exchange.available(available, &rig.peers, rig.now, false);
            assert!(rig.acquire().is_empty());
            let bits = (1 << (row + 1)) - 1;
            assert!(rig.requests().contains(&(1, 1, bits, 15 & !bits)));
        }
        let read = rig.columns.acquire_strict(complete.unwrap()).unwrap();
        let bytes = read.buffer().unwrap().0;
        let cells = if format == ForkName::Fulu {
            assert!(DataColumnSidecarFuluView::check_size(bytes));
            DataColumnSidecarFuluView::column(bytes)
        } else {
            assert!(DataColumnSidecarGloasView::check_size(bytes));
            DataColumnSidecarGloasView::column(bytes)
        };
        for (row, cell) in cells.chunks_exact(BYTES_PER_CELL).enumerate() {
            assert_eq!(cell, &[row as u8; BYTES_PER_CELL]);
        }
        drop(read);
        rig.now += Duration::from_secs(1);
        assert!(rig.acquire().is_empty());
        assert!(rig.requests().iter().all(|request| request.3 == 0));
    }
}

#[test]
fn completion_before_context_and_unknown_metadata_never_start_requests() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.enable_requests();
    rig.connect(1, false, true);
    rig.complete(1);
    rig.demand(2);
    rig.availability(1, 0);
    for i in 10..200u8 {
        let mut message = rig.message(1, 15, 0);
        message.group.block_root = [i; 32];
        rig.exchange.metadata(message, &rig.ingress, &rig.peers, rig.now);
    }
    assert!(rig.acquire().is_empty());
    assert!(rig.requests().iter().all(|request| request.3 == 0));
    rig.now += Duration::from_secs(12);
    rig.ingress.allocator_mut().advance(rig.now, 0).unwrap();
    assert!(rig.acquire().is_empty());
    assert!(rig.requests().iter().all(|request| request.3 == 0));
    rig.demand(2); // Expired context cannot be revived in the new slot.
    assert!(rig.acquire().is_empty());
}

#[test]
fn sparse_columns_include_the_highest_bit_and_cancel_all_requests_on_fallback() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let columns = 1 | (1 << 127);
        let mut rig = Rig::with_columns(format, columns);
        rig.enable_requests();
        rig.connect(1, false, true);
        rig.demand(columns);
        for column in [0, 127] {
            rig.availability(column, 0);
        }
        assert!(rig.acquire().is_empty());
        let requests = rig.requests();
        assert!(requests.contains(&(1, 0, 0, 15)));
        assert!(requests.contains(&(1, 127, 0, 15)));
        rig.now += Duration::from_millis(750);
        assert!(
            matches!(rig.acquire().as_slice(), [SyncNeed::Missing { columns: missing, .. }] if *missing == columns)
        );
        let requests = rig.requests();
        assert!(requests.contains(&(1, 0, 0, 0)));
        assert!(requests.contains(&(1, 127, 0, 0)));
        rig.now += Duration::from_secs(1);
        assert!(rig.acquire().is_empty());
    }
}

#[test]
fn timeout_changes_peer_then_hands_remaining_columns_to_full_recovery_once() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.enable_requests();
    rig.connect(1, false, true);
    rig.connect(2, false, true);
    rig.demand(3);
    for column in 0..2 {
        rig.availability(column, 0);
    }
    assert!(rig.acquire().is_empty());
    let first = rig.requests();
    assert!(first.contains(&(1, 0, 0, 15)));
    assert!(first.contains(&(2, 1, 0, 15)));
    rig.now += Duration::from_millis(250);
    assert!(rig.acquire().is_empty());
    let second = rig.requests();
    assert!(second.contains(&(2, 1, 0, 0)));
    assert!(second.contains(&(1, 1, 0, 15)));
    rig.complete(0);
    rig.now += Duration::from_millis(250);
    let recovery = rig.acquire();
    assert_eq!(recovery.len(), 1);
    assert!(matches!(recovery[0], SyncNeed::Missing {
        root: ROOT,
        kind: DataKind::Columns,
        columns: 2,
        ..
    }));
    assert!(rig.requests().iter().all(|request| request.3 == 0));
    rig.now += Duration::from_secs(1);
    rig.demand(3);
    assert!(rig.acquire().is_empty());
    assert!(rig.requests().iter().all(|request| request.3 == 0));
    rig.now += Duration::from_secs(12);
    rig.ingress.allocator_mut().advance(rig.now, 0).unwrap();
    assert!(rig.acquire().is_empty());
}

#[test]
fn withdrawal_and_disconnect_switch_peer_without_penalizing_expired_promises() {
    for disconnect in [false, true] {
        let mut rig = Rig::new(ForkName::Gloas);
        rig.enable_requests();
        rig.connect(1, false, true);
        rig.connect(2, false, false);
        rig.availability(1, 0);
        rig.demand(2);
        rig.offer(1, 1, 15);
        rig.offer(2, 1, 15);
        rig.acquire();
        assert!(rig.requests().contains(&(1, 1, 0, 15)));
        if disconnect {
            let event = PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: PeerId::default() };
            rig.exchange.peer_event(&event, rig.now);
            rig.peers.handle_event(event, rig.now, &mut |_| {});
            rig.now += Duration::from_millis(20);
        } else {
            rig.offer(1, 1, 0);
        }
        assert!(rig.acquire().is_empty());
        assert!(rig.requests().contains(&(2, 1, 0, 15)));
    }
}

#[test]
fn no_peers_or_no_installed_assembly_recovers_and_rejected_context_does_not() {
    for installed in [false, true] {
        let mut rig = Rig::new(ForkName::Fulu);
        rig.enable_requests();
        rig.demand(3);
        if installed {
            rig.availability(0, 0);
            rig.availability(1, 0);
        } else {
            rig.connect(1, false, true);
        }
        assert!(rig.acquire().is_empty());
        rig.now += Duration::from_millis(750);
        assert!(matches!(rig.acquire().as_slice(), [SyncNeed::Missing {
            root: ROOT,
            columns: 3,
            ..
        }]));
        assert!(rig.requests().iter().all(|request| request.3 == 0));
    }
    let mut rig = Rig::new(ForkName::Fulu);
    rig.enable_requests();
    rig.demand(3);
    rig.exchange.reject(&ROOT);
    rig.now += Duration::from_secs(1);
    assert!(rig.acquire().is_empty());
}

#[test]
fn dropped_request_retries_without_extending_the_acquisition_deadline() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.enable_requests();
    rig.connect(1, false, true);
    rig.availability(1, 0);
    rig.demand(2);
    rig.acquire();
    let first = rig.spin();
    assert_eq!(first.len(), 1);
    rig.dropped(1, first[0].1);
    rig.now += RETRY;
    assert!(rig.acquire().is_empty());
    assert!(rig.requests().contains(&(1, 1, 0, 15)));
    rig.now += Duration::from_millis(650);
    assert_eq!(rig.acquire().len(), 1);
    assert!(rig.requests().iter().all(|request| request.3 == 0));
}

#[test]
fn live_fulu_to_gloas_cutover_uses_new_context_group_and_requests_without_a_header() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.enable_requests();
    rig.connect(1, true, true);
    rig.availability(1, 0);
    rig.demand(2);
    rig.acquire();
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    let partial = rpc.partial.as_option().unwrap();
    assert_eq!(partial.group_id.unwrap().len(), 33);
    assert!(!PartialDataColumnSidecarFuluView::header(partial.partial_message.unwrap()).is_empty());

    rig.complete(1);
    rig.acquire();
    rig.spin();
    rig.now += Duration::from_secs(32 * 12);
    let boundary = rig.ingress.allocator_mut().advance(rig.now, 0).unwrap();
    rig.store.advance(rig.now, 0, |_| {});
    rig.network.advance_retention(TCacheId::ControlSlot, boundary.retain_from);
    rig.columns.advance_retention(TCacheId::ControlSlot, boundary.retain_from);
    assert!(rig.acquire().is_empty());
    rig.spin();
    let next_domain = GossipDomain::new([2; 4], ForkName::Gloas);
    rig.peers.set_active_domains(next_domain.digest(), Some(rig.domain.digest()), &mut |_| {});
    for event in [
        PeerEvent::P2pGossipTopicSubscribe {
            p2p_peer: 1,
            topic: GossipTopic::DataColumnSidecar(1),
            digest: next_domain.digest(),
        },
        PeerEvent::P2pGossipPartialCaps {
            p2p_peer: 1,
            subnet: 1,
            digest: next_domain.digest(),
            requests: true,
            supports_sending: true,
        },
    ] {
        rig.peers.handle_event(event, rig.now, &mut |_| {});
    }
    let root = [8; 32];
    let context =
        CommitmentContext { block_root: root, slot: 32, format: ForkName::Gloas, blob_count: ROWS };
    rig.store
        .admit_context(
            context,
            next_domain,
            ContextData::Gloas { commitments: &[0x44; ROWS * 48] },
            None,
        )
        .unwrap();
    let request = rig.store.request_assemblies(&root).unwrap();
    let set = rig.ingress.allocator_mut().allocate(request, None).unwrap();
    rig.store.install(set, &mut rig.columns).unwrap();
    let available = rig.store.availability(&root, 1).unwrap();
    assert!(available.header.is_none());
    rig.ingress.update_availability(available, rig.now);
    rig.exchange.available(available, &rig.peers, rig.now, false);
    rig.exchange.context(AssemblyRequest { columns: 2, ..request }, set.expires, rig.now);
    assert!(rig.acquire().is_empty());
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    let partial = rpc.partial.as_option().unwrap();
    assert_eq!(partial.topic_id, Some(&b"/eth2/02020202/data_column_sidecar_1/ssz_snappy"[..]));
    assert_eq!(partial.group_id.unwrap().len(), 41);
    assert_eq!(&partial.group_id.unwrap()[33..], &32u64.to_le_bytes());
    assert!(partial.partial_message.is_none());
    assert_eq!(
        PartialDataColumnPartsMetadataView::check_size(partial.parts_metadata.unwrap(), ROWS),
        Some((0, 15))
    );

    rig.exchange.context(rig.request, set.expires, rig.now);
    rig.offer(1, 1, 15); // Delayed Fulu metadata cannot create current-slot demand.
    assert!(rig.acquire().is_empty());
    assert!(rig.spin().is_empty());
}
