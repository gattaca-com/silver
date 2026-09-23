use std::{
    array,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_chain_spec::{ForkName, SpecConfig};
use silver_columns::cell_store::CellStore;
use silver_common::{
    GossipDomain, GossipTopic, Nanos, P2pStreamId, SilverSpine, StreamProtocol,
    SubReservationError, TCache, TCacheId, TCacheProducer, TCacheRead, TCacheReader, TCacheRef,
    TProducer, TReadMode, TReservation,
    cell_store::{
        CellKey, CellOrigin, CellSource, CellStoreConfig, CellStoreEvent, CellValidationOutcome,
        CellValidationRequest, ColumnRef, CommitmentContext, ContextData, FuluContextSource,
        RetentionEvent, StoreError,
    },
    column_util::push_data_column_sidecar_prefix,
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};
use silver_control::cell_ingress::CellIngress;
use tempfile::TempDir;

const ROOT: [u8; 32] = [1; 32];
const PROOF: [u8; BYTES_PER_KZG_PROOF] = [0x22; BYTES_PER_KZG_PROOF];
const SLOT: Duration = Duration::from_secs(12);

#[path = "cell_ingress/partial.rs"]
mod partial;

struct Endpoint;

impl Tile<SilverSpine> for Endpoint {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

struct Rig {
    control: CellIngress,
    store: CellStore,
    columns: Box<TCacheReader>,
    network: Box<TCacheReader>,
    el: TProducer,
    el_consumer: TCacheReader,
    adapters: [SpineAdapter<SilverSpine>; 3],
    cache: TCacheRef,
    now: Instant,
    start: Instant,
    context: CommitmentContext,
    _spine: Box<SilverSpine>,
    _directory: TempDir,
}

#[test]
fn block_derived_header_is_copied_from_el_cache_into_the_shared_cache() {
    let mut rig = Rig::new(ForkName::Fulu);
    let mut header = [0x33; 208];
    header[..8].copy_from_slice(&rig.context.slot.to_le_bytes());
    let data = ContextData::Fulu {
        signed_header: &header,
        inclusion_proof: &[0x33; 128],
        commitments: &[0x33; 96],
    };
    let mut write = rig.el.reserve(data.encoded_len(), false).unwrap();
    data.write(write.buffer().unwrap());
    write.flush().unwrap();
    let source = FuluContextSource::ElHeader(write.read());
    rig.store
        .admit_context(rig.context, GossipDomain::new([0; 4], ForkName::Fulu), data, Some(source))
        .unwrap();
    let request = rig.store.request_assemblies(&ROOT).unwrap();
    rig.adapters[1].produce(CellStoreEvent::Allocate(request));
    rig.adapters[0].consume(|event: CellStoreEvent, producers| {
        rig.control.handle(event, rig.now, producers, &mut rig.el_consumer);
    });
    assert_eq!(rig.reservations().len(), 3);
    let header = rig.store.availability(&ROOT, 0).unwrap().header.unwrap();
    assert_eq!(header.id(), rig.cache.id());
    assert_ne!(header.id(), rig.el.cache_ref().id());
    assert!(data.matches(rig.control.producer_mut().read_buffer(header).unwrap()));
}

impl Rig {
    fn new(format: ForkName) -> Self {
        let spec = Arc::new(SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { u64::MAX },
            max_blobs_per_block_electra: 2,
            blob_schedule: Vec::new(),
            ..SpecConfig::mainnet()
        });
        let config = CellStoreConfig::new(spec, 7, Duration::from_secs(11)).unwrap();
        let producer = TCache::producer(TCacheId::ControlSlot, config.cache_capacity());
        let cache = producer.cache_ref();
        let columns = Box::new(TCacheReader::single(cache, "", TReadMode::Retained).unwrap());
        let network = Box::new(TCacheReader::single(cache, "", TReadMode::Retained).unwrap());
        let el = TCache::producer(TCacheId::ColumnsProcessing, 4096);
        let el_consumer = TCacheReader::single(el.cache_ref(), "", TReadMode::Sliding).unwrap();
        let now = Instant::now();
        let directory = tempfile::tempdir().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(directory.path(), None));
        let adapters = array::from_fn(|_| {
            let mut adapter = SpineAdapter::connect_tile(&Endpoint, &mut *spine);
            adapter.consume(|_: RetentionEvent, _| {});
            adapter.consume(|_: CellStoreEvent, _| {});
            adapter
        });
        Self {
            control: CellIngress::new(config.clone(), producer, 0, now).unwrap(),
            store: CellStore::new(config, 0, now).unwrap(),
            columns,
            network,
            el,
            el_consumer,
            adapters,
            cache,
            now,
            start: now,
            context: CommitmentContext { block_root: ROOT, slot: 0, format, blob_count: 2 },
            _spine: spine,
            _directory: directory,
        }
    }

    fn admit(&mut self) {
        let mut header = [0x33; 208];
        header[..8].copy_from_slice(&self.context.slot.to_le_bytes());
        let data = if self.context.format == ForkName::Fulu {
            ContextData::Fulu {
                signed_header: &header,
                inclusion_proof: &[0x33; 128],
                commitments: &[0x33; 96],
            }
        } else {
            ContextData::Gloas { commitments: &[0x33; 96] }
        };
        let source = if self.context.format == ForkName::Fulu {
            let mut header =
                self.control.producer_mut().reserve(data.encoded_len(), false).unwrap();
            data.write(header.buffer().unwrap());
            header.flush().unwrap();
            Some(FuluContextSource::Header(header.read()))
        } else {
            None
        };
        let domain = GossipDomain::new([0; 4], self.context.format);
        assert!(self.store.admit_context(self.context, domain, data, source).unwrap());
        let request = self.store.request_assemblies(&ROOT).unwrap();
        self.adapters[1].produce(CellStoreEvent::Allocate(request));
        self.adapters[0].consume(|event: CellStoreEvent, producers| {
            self.control.handle(event, self.now, producers, &mut self.el_consumer)
        });
    }

    fn reservations(&mut self) -> Vec<ColumnRef> {
        let mut contexts = 0;
        self.adapters[1].consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Allocated { request, set } = event {
                assert_eq!(request.context, self.context);
                self.store.install(set.unwrap(), &mut self.columns).unwrap();
                contexts += 1;
            }
        });
        assert_eq!(contexts, 1);
        self.store.reservations(&ROOT).collect()
    }

    fn reserve(&mut self, len: usize) -> Result<TReservation, StoreError> {
        self.control.producer_mut().reserve(len, false).ok_or(StoreError::CacheFull)
    }

    fn write(&mut self, len: usize, byte: u8) -> TCacheRead {
        let mut write = self.reserve(len).unwrap();
        write.buffer().unwrap().fill(byte);
        write.flush().unwrap();
        write.read()
    }

    fn fill(&mut self) {
        let mut count = 0;
        while let Ok(mut write) = self.reserve(8192) {
            write.buffer().unwrap().fill(0xcc);
            write.flush().unwrap();
            count += 1;
            assert!(count <= self.cache.capacity() / 8192 + 2);
        }
    }

    fn expire(&mut self) -> RetentionEvent {
        self.control.spin(self.now, &self.adapters[0].producers);
        self.store.advance(self.now, 0, |_| {});
        let mut boundary = None;
        self.adapters[1].consume(|event: RetentionEvent, _| {
            assert!(boundary.is_none());
            self.columns.advance_retention(TCacheId::ControlSlot, event.retain_from);
            boundary = Some(event);
        });
        boundary.unwrap()
    }

    fn network_boundaries(&mut self) {
        self.adapters[2].consume(|event: RetentionEvent, _| {
            self.network.advance_retention(TCacheId::ControlSlot, event.retain_from);
        });
    }

    fn full_bytes(&self, column: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        if self.context.format == ForkName::Fulu {
            let mut header = [0x33; 208];
            header[..8].copy_from_slice(&self.context.slot.to_le_bytes());
            push_data_column_sidecar_prefix(&mut bytes, column as u64, 2, &header, &[0x33; 128]);
        } else {
            bytes.extend_from_slice(&(column as u64).to_le_bytes());
            bytes.extend_from_slice(&56u32.to_le_bytes());
            bytes.extend_from_slice(&((56 + 2 * BYTES_PER_CELL) as u32).to_le_bytes());
            bytes.extend_from_slice(&self.context.slot.to_le_bytes());
            bytes.extend_from_slice(&ROOT);
        }
        for row in 0..2 {
            bytes.extend_from_slice(&[0x11 + row as u8; BYTES_PER_CELL]);
        }
        if self.context.format == ForkName::Fulu {
            bytes.extend_from_slice(&[0x33; 96]);
        }
        bytes.extend_from_slice(&[0x22; 2 * BYTES_PER_KZG_PROOF]);
        bytes
    }
}

#[test]
fn gossip_full_sidecars_and_cells_share_one_cache_through_validation_and_expiry() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        let expires = rig.start + SLOT;
        let bytes = rig.full_bytes(0);
        let mut full = rig.reserve(bytes.len()).unwrap();
        full.write_all(&bytes).unwrap();
        full.flush().unwrap();
        let full_read = full.read();
        drop(full);

        // The first full sidecar precedes the block's assembly reservations.
        rig.admit();
        let columns = rig.reservations();
        assert_eq!(columns.len(), 3);
        assert!(columns[0].reservation.read().seq() > full_read.seq());
        let validation = rig.columns.acquire_strict(full_read).unwrap();
        assert_eq!(validation.buffer().unwrap().0, bytes);
        drop(validation);
        // Cryptographic validation is outside this ownership fixture.
        rig.store.retain_full(&ROOT, 0, full_read, &mut rig.columns).unwrap();

        for row in 0..2 {
            let pending = if row == 0 {
                rig.control
                    .stage_cell(
                        CellKey { block_root: ROOT, column: 1, row },
                        &[0x11; BYTES_PER_CELL],
                        &PROOF,
                        rig.now,
                    )
                    .unwrap()
                    .unwrap()
            } else {
                columns[1]
                    .stage(&mut rig.columns, row, &[0x12; BYTES_PER_CELL], &PROOF)
                    .unwrap()
                    .unwrap()
            };
            let origin = if row == 0 {
                CellOrigin::Gossip {
                    stream_id: P2pStreamId::new(42, 7, StreamProtocol::GossipSub, true),
                    topic: GossipTopic::DataColumnSidecar(1),
                    received: Nanos::now(),
                }
            } else {
                CellOrigin::El { request_id: 99 }
            };
            rig.adapters[row].produce(CellStoreEvent::Validate(CellValidationRequest {
                pending,
                slot: rig.context.slot,
                origin,
                deadline: expires,
                domain: GossipDomain::new([0; 4], format),
            }));
        }

        let mut validated = 0;
        rig.adapters[1].consume(|event: CellStoreEvent, producers| {
            if let CellStoreEvent::Validate(request) = event {
                let validation = request.pending.data.acquire(&mut rig.columns).unwrap();
                assert_eq!(
                    validation.buffers()[0],
                    &[0x11 + request.pending.key.row as u8; BYTES_PER_CELL]
                );
                validation.accept().unwrap();
                producers.produce(CellStoreEvent::Validation {
                    request,
                    outcome: CellValidationOutcome::Accepted,
                });
                validated += 1;
            }
        });
        assert_eq!(validated, 2);
        rig.store.refresh_column(&ROOT, 1, &mut rig.columns).unwrap();
        rig.adapters[1]
            .produce(CellStoreEvent::Available(rig.store.availability(&ROOT, 1).unwrap()));
        rig.adapters[0].consume(|event: CellStoreEvent, producers| {
            rig.control.handle(event, rig.now, producers, &mut rig.el_consumer);
        });
        let mut available = 0;
        rig.adapters[2].consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Available(column) = event {
                for row in 0..2 {
                    let cell = column.cell(row).unwrap();
                    assert_eq!(cell.read().id(), rig.cache.id());
                    let acquired = cell.acquire(&mut rig.network).unwrap();
                    assert_eq!(acquired.proof.as_ref(), PROOF);
                    available += 1;
                }
            }
        });
        assert_eq!(available, 2);

        let full = rig.store.cell(CellKey { block_root: ROOT, column: 0, row: 0 }).unwrap();
        let assembly = rig.store.cell(CellKey { block_root: ROOT, column: 1, row: 0 }).unwrap();
        assert!(matches!(full.source, CellSource::Full { .. }));
        assert!(matches!(assembly.source, CellSource::Assembly { .. }));
        assert_eq!(full.read().seq(), full_read.seq());
        assert_eq!(full.read().id(), assembly.read().id());

        for _ in 0..rig.cache.capacity() / 8192 / 2 {
            let newer = rig.write(8192, 0xcc);
            drop(rig.columns.acquire_strict(newer).unwrap());
            drop(rig.network.acquire_strict(newer).unwrap());
        }
        rig.now = expires - Duration::from_nanos(1);
        rig.control.spin(rig.now, &rig.adapters[0].producers);
        rig.adapters[2].consume(|_: RetentionEvent, _| panic!("expired before the slot boundary"));
        let full_send = full.acquire(&mut rig.network).unwrap();
        let assembly_send = assembly.acquire(&mut rig.network).unwrap();
        assert_eq!(full_send.cell.as_ref(), &[0x11; BYTES_PER_CELL]);
        assert_eq!(assembly_send.cell.as_ref(), &[0x11; BYTES_PER_CELL]);

        rig.now = expires;
        let event = rig.expire();
        assert_eq!(event.expired_slot, 0);
        rig.network_boundaries();
        assert_eq!(rig.store.counts().cells, 0);
        assert_eq!(full_send.cell.as_ref(), &[0x11; BYTES_PER_CELL]);
        assert_eq!(assembly_send.cell.as_ref(), &[0x11; BYTES_PER_CELL]);
        assert!(columns[1].reservation.acquire(&mut rig.columns).is_err());
    }
}

#[test]
fn cancellation_cannot_reset_a_retry_or_an_active_validator() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.admit();
    let column = rig.reservations()[0];
    let key = CellKey { block_root: ROOT, column: 0, row: 0 };
    let old =
        rig.control.stage_cell(key, &[0x99; BYTES_PER_CELL], &PROOF, rig.now).unwrap().unwrap();
    let validation = old.data.acquire(&mut rig.columns).unwrap();
    drop(validation);
    let retry =
        rig.control.stage_cell(key, &[0x11; BYTES_PER_CELL], &PROOF, rig.now).unwrap().unwrap();
    assert!(!rig.control.cancel(old, rig.now));
    rig.adapters[0].produce(CellStoreEvent::Cancel(retry));
    rig.adapters[1].consume(|event: CellStoreEvent, _| {
        if let CellStoreEvent::Cancel(pending) = event {
            assert!(pending.data.cancel(&mut rig.columns).unwrap());
        }
    });
    let pending =
        column.stage(&mut rig.columns, 0, &[0x11; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    let validation = pending.data.acquire(&mut rig.columns).unwrap();
    assert!(!rig.control.cancel(pending, rig.now));
    assert_eq!(validation.buffers()[0], &[0x11; BYTES_PER_CELL]);
    validation.accept().unwrap();
}

#[test]
fn delayed_expiry_preserves_next_slot_data_and_newer_events_recover_missed_ones() {
    let mut rig = Rig::new(ForkName::Fulu);
    for _ in 0..8 {
        rig.write(8192, 0x11);
    }
    rig.now += SLOT;
    let old = rig.expire();
    let next = rig.write(32, 0x22);
    for _ in 0..8 {
        let newer = rig.write(8192, 0x33);
        drop(rig.network.acquire_strict(newer).unwrap());
    }
    rig.network_boundaries();
    assert_eq!(rig.network.acquire_strict(next).unwrap().buffer().unwrap().0, &[0x22; 32]);
    rig.now += SLOT;
    let missed = rig.expire();
    for _ in 0..8 {
        rig.write(8192, 0x33);
    }
    rig.now += SLOT;
    let latest = rig.expire();
    // The latest boundary is sufficient even if earlier notifications are missed.
    rig.network.advance_retention(TCacheId::ControlSlot, latest.retain_from);
    rig.network.advance_retention(TCacheId::ControlSlot, missed.retain_from);
    rig.network.advance_retention(TCacheId::ControlSlot, old.retain_from);
    for _ in 0..20 {
        rig.write(8192, 0x44);
    }
}

#[test]
fn active_writers_validators_and_sends_survive_expiry_without_store_pins() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.admit();
    let columns = rig.reservations();
    let key = CellKey { block_root: ROOT, column: 0, row: 0 };
    let pending =
        rig.control.stage_cell(key, &[0x11; BYTES_PER_CELL], &PROOF, rig.now).unwrap().unwrap();
    pending.data.acquire(&mut rig.columns).unwrap().accept().unwrap();
    rig.store.refresh_column(&ROOT, 0, &mut rig.columns).unwrap();
    let send = rig.store.cell(key).unwrap().acquire(&mut rig.network).unwrap();
    let pending =
        columns[0].stage(&mut rig.columns, 1, &[0x22; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    let validation = pending.data.acquire(&mut rig.columns).unwrap();
    let writer = columns[1].reservation.acquire(&mut rig.columns).unwrap();
    let writing = writer.claim(0).unwrap();
    rig.now += SLOT;
    rig.expire();
    rig.network_boundaries();
    rig.fill();
    assert_eq!(send.cell.as_ref(), &[0x11; BYTES_PER_CELL]);
    assert_eq!(validation.buffers()[0], &[0x22; BYTES_PER_CELL]);
    drop(send);
    assert!(rig.reserve(8192).is_err());
    drop(validation);
    rig.fill();
    rig.now += SLOT;
    rig.expire();
    rig.network_boundaries();
    assert!(rig.reserve(8192).is_err());
    assert!(matches!(
        writing.write(&[0x33; BYTES_PER_CELL], &PROOF),
        Err(SubReservationError::Closed)
    ));
    drop(writer);
    assert!(rig.reserve(8192).is_ok());
}
