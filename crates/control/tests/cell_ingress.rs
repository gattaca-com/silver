use std::{
    array,
    io::Write,
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_chain_spec::{ForkName, SpecConfig};
use silver_columns::cell_store::{CellStoreConfig, CommitmentContext, ContextData};
use silver_common::{
    GossipTopic, MessageId, Nanos, P2pStreamId, SilverSpine, StreamProtocol, SubReservationError,
    TCache, TCacheProducer, TCacheRead, TCacheRef, TRandomAccess,
    cells::{
        CellKey, CellOrigin, CellSource, CellStoreEvent, CellValidationOutcome,
        CellValidationRequest, ColumnRef, RetentionEvent,
    },
    column_util::push_data_column_sidecar_prefix,
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};
use silver_control::cell_ingress::CellIngress;
use tempfile::TempDir;

const ROOT: [u8; 32] = [1; 32];
const PROOF: [u8; BYTES_PER_KZG_PROOF] = [0x22; BYTES_PER_KZG_PROOF];
const SLOT: Duration = Duration::from_secs(12);

struct Endpoint;

impl Tile<SilverSpine> for Endpoint {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

struct Rig {
    control: CellIngress,
    columns: Box<TRandomAccess>,
    network: Box<TRandomAccess>,
    adapters: [SpineAdapter<SilverSpine>; 3],
    cache: TCacheRef,
    now: Instant,
    start: Instant,
    context: CommitmentContext,
    _spine: Box<SilverSpine>,
    _directory: TempDir,
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
        let producer = TCache::producer("", config.cache_capacity());
        let cache = producer.cache_ref();
        let columns = Box::new(cache.retained_random_access("").unwrap());
        let network = Box::new(cache.retained_random_access("").unwrap());
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
            control: CellIngress::new(config, producer, 0, now).unwrap(),
            columns,
            network,
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
        assert!(
            self.control
                .admit_context(self.context, data, self.now, &self.adapters[0].producers)
                .unwrap()
        );
    }

    fn reservations(&mut self) -> Vec<ColumnRef> {
        let mut columns = Vec::new();
        let mut contexts = 0;
        self.adapters[1].consume(|event: CellStoreEvent, _| match event {
            CellStoreEvent::Context { block_root, format, blob_count, ssz, .. } => {
                assert_eq!(block_root, ROOT);
                assert_eq!(format, self.context.format);
                assert_eq!(blob_count, 2);
                assert!(ptr::eq(&*ssz.cache_ref(), &*self.cache));
                contexts += 1;
            }
            CellStoreEvent::Reservation(column) => {
                assert!(ptr::eq(&*column.reservation.read().cache_ref(), &*self.cache));
                columns.push(column);
            }
            _ => {}
        });
        assert_eq!(contexts, 1);
        columns
    }

    fn write(&mut self, len: usize, byte: u8) -> TCacheRead {
        let mut write = self.control.store_mut().reserve_full(len).unwrap();
        write.buffer().unwrap().fill(byte);
        write.flush().unwrap();
        write.read()
    }

    fn fill(&mut self) {
        let mut count = 0;
        while let Ok(mut write) = self.control.store_mut().reserve_full(8192) {
            write.buffer().unwrap().fill(0xcc);
            write.flush().unwrap();
            count += 1;
            assert!(count <= self.cache.capacity() / 8192 + 2);
        }
    }

    fn expire(&mut self) -> RetentionEvent {
        self.control.spin(self.now, &self.adapters[0].producers);
        let mut boundary = None;
        self.adapters[1].consume(|event: RetentionEvent, _| {
            assert!(boundary.is_none());
            self.columns.advance_retention(event.retain_from);
            boundary = Some(event);
        });
        boundary.unwrap()
    }

    fn network_boundaries(&mut self) {
        self.adapters[2].consume(|event: RetentionEvent, _| {
            self.network.advance_retention(event.retain_from);
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
        let mut full = rig.control.store_mut().reserve_full(bytes.len()).unwrap();
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
        rig.control.store_mut().retain_full(&ROOT, 0, full_read).unwrap();

        for row in 0..2 {
            let pending = if row == 0 {
                rig.control
                    .store_mut()
                    .stage_cell(
                        CellKey { block_root: ROOT, column: 1, row },
                        &[0x11; BYTES_PER_CELL],
                        &PROOF,
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
                    message_id: MessageId::default(),
                    received: Nanos::now(),
                }
            } else {
                CellOrigin::El { request_id: 99 }
            };
            rig.adapters[row].produce(CellStoreEvent::Validate(CellValidationRequest {
                pending,
                origin,
                deadline: expires,
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
        rig.adapters[0].consume(|event: CellStoreEvent, producers| {
            rig.control.handle(event, rig.now, producers);
        });
        let mut available = 0;
        rig.adapters[2].consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Available { cell, .. } = event {
                assert!(ptr::eq(&*cell.read().cache_ref(), &*rig.cache));
                let acquired = cell.acquire(&mut rig.network).unwrap();
                assert_eq!(acquired.proof.as_ref(), PROOF);
                available += 1;
            }
        });
        assert_eq!(available, 2);

        let full =
            rig.control.store_mut().cell(CellKey { block_root: ROOT, column: 0, row: 0 }).unwrap();
        let assembly =
            rig.control.store_mut().cell(CellKey { block_root: ROOT, column: 1, row: 0 }).unwrap();
        assert!(matches!(full.source, CellSource::Full { .. }));
        assert!(matches!(assembly.source, CellSource::Assembly { .. }));
        assert_eq!(full.read().seq(), full_read.seq());
        assert!(ptr::eq(&*full.read().cache_ref(), &*assembly.read().cache_ref()));

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
        assert_eq!(rig.control.store_mut().counts().cells, 0);
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
        rig.control.store_mut().stage_cell(key, &[0x99; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    let validation = old.data.acquire(&mut rig.columns).unwrap();
    drop(validation);
    let retry =
        rig.control.store_mut().stage_cell(key, &[0x11; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    assert!(!rig.control.cancel(old, rig.now));
    rig.adapters[1].produce(CellStoreEvent::Cancel(retry));
    rig.adapters[0].consume(|event: CellStoreEvent, producers| {
        rig.control.handle(event, rig.now, producers);
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
    rig.network.advance_retention(latest.retain_from);
    rig.network.advance_retention(missed.retain_from);
    rig.network.advance_retention(old.retain_from);
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
        rig.control.store_mut().stage_cell(key, &[0x11; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    pending.data.acquire(&mut rig.columns).unwrap().accept().unwrap();
    rig.control.store_mut().refresh_column(&ROOT, 0).unwrap();
    let send = rig.control.store_mut().cell(key).unwrap().acquire(&mut rig.network).unwrap();
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
    assert!(rig.control.store_mut().reserve_full(8192).is_err());
    drop(validation);
    rig.fill();
    rig.now += SLOT;
    rig.expire();
    rig.network_boundaries();
    assert!(rig.control.store_mut().reserve_full(8192).is_err());
    assert!(matches!(
        writing.write(&[0x33; BYTES_PER_CELL], &PROOF),
        Err(SubReservationError::Closed)
    ));
    drop(writer);
    assert!(rig.control.store_mut().reserve_full(8192).is_ok());
}
