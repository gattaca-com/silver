use std::{collections::VecDeque, io::Write, str, time::Instant};

use buffa::MessageView;
use flux::spine::SpineAdapter;
use silver_common::{
    Error, GOSSIP_TOPIC_COUNTER_SLOTS, GossipDomain, GossipMsgIn, GossipMsgOut, GossipTopic,
    LOCAL_GOSSIP_STREAM_ID, MessageId, Nanos, NewGossipMsg, P2pStreamId, PeerControl, PeerEvent,
    SelfBuiltGossip, SilverSpine, StreamProtocol, TCacheError, TCacheId, TCacheProducer,
    TCacheRead, TCacheReader, TCacheTable, TProducer, TReadMode, TileId,
    cell_store::PartialColumnsMode, msg_id_valid_snappy,
};

use crate::{
    ColumnIngress, GossipHandlerEvent, PartialInbound, PartialMetadataReceived,
    control::{
        self, copy_idontwants_to_protobuf_output, copy_ihaves_to_protobuf_output, handle_grafts,
        handle_idontwants, handle_ihaves, handle_iwants, handle_prunes, handle_subscriptions,
    },
    dedup::DedupCache,
    generated::RPCView,
    mcache::MessageCache,
    message::{copy_compressed_to_protobuf_output, handle_incoming},
};

/// Reads all incoming gossip protobuf messages (sequential consumer):
/// - handles control messages and emits spine messages
/// - deduplicates individual gossip messages
///   - decompresses individual messages and writes SSZ to downstream TCache
///   - copies individual message snappy to message cache TCache wrapped in
///     protobuf ready for sending
///   - produces `NewGossipMsg` on spine for downstream consumers
///  - periodically generates new IHAVE messages
///    - produces `NewIHaveMsg`s on spine
pub struct GossipHandler {
    incoming_gossip_publish: TProducer,
    domains: ActiveDomains,
    dedup_cache: DedupCache,

    // publisher of gossip message protobufs.
    pub mcache_publish: TProducer,
    mcache: MessageCache,

    // scratch buffer for iwant meessage ids.
    iwant_buffer: Vec<MessageId>,

    // snappy block-compression for locally published messages.
    snap_encoder: snap::raw::Encoder,
    snap_scratch: Vec<u8>,

    extensions: ExtensionTracker,
    partial_columns: PartialColumnsMode,

    events: VecDeque<GossipHandlerEvent>,

    // Last: the mcache's acquired reads point into it.
    reader: TCacheReader,
}

impl GossipHandler {
    pub fn new(
        tcaches: TCacheTable,
        ssz_gossip_publish: TProducer,
        protobuf_gossip_publish: TProducer,
        domain: Option<GossipDomain>,
    ) -> Result<Self, Error> {
        let mcache = MessageCache::new();

        Ok(Self {
            incoming_gossip_publish: ssz_gossip_publish,
            domains: ActiveDomains::new(domain),
            dedup_cache: DedupCache::default(),
            mcache_publish: protobuf_gossip_publish,
            mcache,
            extensions: ExtensionTracker::default(),
            partial_columns: PartialColumnsMode::Off,
            iwant_buffer: Vec::with_capacity(256),
            snap_encoder: snap::raw::Encoder::new(),
            snap_scratch: Vec::new(),
            events: VecDeque::with_capacity(64),
            reader: TCacheReader::new(tcaches),
        })
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(TCacheId::NetworkIngress, "gossip_network_ingress", TReadMode::Sliding)?;
        self.reader.open_forwarder(
            TileId::Control,
            TCacheId::ControlGossip,
            TReadMode::SlidingManualFree,
        )?;
        self.reader.declare(TCacheId::ControlGossip, &[TileId::Columns]);
        Ok(())
    }

    fn generate_ihave_messages(&mut self, now: Instant, emit: &mut impl FnMut(GossipHandlerEvent)) {
        if self.mcache.generate_ihaves(now) {
            let mut seen = [[false; GOSSIP_TOPIC_COUNTER_SLOTS]; 2];
            for &(topic, domain) in self.mcache.topics() {
                // A drained domain's leftover entries advertise nothing.
                let Some((lane, hex)) = self.domains.index_hex(domain) else {
                    continue;
                };
                if seen[lane][topic.counter_slot()] {
                    continue;
                }
                seen[lane][topic.counter_slot()] = true;

                let msgs_iter = self.mcache.get_ihaves(topic, domain);
                let (msg_count, _) = msgs_iter.size_hint(); // exact size iterator
                if msg_count > 0 {
                    if let Ok(tcache) = copy_ihaves_to_protobuf_output(
                        &mut self.mcache_publish,
                        &topic.to_wire(hex),
                        msgs_iter,
                    ) {
                        emit(GossipHandlerEvent::PeerEvent(PeerEvent::OutboundIHave {
                            digest: domain.digest(),
                            topic,
                            msg_count,
                            protobuf: tcache,
                        }));
                    }
                }
            }
        }
    }

    /// Publish an already-validated message that did not arrive over gossip
    /// on `topic`: compress, wrap as protobuf into the outgoing tcache,
    /// register with dedup + mcache (so gossip copies dedupe and IWANTs can
    /// be served). Returns `None` when a gossip copy was already seen, or
    /// pre-Status (no fork digest yet).
    pub fn publish(&mut self, topic: GossipTopic, ssz: &[u8]) -> Option<SelfBuiltGossip> {
        self.publish_in_domain(topic, self.domains.current_domain()?, ssz)
    }

    pub fn publish_in_domain(
        &mut self,
        topic: GossipTopic,
        domain: GossipDomain,
        ssz: &[u8],
    ) -> Option<SelfBuiltGossip> {
        let mut encoded = [0; 8];
        let digest = if let Some((_, digest)) = self.domains.index_hex(domain) {
            digest
        } else {
            hex::encode_to_slice(domain.digest(), &mut encoded).expect("fork digest hex size");
            str::from_utf8(&encoded).expect("hex is ASCII")
        };
        let wire = topic.to_wire(digest);
        if ssz.len() > topic.max_uncompressed_size() {
            tracing::error!(?topic, len = ssz.len(), "outgoing gossip payload too large");
            return None;
        }
        let n = match self.compress(ssz) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(?e, ?topic, "publish snappy compress failed");
                return None;
            }
        };
        let msg_id = msg_id_valid_snappy(&wire, ssz);
        let fast_hash = self.dedup_cache.contains_fast(&wire, &self.snap_scratch[..n]).ok()?;
        if !self.dedup_cache.insert(fast_hash, msg_id) {
            return None;
        }
        let read = copy_compressed_to_protobuf_output(
            &mut self.mcache_publish,
            &self.snap_scratch[..n],
            &wire,
        )
        .inspect_err(|e| tracing::error!(?e, ?topic, "publish protobuf write failed"))
        .ok()?;
        self.mcache.insert(msg_id, topic, domain, read, &mut self.reader);
        let idontwant =
            copy_idontwants_to_protobuf_output(&mut self.mcache_publish, std::iter::once(&msg_id))
                .inspect_err(|e| tracing::error!(?e, ?topic, "publish idontwant write failed"))
                .ok()?;
        Some(SelfBuiltGossip { msg_id, domain, protobuf: read, idontwant })
    }

    /// Inject a locally-originated, not-yet-validated SSZ message at the same
    /// boundary as decoded inbound gossip. The queued TCache references are
    /// retained by `NewGossipMsg` until Beacon State accepts or rejects it;
    /// mcache insertion remains on the accepted `PeerEvent::SendGossip` path.
    ///
    /// Local submissions deliberately bypass inbound deduplication so every
    /// API request receives a Beacon State validation outcome. `Ok(None)`
    /// means the fork digest is not available yet.
    pub fn inject_local(
        &mut self,
        topic: GossipTopic,
        ssz: &[u8],
        ssz_read: Option<TCacheRead>,
        recv_ts: Nanos,
    ) -> Result<Option<MessageId>, Error> {
        let Some((domain, wire)) = self.domains.current_wire(topic) else {
            return Ok(None);
        };
        if ssz.len() > topic.max_uncompressed_size() {
            return Err(Error::GossipPayloadTooLarge);
        }

        let compressed_len = self.compress(ssz)?;
        let compressed = &self.snap_scratch[..compressed_len];
        let msg_id = msg_id_valid_snappy(&wire, ssz);
        let fast_hash = self.dedup_cache.contains_fast(&wire, compressed).ok();

        let (ssz_read, ssz_reservation) = match ssz_read {
            Some(read) => (read, None),
            None => {
                let mut reservation = self
                    .incoming_gossip_publish
                    .reserve(ssz.len(), false)
                    .ok_or(Error::BufferTooSmall)?;
                reservation.write_all(ssz)?;
                (reservation.read(), Some(reservation))
            }
        };

        // From here onward a network duplicate must not race this local
        // candidate into Beacon State first. Roll the entry back if either
        // TCache message cannot be completed.
        let inserted =
            fast_hash.is_some_and(|fast_hash| self.dedup_cache.insert(fast_hash, msg_id));
        let protobuf =
            match copy_compressed_to_protobuf_output(&mut self.mcache_publish, compressed, &wire) {
                Ok(protobuf) => protobuf,
                Err(error) => {
                    if inserted {
                        self.dedup_cache.remove(fast_hash.unwrap(), &msg_id);
                    }
                    return Err(error);
                }
            };
        if let Err(error) = ssz_reservation.map_or(Ok(()), |mut reservation| reservation.flush()) {
            if inserted {
                self.dedup_cache.remove(fast_hash.unwrap(), &msg_id);
            }
            return Err(error.into());
        }

        self.events.push_back(GossipHandlerEvent::NewGossip(NewGossipMsg {
            stream_id: LOCAL_GOSSIP_STREAM_ID,
            topic,
            domain,
            ssz_cache: silver_common::SszCache::Gossip,
            msg_hash: msg_id,
            recv_ts,
            ssz: ssz_read,
            protobuf,
        }));
        Ok(Some(msg_id))
    }

    fn compress(&mut self, ssz: &[u8]) -> Result<usize, snap::Error> {
        let bound = snap::raw::max_compress_len(ssz.len());
        if self.snap_scratch.len() < bound {
            self.snap_scratch.resize(bound, 0);
        }
        self.snap_encoder.compress(ssz, &mut self.snap_scratch)
    }

    /// Replace the routable domains: `current` plus at most one
    /// neighbour (next during advance subscription, previous while it
    /// drains).
    pub fn set_domains(&mut self, current: GossipDomain, other: Option<GossipDomain>) {
        self.domains.set(current, other);
    }

    pub fn loop_start(&mut self) {
        self.incoming_gossip_publish.loop_start();
        self.mcache_publish.loop_start();
    }

    pub fn handle_peer_control(&mut self, peer_control: PeerControl) {
        let mut events = std::mem::take(&mut self.events);
        self.handle_peer_control_inner(peer_control, &mut |e| events.push_back(e));
        self.events = events;
    }

    pub fn current_domain(&self) -> Option<GossipDomain> {
        self.domains.current_domain()
    }

    pub fn mcache_insert(
        &mut self,
        id: MessageId,
        topic: GossipTopic,
        domain: GossipDomain,
        protobuf: TCacheRead,
    ) {
        self.mcache.insert(id, topic, domain, protobuf, &mut self.reader);
    }

    pub fn pop_event(&mut self) -> Option<GossipHandlerEvent> {
        self.events.pop_front()
    }

    pub fn set_partial_columns_mode(&mut self, mode: PartialColumnsMode) {
        self.partial_columns = mode;
    }

    fn handle_peer_control_inner(
        &mut self,
        peer_control: PeerControl,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) {
        match peer_control {
            PeerControl::P2pGossipSubscribe { p2p: _, p2p_connection, topic, digest } => {
                let wire = topic.to_wire(&hex::encode(digest));
                let mode = if matches!(topic, GossipTopic::DataColumnSidecar(_)) {
                    self.partial_columns
                } else {
                    PartialColumnsMode::Off
                };
                if let Ok(tcache) =
                    control::copy_subscriptions(&mut self.mcache_publish, &[&wire], mode)
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip subscribe");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipUnsubscribe { p2p: _, p2p_connection, topic, digest } => {
                let wire = topic.to_wire(&hex::encode(digest));
                if let Ok(tcache) =
                    control::copy_unsubscribes_to_protobuf_output(&mut self.mcache_publish, &[
                        &wire,
                    ])
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip unsubscribe");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipGraft { p2p: _, p2p_connection, topic, digest } => {
                let wire = topic.to_wire(&hex::encode(digest));
                if let Ok(tcache) =
                    control::copy_grafts_to_protobuf_output(&mut self.mcache_publish, &[&wire])
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip graft");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipPrune {
                p2p: _,
                p2p_connection,
                topic,
                digest,
                backoff_seconds,
            } => {
                let wire = topic.to_wire(&hex::encode(digest));
                if let Ok(tcache) = control::copy_prunes_to_protobuf_output(
                    &mut self.mcache_publish,
                    &[&wire],
                    backoff_seconds,
                ) {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip prune");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            _ => {} // no_ops for this tile
        }
    }

    pub fn spin(
        &mut self,
        adapter: &mut SpineAdapter<SilverSpine>,
        data_columns: Option<&mut TProducer>,
    ) -> bool {
        self.spin_columns(adapter, data_columns)
    }

    pub fn spin_columns<I: ColumnIngress>(
        &mut self,
        adapter: &mut SpineAdapter<SilverSpine>,
        data_columns: Option<&mut I>,
    ) -> bool {
        let mut events = std::mem::take(&mut self.events);
        let did_work = self.spin_inner(adapter, data_columns, &mut |e| events.push_back(e));
        self.events = events;
        did_work
    }

    fn spin_inner<I: ColumnIngress>(
        &mut self,
        adapter: &mut SpineAdapter<SilverSpine>,
        mut data_columns: Option<&mut I>,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) -> bool {
        let mut did_work = false;
        let now = Instant::now();
        self.dedup_cache.maybe_rotate(now);
        self.mcache.maybe_rotate(now);
        self.generate_ihave_messages(now, emit);
        self.reader.free_undrained();

        adapter.consume(|msg: GossipMsgIn, producers| {
            did_work = true;

            let acquired = self.reader.acquire(msg.tcache);
            let Ok((mut buffer, recv_ts)) = acquired.buffer() else {
                return;
            };

            // Incoming gossip messages are prefixed with P2pStreamId
            let stream_id: &P2pStreamId = buffer.into();
            tracing::trace!(?stream_id, len = buffer.len(), "gossip protobuf recv");

            buffer = &buffer[size_of::<P2pStreamId>()..];

            let gossip_proto = match RPCView::decode_view(buffer) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(?stream_id, len = buffer.len(), ?e, "RPC decode failed");
                    None
                }
            };
            if let Some(gossip_proto) = gossip_proto {
                let announced = || {
                    gossip_proto
                        .control
                        .as_option()
                        .and_then(|control| control.extensions.as_option())
                        .and_then(|extensions| extensions.partial_messages)
                        .unwrap_or(false)
                };
                if let Some(partial_messages) = self.extensions.first_rpc(stream_id, announced) {
                    emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipExtensions {
                        p2p_peer: stream_id.peer(),
                        partial_messages,
                    }));
                }
                handle_subscriptions(stream_id, gossip_proto.subscriptions, &self.domains, emit);

                if self.partial_columns.supports_sending() &&
                    let Some(partial) = gossip_proto.partial.as_option() &&
                    let Some(metadata) =
                        PartialMetadataReceived::decode(partial, *stream_id, &self.domains)
                {
                    emit(GossipHandlerEvent::PartialMetadata(metadata));
                }

                if self.partial_columns.requests() &&
                    stream_id.protocol() == StreamProtocol::GossipSubV13 &&
                    let Some(partial) = gossip_proto.partial.as_option() &&
                    let Some(message) =
                        PartialInbound::decode(partial, *stream_id, recv_ts, &self.domains) &&
                    let Some(ingress) = data_columns.as_deref_mut()
                {
                    ingress.receive_partial(message, producers);
                }

                if let Some(control) = gossip_proto.control.as_option() {
                    handle_grafts(stream_id, &control.graft, &self.domains, emit);
                    handle_prunes(stream_id, &control.prune, &self.domains, emit);
                    handle_iwants(stream_id, &control.iwant, &mut self.mcache, emit);
                    handle_idontwants(stream_id, &control.idontwant, emit);
                    handle_ihaves(
                        stream_id,
                        &control.ihave,
                        &self.domains,
                        &self.mcache,
                        &self.dedup_cache,
                        &mut self.mcache_publish,
                        emit,
                        &mut self.iwant_buffer,
                    );
                }

                for gossip_msg in &gossip_proto.publish {
                    if gossip_msg.key.is_some() ||
                        gossip_msg.signature.is_some() ||
                        gossip_msg.seqno.is_some() ||
                        gossip_msg.from.is_some()
                    {
                        // Spec violation
                        emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidFrame {
                            p2p_peer: stream_id.peer(),
                        }));
                        continue;
                    }
                    if let Some(snappy_data) = gossip_msg.data {
                        if let Err(e) = handle_incoming(
                            gossip_msg.topic,
                            snappy_data,
                            stream_id,
                            &self.domains,
                            recv_ts,
                            &mut self.dedup_cache,
                            &mut self.incoming_gossip_publish,
                            data_columns.as_deref_mut().map(ColumnIngress::producer_mut),
                            &mut self.mcache_publish,
                            emit,
                        ) {
                            tracing::error!(
                                ?e,
                                ?stream_id,
                                topic = gossip_msg.topic,
                                "error handling incoming gossip message"
                            );
                        }
                    }
                }
            }
        });

        // Free read data.
        self.reader.free();

        did_work
    }
}

/// The routable fork domains: `current` plus at most one neighbour —
/// the next domain during advance subscription, or the previous one
/// while it drains. `current` is `None` until the first status.
#[derive(Default)]
pub struct ActiveDomains {
    current: Option<DomainState>,
    other: Option<DomainState>,
}

struct DomainState {
    domain: GossipDomain,
    hex: String,
}

impl DomainState {
    fn new(domain: GossipDomain) -> Self {
        Self { domain, hex: hex::encode(domain.digest()) }
    }
}

impl ActiveDomains {
    pub(crate) fn new(current: Option<GossipDomain>) -> Self {
        Self { current: current.map(DomainState::new), other: None }
    }

    fn set(&mut self, current: GossipDomain, other: Option<GossipDomain>) {
        if self.current.as_ref().map(|s| s.domain) != Some(current) {
            self.current = Some(DomainState::new(current));
        }
        if self.other.as_ref().map(|s| s.domain) != other {
            self.other = other.map(DomainState::new);
        }
    }

    fn states(&self) -> impl Iterator<Item = &DomainState> {
        self.current.iter().chain(self.other.iter())
    }

    /// Resolve a wire topic against the routable domains; unknown
    /// digests are ignored, never penalized.
    pub(crate) fn parse(&self, wire: &str) -> Result<(GossipTopic, GossipDomain), Error> {
        for state in self.states() {
            if let Ok(topic) = GossipTopic::from_wire(wire, &state.hex) {
                return Ok((topic, state.domain));
            }
        }
        Err(Error::ParseTopicError)
    }

    /// Local sends always use the current domain.
    fn current_wire(&self, topic: GossipTopic) -> Option<(GossipDomain, String)> {
        self.current.as_ref().map(|s| (s.domain, topic.to_wire(&s.hex)))
    }

    fn current_domain(&self) -> Option<GossipDomain> {
        self.current.as_ref().map(|s| s.domain)
    }

    fn index_hex(&self, domain: GossipDomain) -> Option<(usize, &str)> {
        if let Some(s) = &self.current &&
            s.domain == domain
        {
            return Some((0, &s.hex));
        }
        if let Some(s) = &self.other &&
            s.domain == domain
        {
            return Some((1, &s.hex));
        }
        None
    }
}

/// Latest inbound gossip stream per peer. Gossipsub 1.3 extensions count
/// only in the first RPC of a meshsub 1.3 stream; any replacement stream
/// resets the peer's capability, so a 1.2 or announcement-less stream
/// turns it off. Keys are connection-slab indices, so the map is bounded
/// by the connection limit and slots are reused.
#[derive(Default)]
struct ExtensionTracker {
    streams: fxhash::FxHashMap<usize, P2pStreamId>,
}

impl ExtensionTracker {
    /// `Some(capability)` when this frame is the first on its stream;
    /// `None` when the announcement state is unchanged.
    fn first_rpc(
        &mut self,
        stream_id: &P2pStreamId,
        announced: impl FnOnce() -> bool,
    ) -> Option<bool> {
        match self.streams.get(&stream_id.peer()) {
            Some(seen) if seen == stream_id => None,
            _ => {
                self.streams.insert(stream_id.peer(), *stream_id);
                Some(stream_id.protocol() == StreamProtocol::GossipSubV13 && announced())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        ForkName, TCache, TCacheId, TCacheProducer, TCacheTable, ssz_view::SINGLE_ATT_SIZE,
    };

    use super::*;

    fn v13_stream(peer: usize, stream: u64) -> P2pStreamId {
        P2pStreamId::new(peer, stream, StreamProtocol::GossipSubV13, true)
    }

    #[test]
    fn delayed_publications_keep_their_fork_and_digest_domain() {
        let old = GossipDomain::new([1; 4], ForkName::Fulu);
        let incoming = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
        let protobuf = TCache::producer(TCacheId::ControlGossip, 1 << 16);
        let mut output =
            Box::new(TCacheReader::single(protobuf.cache_ref(), "", TReadMode::Sliding).unwrap());
        let mut handler = GossipHandler::new(
            TCacheTable::from_iter([incoming.cache_ref(), protobuf.cache_ref()]),
            TCache::producer(TCacheId::ControlProcessing, 1 << 16),
            protobuf,
            Some(old),
        )
        .unwrap();
        handler.open_tcaches().unwrap();
        let topic = GossipTopic::DataColumnSidecar(3);
        for (index, current) in
            [GossipDomain::new([2; 4], ForkName::Fulu), GossipDomain::new([3; 4], ForkName::Gloas)]
                .into_iter()
                .enumerate()
        {
            handler.set_domains(current, None);
            let bytes = [index as u8; 20];
            let built = handler.publish_in_domain(topic, old, &bytes).unwrap();
            let read = output.acquire(built.protobuf);
            let rpc = RPCView::decode_view(read.buffer().unwrap().0).unwrap();
            let published = rpc.publish.iter().next().unwrap();
            assert_eq!(published.topic, topic.to_wire("01010101"));
            assert_eq!(built.msg_id, msg_id_valid_snappy(&topic.to_wire("01010101"), &bytes));
        }
    }

    /// Extensions are stream-scoped: only the first RPC counts, a
    /// replacement stream resets the capability, and a 1.2 stream can
    /// never set it.
    #[test]
    fn extension_tracker_scopes_announcements_to_streams() {
        let mut tracker = ExtensionTracker::default();
        let first = v13_stream(1, 4);

        assert_eq!(tracker.first_rpc(&first, || true), Some(true));
        // Repeated or late announcements on the same stream are ignored.
        assert_eq!(tracker.first_rpc(&first, || false), None);
        assert_eq!(tracker.first_rpc(&first, || true), None);

        // Replacement stream without an announcement resets to off.
        let reopened = v13_stream(1, 8);
        assert_eq!(tracker.first_rpc(&reopened, || false), Some(false));
        assert_eq!(tracker.first_rpc(&reopened, || true), None);

        // A renegotiated 1.2 stream cannot announce extensions.
        let downgraded = P2pStreamId::new(1, 12, StreamProtocol::GossipSub, true);
        assert_eq!(tracker.first_rpc(&downgraded, || true), Some(false));

        // Peers are tracked independently.
        assert_eq!(tracker.first_rpc(&v13_stream(2, 4), || true), Some(true));
    }

    #[test]
    fn local_injection_uses_inbound_tcaches_without_precaching() {
        let incoming = TCache::producer(TCacheId::NetworkIngress, 1 << 12);

        let ssz_producer = TCache::producer(TCacheId::ControlProcessing, 1 << 12);
        let mut ssz_consumer = TCacheReader::single(
            ssz_producer.cache_ref(),
            "inject_local_ssz_test",
            TReadMode::Sliding,
        )
        .expect("ssz consumer");
        let protobuf_producer = TCache::producer(TCacheId::ControlGossip, 1 << 12);
        let mut protobuf_consumer = TCacheReader::single(
            protobuf_producer.cache_ref(),
            "inject_local_protobuf_test",
            TReadMode::Sliding,
        )
        .expect("protobuf consumer");

        let mut handler = GossipHandler::new(
            TCacheTable::from_iter([incoming.cache_ref(), protobuf_producer.cache_ref()]),
            ssz_producer,
            protobuf_producer,
            Some(GossipDomain::new([1, 2, 3, 4], silver_common::ForkName::Fulu)),
        )
        .expect("gossip handler");
        handler.open_tcaches().unwrap();
        let topic = GossipTopic::BeaconAttestation(7);
        let ssz = [42; SINGLE_ATT_SIZE];

        let msg_id = handler
            .inject_local(topic, &ssz, None, Nanos::now())
            .expect("local injection")
            .expect("new message");
        let message = match handler.pop_event().expect("new gossip event") {
            GossipHandlerEvent::NewGossip(message) => message,
            GossipHandlerEvent::PartialMetadata(_) |
            GossipHandlerEvent::PeerEvent(_) |
            GossipHandlerEvent::SendGossip(_) => {
                panic!("unexpected local injection event")
            }
        };

        assert_eq!(message.stream_id, LOCAL_GOSSIP_STREAM_ID);
        assert_eq!(message.topic, topic);
        assert_eq!(message.msg_hash, msg_id);
        assert_eq!(ssz_consumer.acquire(message.ssz).buffer().unwrap().0, ssz);
        assert!(!protobuf_consumer.acquire(message.protobuf).buffer().unwrap().0.is_empty());
        assert!(handler.dedup_cache.has(&msg_id));
        assert!(!handler.mcache.has(&msg_id));

        assert_eq!(handler.inject_local(topic, &ssz, None, Nanos::now()).unwrap(), Some(msg_id));
        let duplicate = match handler.pop_event().expect("duplicate local gossip event") {
            GossipHandlerEvent::NewGossip(message) => message,
            GossipHandlerEvent::PartialMetadata(_) |
            GossipHandlerEvent::PeerEvent(_) |
            GossipHandlerEvent::SendGossip(_) => {
                panic!("unexpected duplicate local injection event")
            }
        };
        assert_eq!(duplicate.msg_hash, msg_id);

        handler.mcache_insert(msg_id, topic, message.domain, message.protobuf);
        assert!(handler.mcache.has(&msg_id));
    }
}
