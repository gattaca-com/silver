use std::net::SocketAddr;

use crate::{
    header::{HEADER_LEN, Header, Kind, MAX_DATAGRAM},
    records::{
        PEER_ID_MAX, PeerP2p, PeerScores, PeerTopic, Source, StageRecord, TileUtil, TimingStats,
        USER_AGENT_MAX,
    },
};

const PAYLOAD_MAX: usize = MAX_DATAGRAM - HEADER_LEN;
/// Prefix before an 8-aligned u64 array or fixed-size entry list.
const ALIGNED_PREFIX: usize = 8;
const VALUES_PER_DATAGRAM: usize = (PAYLOAD_MAX - ALIGNED_PREFIX) / 8;
const FIXED_ENTRY_LEN: usize = 40;
const FIXED_ENTRIES_PER_DATAGRAM: usize = (PAYLOAD_MAX - ALIGNED_PREFIX) / FIXED_ENTRY_LEN;
const NAME_MAX: usize = u8::MAX as usize;
const PEER_LEN: usize = 48;
const PEER_P2P_LEN: usize = PEER_LEN + 8 + 24 + 8 * 8;
const PEER_SCORES_LEN: usize = PEER_LEN + 8 + USER_AGENT_MAX + 8 + 9 * 8;
const PEER_TOPIC_LEN: usize = PEER_LEN + 8 + 3 * 8 + 4 * 8;
const STAGE_LEN: usize = 32 + 3 * 8 + 8;

/// Splits each call's records across as many datagrams as needed, handing
/// each to `emit` as it fills. Streamed kinds (peers, stages) stay in an open
/// datagram across calls until it fills, another kind is encoded, or `flush`.
pub struct Encoder {
    instance_id: u64,
    boot_id: u64,
    seq: u64,
    buf: [u8; MAX_DATAGRAM],
    len: usize,
    open: Option<Kind>,
    open_count: u16,
}

impl Encoder {
    pub fn new(instance_id: u64, boot_id: u64) -> Self {
        Self {
            instance_id,
            boot_id,
            seq: 0,
            buf: [0; MAX_DATAGRAM],
            len: 0,
            open: None,
            open_count: 0,
        }
    }

    /// Emits the open streamed datagram, if any.
    pub fn flush(&mut self, emit: &mut impl FnMut(&[u8])) {
        if self.open.take().is_some() {
            self.patch_u16(HEADER_LEN, self.open_count);
            self.send(emit);
        }
    }

    pub fn chain(
        &mut self,
        ts_ns: u64,
        genesis_unix_secs: u64,
        slot_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) {
        self.begin(Kind::Chain, ts_ns, emit);
        self.put_u64s(&[genesis_unix_secs, slot_ms]);
        self.send(emit);
    }

    pub fn peer_p2p(&mut self, ts_ns: u64, p: &PeerP2p<'_>, emit: &mut impl FnMut(&[u8])) {
        self.stream(Kind::PeerP2p, ts_ns, PEER_P2P_LEN, emit, |enc| {
            enc.put_peer(p.peer);
            enc.put_u64s(&[p.connection]);
            let (family, ip) = match p.addr {
                SocketAddr::V4(a) => {
                    let mut ip = [0u8; 16];
                    ip[..4].copy_from_slice(&a.ip().octets());
                    (4, ip)
                }
                SocketAddr::V6(a) => (6, a.ip().octets()),
            };
            enc.put(&[family, p.inbound as u8]);
            enc.put(&p.addr.port().to_le_bytes());
            enc.put(&[0; 4]);
            enc.put(&ip);
            enc.put_u64s(&[
                p.connected_ms,
                p.rtt_us,
                p.lost_packets,
                p.rx_blocking,
                p.tx_blocking,
                p.rx_datagrams,
                p.tx_datagrams,
                p.streams,
            ]);
        });
    }

    pub fn peer_scores(&mut self, ts_ns: u64, s: &PeerScores<'_>, emit: &mut impl FnMut(&[u8])) {
        self.stream(Kind::PeerScores, ts_ns, PEER_SCORES_LEN, emit, |enc| {
            enc.put_peer(s.peer);
            let agent = truncate_utf8(s.user_agent, USER_AGENT_MAX).as_bytes();
            let mut field = [0u8; 8 + USER_AGENT_MAX];
            field[0] = agent.len() as u8;
            field[8..8 + agent.len()].copy_from_slice(agent);
            enc.put(&field);
            enc.put(&s.mesh_count.to_le_bytes());
            enc.put(&[0; 4]);
            enc.put_f64s(&[
                s.p1_time_in_mesh,
                s.p2_first_deliveries,
                s.p3_mesh_deficit,
                s.p3b_mesh_failure,
                s.p4_invalid,
                s.p5_application,
                s.p6_ip_colocation,
                s.p7_behaviour,
                s.total,
            ]);
        });
    }

    pub fn peer_topic(&mut self, ts_ns: u64, t: &PeerTopic<'_>, emit: &mut impl FnMut(&[u8])) {
        self.stream(Kind::PeerTopic, ts_ns, PEER_TOPIC_LEN, emit, |enc| {
            enc.put_peer(t.peer);
            enc.put(&t.topic_slot.to_le_bytes());
            enc.put(&[t.p3_scored as u8, t.mesh_active as u8, 0, 0, 0, 0]);
            enc.put_u64s(&[t.meshed_secs, t.fanout_total, t.fanout_sent]);
            enc.put_f64s(&[
                t.first_deliveries,
                t.mesh_deliveries,
                t.mesh_failure_penalty,
                t.invalid_deliveries,
            ]);
        });
    }

    pub fn stage(&mut self, ts_ns: u64, r: &StageRecord, emit: &mut impl FnMut(&[u8])) {
        self.stream(Kind::Stages, ts_ns, STAGE_LEN, emit, |enc| {
            enc.put(&r.block_root);
            enc.put_u64s(&[
                r.ts_ns,
                r.slot.unwrap_or(u64::MAX),
                r.column_index.unwrap_or(u64::MAX),
            ]);
            enc.put(&[r.stage as u8, r.detail, 0, 0, 0, 0, 0, 0]);
        });
    }

    fn stream(
        &mut self,
        kind: Kind,
        ts_ns: u64,
        entry_len: usize,
        emit: &mut impl FnMut(&[u8]),
        put_entry: impl FnOnce(&mut Self),
    ) {
        if self.open != Some(kind) || self.room() < entry_len {
            self.begin(kind, ts_ns, emit);
            self.put(&[0; ALIGNED_PREFIX]);
            self.open = Some(kind);
            self.open_count = 0;
        }
        let start = self.len;
        put_entry(self);
        debug_assert_eq!(self.len - start, entry_len);
        self.open_count += 1;
    }

    /// Names past 255 bytes are truncated.
    pub fn sources(&mut self, ts_ns: u64, sources: &[Source<'_>], emit: &mut impl FnMut(&[u8])) {
        let mut rest = sources;
        while !rest.is_empty() {
            self.begin(Kind::Sources, ts_ns, emit);
            let count_at = self.len;
            self.put(&0u16.to_le_bytes());
            let mut n = 0;
            while let Some(s) = rest.first() {
                let name = truncate_utf8(s.name, NAME_MAX);
                if self.room() < 4 + name.len() {
                    break;
                }
                self.put(&s.id.to_le_bytes());
                self.put(&[s.class as u8, name.len() as u8]);
                self.put(name.as_bytes());
                n += 1;
                rest = &rest[1..];
            }
            self.patch_u16(count_at, n);
            self.send(emit);
        }
    }

    /// Names past 255 bytes are truncated.
    pub fn slot_names<S: AsRef<str>>(
        &mut self,
        ts_ns: u64,
        source_id: u16,
        names: &[S],
        emit: &mut impl FnMut(&[u8]),
    ) {
        let mut first_slot = 0;
        while first_slot < names.len() {
            self.begin(Kind::SlotNames, ts_ns, emit);
            self.put(&source_id.to_le_bytes());
            let count_at = self.len;
            self.put(&0u16.to_le_bytes());
            self.put(&(first_slot as u32).to_le_bytes());
            let mut n = 0;
            for name in &names[first_slot..] {
                let name = truncate_utf8(name.as_ref(), NAME_MAX);
                if self.room() < 1 + name.len() {
                    break;
                }
                self.put(&[name.len() as u8]);
                self.put(name.as_bytes());
                n += 1;
            }
            self.patch_u16(count_at, n);
            first_slot += n as usize;
            self.send(emit);
        }
    }

    /// Truncated to one datagram.
    pub fn build_info(&mut self, ts_ns: u64, text: &str, emit: &mut impl FnMut(&[u8])) {
        self.text(Kind::BuildInfo, ts_ns, text, emit);
    }

    /// Truncated to one datagram.
    pub fn instance(&mut self, ts_ns: u64, label: &str, emit: &mut impl FnMut(&[u8])) {
        self.text(Kind::Instance, ts_ns, label, emit);
    }

    pub fn counter_values(
        &mut self,
        ts_ns: u64,
        source_id: u16,
        values: &[u64],
        emit: &mut impl FnMut(&[u8]),
    ) {
        for (i, chunk) in values.chunks(VALUES_PER_DATAGRAM).enumerate() {
            self.begin(Kind::CounterValues, ts_ns, emit);
            self.put(&source_id.to_le_bytes());
            self.put(&(chunk.len() as u16).to_le_bytes());
            self.put(&((i * VALUES_PER_DATAGRAM) as u32).to_le_bytes());
            for v in chunk {
                self.put(&v.to_le_bytes());
            }
            self.send(emit);
        }
    }

    pub fn tile_utils(&mut self, ts_ns: u64, utils: &[TileUtil], emit: &mut impl FnMut(&[u8])) {
        self.fixed_entries(Kind::TileUtils, ts_ns, utils, emit, |enc, u| {
            enc.put(&u.source_id.to_le_bytes());
            enc.put(&[0; 6]);
            for v in [u.busy, u.total, u.busy_count, u.busy_max] {
                enc.put(&v.to_le_bytes());
            }
        });
    }

    pub fn timings(&mut self, ts_ns: u64, timings: &[TimingStats], emit: &mut impl FnMut(&[u8])) {
        self.fixed_entries(Kind::Timings, ts_ns, timings, emit, |enc, t| {
            enc.put(&t.source_id.to_le_bytes());
            enc.put(&[t.channel as u8, 0, 0, 0, 0, 0]);
            for v in [t.count, t.p50_ns, t.p99_ns, t.max_ns] {
                enc.put(&v.to_le_bytes());
            }
        });
    }

    fn fixed_entries<T>(
        &mut self,
        kind: Kind,
        ts_ns: u64,
        entries: &[T],
        emit: &mut impl FnMut(&[u8]),
        mut put_entry: impl FnMut(&mut Self, &T),
    ) {
        for chunk in entries.chunks(FIXED_ENTRIES_PER_DATAGRAM) {
            self.begin(kind, ts_ns, emit);
            self.put(&(chunk.len() as u16).to_le_bytes());
            self.put(&[0; 6]);
            for e in chunk {
                let start = self.len;
                put_entry(self, e);
                debug_assert_eq!(self.len - start, FIXED_ENTRY_LEN);
            }
            self.send(emit);
        }
    }

    fn text(&mut self, kind: Kind, ts_ns: u64, text: &str, emit: &mut impl FnMut(&[u8])) {
        self.begin(kind, ts_ns, emit);
        self.put(truncate_utf8(text, PAYLOAD_MAX).as_bytes());
        self.send(emit);
    }

    fn begin(&mut self, kind: Kind, ts_ns: u64, emit: &mut impl FnMut(&[u8])) {
        self.flush(emit);
        let header = Header {
            kind,
            instance_id: self.instance_id,
            boot_id: self.boot_id,
            seq: self.seq,
            ts_ns,
        };
        header.write((&mut self.buf[..HEADER_LEN]).try_into().unwrap());
        self.len = HEADER_LEN;
    }

    fn room(&self) -> usize {
        MAX_DATAGRAM - self.len
    }

    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn patch_u16(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn send(&mut self, emit: &mut impl FnMut(&[u8])) {
        emit(&self.buf[..self.len]);
        self.seq += 1;
    }

    fn put_u64s(&mut self, values: &[u64]) {
        for v in values {
            self.put(&v.to_le_bytes());
        }
    }

    fn put_f64s(&mut self, values: &[f64]) {
        for v in values {
            self.put(&v.to_le_bytes());
        }
    }

    fn put_peer(&mut self, peer: &[u8]) {
        let id = &peer[..peer.len().min(PEER_ID_MAX)];
        let mut field = [0u8; PEER_LEN];
        field[0] = id.len() as u8;
        field[1..1 + id.len()].copy_from_slice(id);
        self.put(&field);
    }
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{SourceClass, StageCode, TimingChannel};

    /// Independent reading of the layout table in `lib.rs`, standing in for
    /// the dashboard's JS decoder.
    struct Reader<'a> {
        buf: &'a [u8],
        at: usize,
    }

    impl<'a> Reader<'a> {
        fn payload(dgram: &'a [u8]) -> Self {
            Self { buf: dgram, at: HEADER_LEN }
        }

        fn bytes(&mut self, n: usize) -> &'a [u8] {
            let b = &self.buf[self.at..self.at + n];
            self.at += n;
            b
        }

        fn u8(&mut self) -> u8 {
            self.bytes(1)[0]
        }

        fn u16(&mut self) -> u16 {
            u16::from_le_bytes(self.bytes(2).try_into().unwrap())
        }

        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.bytes(4).try_into().unwrap())
        }

        fn u64(&mut self) -> u64 {
            assert_eq!(self.at % 8, 0, "u64 at an unaligned offset");
            u64::from_le_bytes(self.bytes(8).try_into().unwrap())
        }

        fn name(&mut self) -> &'a str {
            let len = self.u8() as usize;
            std::str::from_utf8(self.bytes(len)).unwrap()
        }

        fn done(&self) {
            assert_eq!(self.at, self.buf.len(), "trailing bytes");
        }
    }

    fn source_class(v: u8) -> SourceClass {
        match v {
            0 => SourceClass::Counters,
            1 => SourceClass::TCache,
            2 => SourceClass::Timing,
            3 => SourceClass::Tile,
            _ => panic!("bad class {v}"),
        }
    }

    fn timing_channel(v: u8) -> TimingChannel {
        match v {
            0 => TimingChannel::Latency,
            1 => TimingChannel::Processing,
            _ => panic!("bad channel {v}"),
        }
    }

    fn collect(f: impl FnOnce(&mut Encoder, &mut dyn FnMut(&[u8]))) -> Vec<Vec<u8>> {
        let mut enc = Encoder::new(0xAA, 0xBB);
        let mut out = Vec::new();
        f(&mut enc, &mut |d: &[u8]| out.push(d.to_vec()));
        for d in &out {
            assert!(d.len() <= MAX_DATAGRAM, "datagram of {} bytes", d.len());
        }
        out
    }

    fn headers(dgrams: &[Vec<u8>], kind: Kind) -> Vec<Header> {
        dgrams
            .iter()
            .map(|d| {
                let h = Header::parse(d).expect("parses");
                assert_eq!(h.kind, kind);
                h
            })
            .collect()
    }

    #[test]
    fn header_round_trips_and_rejects_foreign_datagrams() {
        let dgrams = collect(|enc, emit| enc.build_info(77, "b", &mut |d| emit(d)));
        let h = Header::parse(&dgrams[0]).unwrap();
        assert_eq!(h, Header {
            kind: Kind::BuildInfo,
            instance_id: 0xAA,
            boot_id: 0xBB,
            seq: 0,
            ts_ns: 77
        });

        let mut bad = dgrams[0].clone();
        bad[0] ^= 1;
        assert_eq!(Header::parse(&bad), None, "magic");
        let mut bad = dgrams[0].clone();
        bad[4] = 99;
        assert_eq!(Header::parse(&bad), None, "version");
        let mut bad = dgrams[0].clone();
        bad[6] = 99;
        assert_eq!(Header::parse(&bad), None, "kind");
        assert_eq!(Header::parse(&dgrams[0][..HEADER_LEN - 1]), None, "short");
    }

    #[test]
    fn counter_values_split_by_slot_range_with_contiguous_seq() {
        let values: Vec<u64> = (0..400).map(|i| i * 1_000_003).collect();
        let dgrams = collect(|enc, emit| enc.counter_values(5, 9, &values, &mut |d| emit(d)));
        assert_eq!(dgrams.len(), 400usize.div_ceil(VALUES_PER_DATAGRAM));

        let mut got = Vec::new();
        for (i, (d, h)) in dgrams.iter().zip(headers(&dgrams, Kind::CounterValues)).enumerate() {
            assert_eq!(h.seq, i as u64);
            let mut r = Reader::payload(d);
            assert_eq!(r.u16(), 9);
            let count = r.u16() as usize;
            assert_eq!(r.u32() as usize, got.len(), "first_slot");
            got.extend((0..count).map(|_| r.u64()));
            r.done();
        }
        assert_eq!(got, values);
    }

    #[test]
    fn names_split_without_reassembly_and_truncate_on_char_boundary() {
        let long = "é".repeat(200);
        let sources: Vec<Source<'_>> = (0..80)
            .map(|i| Source {
                id: i,
                class: source_class((i % 4) as u8),
                name: if i == 3 { &long } else { "beacon_state_counters_x" },
            })
            .collect();
        let dgrams = collect(|enc, emit| enc.sources(1, &sources, &mut |d| emit(d)));
        assert!(dgrams.len() > 1);

        let mut got = Vec::new();
        for d in &dgrams {
            let mut r = Reader::payload(d);
            for _ in 0..r.u16() {
                let id = r.u16();
                let class = source_class(r.u8());
                got.push((id, class, r.name().to_string()));
            }
            r.done();
        }
        assert_eq!(got.len(), sources.len());
        for (s, (id, class, name)) in sources.iter().zip(&got) {
            assert_eq!((s.id, s.class), (*id, *class));
            let want = if s.id == 3 { "é".repeat(127) } else { s.name.to_string() };
            assert_eq!(*name, want);
        }

        let names: Vec<String> = (0..300).map(|i| format!("gossip_topic_{i}_recv")).collect();
        let dgrams = collect(|enc, emit| enc.slot_names(1, 4, &names, &mut |d| emit(d)));
        assert!(dgrams.len() > 1);
        let mut got = Vec::new();
        for d in &dgrams {
            let mut r = Reader::payload(d);
            assert_eq!(r.u16(), 4);
            let count = r.u16();
            assert_eq!(r.u32() as usize, got.len(), "first_slot");
            got.extend((0..count).map(|_| r.name().to_string()));
            r.done();
        }
        assert_eq!(got, names);
    }

    #[test]
    fn fixed_entries_round_trip_across_datagrams() {
        let utils: Vec<TileUtil> = (0..70)
            .map(|i| TileUtil {
                source_id: i,
                busy: i as u64,
                total: 1 << 40,
                busy_count: 3,
                busy_max: u64::MAX,
            })
            .collect();
        let dgrams = collect(|enc, emit| enc.tile_utils(1, &utils, &mut |d| emit(d)));
        assert_eq!(dgrams.len(), 70usize.div_ceil(FIXED_ENTRIES_PER_DATAGRAM));
        let mut got = Vec::new();
        for d in &dgrams {
            let mut r = Reader::payload(d);
            let count = r.u16();
            r.bytes(6);
            for _ in 0..count {
                let source_id = r.u16();
                r.bytes(6);
                got.push(TileUtil {
                    source_id,
                    busy: r.u64(),
                    total: r.u64(),
                    busy_count: r.u64(),
                    busy_max: r.u64(),
                });
            }
            r.done();
        }
        assert_eq!(got, utils);

        let timings: Vec<TimingStats> = (0..40)
            .map(|i| TimingStats {
                source_id: i / 2,
                channel: timing_channel((i % 2) as u8),
                count: 10,
                p50_ns: 100,
                p99_ns: 900,
                max_ns: 5_000,
            })
            .collect();
        let dgrams = collect(|enc, emit| enc.timings(1, &timings, &mut |d| emit(d)));
        let mut got = Vec::new();
        for d in &dgrams {
            let mut r = Reader::payload(d);
            let count = r.u16();
            r.bytes(6);
            for _ in 0..count {
                let source_id = r.u16();
                let channel = timing_channel(r.u8());
                r.bytes(5);
                got.push(TimingStats {
                    source_id,
                    channel,
                    count: r.u64(),
                    p50_ns: r.u64(),
                    p99_ns: r.u64(),
                    max_ns: r.u64(),
                });
            }
            r.done();
        }
        assert_eq!(got, timings);
    }

    #[test]
    fn text_fills_at_most_one_datagram() {
        let text = "ü".repeat(MAX_DATAGRAM);
        let dgrams = collect(|enc, emit| {
            enc.build_info(1, &text, &mut |d| emit(d));
            enc.instance(1, &text, &mut |d| emit(d));
        });
        assert_eq!(dgrams.len(), 2);
        for (d, kind) in dgrams.iter().zip([Kind::BuildInfo, Kind::Instance]) {
            assert_eq!(Header::parse(d).unwrap().kind, kind);
            let body = std::str::from_utf8(&d[HEADER_LEN..]).expect("cut on a char boundary");
            assert_eq!(body.len(), PAYLOAD_MAX / 2 * 2);
        }
    }

    #[test]
    fn empty_inputs_emit_nothing() {
        let dgrams = collect(|enc, emit| {
            enc.sources(1, &[], &mut |d| emit(d));
            enc.slot_names::<&str>(1, 0, &[], &mut |d| emit(d));
            enc.counter_values(1, 0, &[], &mut |d| emit(d));
            enc.tile_utils(1, &[], &mut |d| emit(d));
            enc.timings(1, &[], &mut |d| emit(d));
        });
        assert!(dgrams.is_empty());
    }

    fn f64(r: &mut Reader<'_>) -> f64 {
        f64::from_bits(r.u64())
    }

    fn peer<'a>(r: &mut Reader<'a>) -> &'a [u8] {
        let field = r.bytes(PEER_LEN);
        &field[1..1 + field[0] as usize]
    }

    fn stage_record(i: u64) -> StageRecord {
        StageRecord {
            block_root: [i as u8; 32],
            ts_ns: 1_000 + i,
            slot: if i.is_multiple_of(2) { Some(i) } else { None },
            column_index: if i.is_multiple_of(3) { Some(i * 7) } else { None },
            stage: StageCode::ColumnRecv,
            detail: 3,
        }
    }

    #[test]
    fn streamed_entries_batch_until_full_and_flush_on_kind_change() {
        let dgrams = collect(|enc, emit| {
            for i in 0..30 {
                enc.stage(1, &stage_record(i), &mut |d| emit(d));
            }
            enc.chain(1, 1_606_824_023, 12_000, &mut |d| emit(d));
            enc.stage(1, &stage_record(30), &mut |d| emit(d));
            enc.flush(&mut |d| emit(d));
            enc.flush(&mut |d| emit(d));
        });
        let kinds: Vec<_> = dgrams.iter().map(|d| Header::parse(d).unwrap().kind).collect();
        assert_eq!(kinds, [Kind::Stages, Kind::Stages, Kind::Chain, Kind::Stages]);
        let seqs: Vec<_> = dgrams.iter().map(|d| Header::parse(d).unwrap().seq).collect();
        assert_eq!(seqs, [0, 1, 2, 3], "seq follows emission order");

        let mut r = Reader::payload(&dgrams[2]);
        assert_eq!((r.u64(), r.u64()), (1_606_824_023, 12_000));
        r.done();

        let mut got = Vec::new();
        for d in [&dgrams[0], &dgrams[1], &dgrams[3]] {
            let mut r = Reader::payload(d);
            let n = r.u16();
            r.bytes(6);
            for _ in 0..n {
                let block_root = r.bytes(32).try_into().unwrap();
                let ts_ns = r.u64();
                let slot = Some(r.u64()).filter(|&v| v != u64::MAX);
                let column_index = Some(r.u64()).filter(|&v| v != u64::MAX);
                let (stage, detail) = (r.u8(), r.u8());
                assert_eq!(stage, StageCode::ColumnRecv as u8);
                r.bytes(6);
                got.push(StageRecord {
                    block_root,
                    ts_ns,
                    slot,
                    column_index,
                    stage: StageCode::ColumnRecv,
                    detail,
                });
            }
            r.done();
        }
        assert_eq!(got, (0..31).map(stage_record).collect::<Vec<_>>());
        assert_eq!(dgrams[0].len(), HEADER_LEN + ALIGNED_PREFIX + 21 * STAGE_LEN, "full");
    }

    #[test]
    fn peer_entries_round_trip() {
        let id: Vec<u8> = (0..60).collect();
        let v4 = PeerP2p {
            peer: &id,
            connection: 9,
            addr: "10.1.2.3:9000".parse().unwrap(),
            inbound: true,
            connected_ms: 1,
            rtt_us: 2,
            lost_packets: 3,
            rx_blocking: 4,
            tx_blocking: 5,
            rx_datagrams: 6,
            tx_datagrams: 7,
            streams: 8,
        };
        let v6 = PeerP2p { addr: "[2001:db8::1]:13000".parse().unwrap(), inbound: false, ..v4 };
        let agent = "Lighthouse/v7.0.0-".repeat(8);
        let scores = PeerScores {
            peer: &id[..38],
            user_agent: &agent,
            mesh_count: 5,
            p1_time_in_mesh: 0.5,
            p2_first_deliveries: 1.5,
            p3_mesh_deficit: -2.5,
            p3b_mesh_failure: -3.5,
            p4_invalid: -4.5,
            p5_application: 5.5,
            p6_ip_colocation: -6.5,
            p7_behaviour: -7.5,
            total: 8.5,
        };
        let topic = PeerTopic {
            peer: &id[..38],
            topic_slot: 17,
            p3_scored: true,
            mesh_active: false,
            meshed_secs: 60,
            fanout_total: 10,
            fanout_sent: 4,
            first_deliveries: 1.25,
            mesh_deliveries: 2.25,
            mesh_failure_penalty: 3.25,
            invalid_deliveries: 4.25,
        };
        let dgrams = collect(|enc, emit| {
            enc.peer_p2p(1, &v4, &mut |d| emit(d));
            enc.peer_p2p(1, &v6, &mut |d| emit(d));
            enc.peer_scores(1, &scores, &mut |d| emit(d));
            enc.peer_topic(1, &topic, &mut |d| emit(d));
            enc.flush(&mut |d| emit(d));
        });
        assert_eq!(dgrams.len(), 3);

        let mut r = Reader::payload(&dgrams[0]);
        assert_eq!(r.u16(), 2);
        r.bytes(6);
        for want in [v4, v6] {
            assert_eq!(peer(&mut r), &id[..PEER_ID_MAX], "truncated to PEER_ID_MAX");
            assert_eq!(r.u64(), want.connection);
            let (family, inbound, port) = (r.u8(), r.u8() == 1, r.u16());
            r.bytes(4);
            let ip = r.bytes(16);
            let addr: SocketAddr = match family {
                4 => (<[u8; 4]>::try_from(&ip[..4]).unwrap(), port).into(),
                6 => (<[u8; 16]>::try_from(ip).unwrap(), port).into(),
                _ => panic!("family {family}"),
            };
            assert_eq!((addr, inbound), (want.addr, want.inbound));
            let rest: Vec<_> = (0..8).map(|_| r.u64()).collect();
            assert_eq!(rest, [1, 2, 3, 4, 5, 6, 7, 8]);
        }
        r.done();

        let mut r = Reader::payload(&dgrams[1]);
        assert_eq!(r.u16(), 1);
        r.bytes(6);
        assert_eq!(peer(&mut r), scores.peer);
        let field = r.bytes(8 + USER_AGENT_MAX);
        let got_agent = std::str::from_utf8(&field[8..8 + field[0] as usize]).unwrap();
        assert_eq!(got_agent, &agent[..USER_AGENT_MAX]);
        assert_eq!(r.u32(), 5);
        r.bytes(4);
        let got: Vec<_> = (0..9).map(|_| f64(&mut r)).collect();
        assert_eq!(got, [0.5, 1.5, -2.5, -3.5, -4.5, 5.5, -6.5, -7.5, 8.5]);
        r.done();

        let mut r = Reader::payload(&dgrams[2]);
        assert_eq!(r.u16(), 1);
        r.bytes(6);
        assert_eq!(peer(&mut r), topic.peer);
        assert_eq!((r.u16(), r.u8(), r.u8()), (17, 1, 0));
        r.bytes(4);
        assert_eq!((r.u64(), r.u64(), r.u64()), (60, 10, 4));
        let got: Vec<_> = (0..4).map(|_| f64(&mut r)).collect();
        assert_eq!(got, [1.25, 2.25, 3.25, 4.25]);
        r.done();
    }
}
