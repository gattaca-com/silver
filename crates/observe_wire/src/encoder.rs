use crate::{
    header::{HEADER_LEN, Header, Kind, MAX_DATAGRAM},
    records::{Source, TileUtil, TimingStats},
};

const PAYLOAD_MAX: usize = MAX_DATAGRAM - HEADER_LEN;
/// Prefix before an 8-aligned u64 array or fixed-size entry list.
const ALIGNED_PREFIX: usize = 8;
const VALUES_PER_DATAGRAM: usize = (PAYLOAD_MAX - ALIGNED_PREFIX) / 8;
const FIXED_ENTRY_LEN: usize = 40;
const FIXED_ENTRIES_PER_DATAGRAM: usize = (PAYLOAD_MAX - ALIGNED_PREFIX) / FIXED_ENTRY_LEN;
const NAME_MAX: usize = u8::MAX as usize;

/// Splits each call's records across as many datagrams as needed, handing
/// each to `emit` as it fills. Nothing is buffered across calls.
pub struct Encoder {
    instance_id: u64,
    boot_id: u64,
    seq: u64,
    buf: [u8; MAX_DATAGRAM],
    len: usize,
}

impl Encoder {
    pub fn new(instance_id: u64, boot_id: u64) -> Self {
        Self { instance_id, boot_id, seq: 0, buf: [0; MAX_DATAGRAM], len: 0 }
    }

    /// Names past 255 bytes are truncated.
    pub fn sources(&mut self, ts_ns: u64, sources: &[Source<'_>], emit: &mut impl FnMut(&[u8])) {
        let mut rest = sources;
        while !rest.is_empty() {
            self.begin(Kind::Sources, ts_ns);
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
            self.flush(emit);
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
            self.begin(Kind::SlotNames, ts_ns);
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
            self.flush(emit);
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
            self.begin(Kind::CounterValues, ts_ns);
            self.put(&source_id.to_le_bytes());
            self.put(&(chunk.len() as u16).to_le_bytes());
            self.put(&((i * VALUES_PER_DATAGRAM) as u32).to_le_bytes());
            for v in chunk {
                self.put(&v.to_le_bytes());
            }
            self.flush(emit);
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
            self.begin(kind, ts_ns);
            self.put(&(chunk.len() as u16).to_le_bytes());
            self.put(&[0; 6]);
            for e in chunk {
                let start = self.len;
                put_entry(self, e);
                debug_assert_eq!(self.len - start, FIXED_ENTRY_LEN);
            }
            self.flush(emit);
        }
    }

    fn text(&mut self, kind: Kind, ts_ns: u64, text: &str, emit: &mut impl FnMut(&[u8])) {
        self.begin(kind, ts_ns);
        self.put(truncate_utf8(text, PAYLOAD_MAX).as_bytes());
        self.flush(emit);
    }

    fn begin(&mut self, kind: Kind, ts_ns: u64) {
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

    fn flush(&mut self, emit: &mut impl FnMut(&[u8])) {
        emit(&self.buf[..self.len]);
        self.seq += 1;
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
    use crate::records::{SourceClass, TimingChannel};

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
}
