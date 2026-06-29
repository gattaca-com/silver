//! Encode the retained `#[timed]` marks as a Fuchsia FXT trace — magic-trace's
//! native format, the one Perfetto reads with per-slice wall-clock time. The
//! init record's realtime anchor (wall-clock at tick 0) drives the UI's
//! "Absolute time"; its Chrome-JSON and protobuf-clock-snapshot paths only ever
//! surface a constant trace datum.
//!
//! Layout mirrors what magic-trace emits (validated against its output): a
//! string table, a process/thread kernel-object pair, a thread record, then
//! duration begin/end events. See the Fuchsia Trace Format spec for the
//! records.

use std::time::{SystemTime, UNIX_EPOCH};

use flux::timing::{Duration, Instant};
use rustc_hash::FxHashMap;

use crate::flamegraph_timer::{
    mark::{Frame, Mark},
    names::untimed,
};

/// `Instant`'s top 2 bits hold the socket id, low 62 the rdtscp counter.
const TSC_MASK: u64 = 0x3fff_ffff_ffff_ffff;
/// Perfetto sniffs these 8 bytes to pick its Fuchsia importer; `FxT` sits
/// between the record's fixed framing bytes.
const MAGIC_NUMBER_RECORD: &[u8] = b"\x10\x00\x04FxT\x16\x00";
const PROCESS_KOID: u64 = 1;
const OBJ_PROCESS: u64 = 1; // zx_obj_type PROCESS
const OBJ_THREAD: u64 = 2; // zx_obj_type THREAD
const DURATION_BEGIN: u64 = 2; // fuchsia event types: 1 is Counter, not begin
const DURATION_END: u64 = 3;
const ARG_KOID: u64 = 8;

pub(super) fn trace<'a>(
    threads: impl Iterator<Item = (&'a str, &'a [Mark])>,
    names: &FxHashMap<u64, String>,
) -> Vec<u8> {
    let threads: Vec<_> = threads.collect();
    debug_assert!(threads.len() < 256, "thread ref is 8-bit");
    let now_tsc = Instant::now().0 & TSC_MASK;
    let now_epoch_ns =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let base_tsc = threads
        .iter()
        .filter_map(|(_, marks)| marks.first().map(|m| m.ts & TSC_MASK))
        .min()
        .unwrap_or(now_tsc);
    // Wall-clock of tick 0 (the earliest mark): now minus how long ago it was.
    let anchor_ns =
        now_epoch_ns.saturating_sub(Duration(now_tsc.saturating_sub(base_tsc)).as_nanos() as u64);
    let ns = |tsc: u64| Duration((tsc & TSC_MASK).saturating_sub(base_tsc)).as_nanos() as u64;

    let mut fxt = Fxt::default();
    fxt.buf.extend_from_slice(MAGIC_NUMBER_RECORD);
    fxt.init(anchor_ns);
    let process = fxt.intern("silver");
    fxt.kernel_object(OBJ_PROCESS, PROCESS_KOID, process, None);

    for (i, (thread, marks)) in threads.iter().enumerate() {
        let koid = i as u64 + 2; // 1 is the process koid
        let index = i as u64 + 1; // 1-based thread-table index
        let name = fxt.intern(thread);
        let process_arg = fxt.intern("process");
        fxt.kernel_object(OBJ_THREAD, koid, name, Some((process_arg, PROCESS_KOID)));
        fxt.thread_record(index, PROCESS_KOID, koid);
        for mark in *marks {
            let (id, ty) = match mark.frame {
                Frame::Open { id, .. } => (id, DURATION_BEGIN),
                Frame::Close { id } => (id, DURATION_END),
            };
            let raw = names.get(&id).map_or("unknown", String::as_str);
            let name = fxt.intern(&untimed(raw));
            fxt.event(ty, index, name, ns(mark.ts));
        }
    }
    fxt.buf
}

#[derive(Default)]
struct Fxt {
    buf: Vec<u8>,
    strings: FxHashMap<String, u16>,
}

impl Fxt {
    fn word(&mut self, w: u64) {
        self.buf.extend_from_slice(&w.to_le_bytes());
    }

    /// String bytes padded up to an 8-byte word boundary.
    fn string_bytes(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
        self.buf.resize(self.buf.len() + (8 - s.len() % 8) % 8, 0);
    }

    /// Index of `s` in the string table, emitting its record on first use so it
    /// precedes any reference. Indices are 1-based (0 means the empty string).
    fn intern(&mut self, s: &str) -> u16 {
        if let Some(&i) = self.strings.get(s) {
            return i;
        }
        let index = self.strings.len() as u16 + 1;
        debug_assert!(index < 0x8000, "string ref is 15-bit");
        self.strings.insert(s.to_owned(), index);
        let size = 1 + words(s.len());
        // type 2, index [16:31), length [32:47).
        self.word(2 | (size << 4) | (u64::from(index) << 16) | ((s.len() as u64) << 32));
        self.string_bytes(s.as_bytes());
        index
    }

    /// Init record (4 words): ns timebase, base tick 0, realtime at base tick.
    fn init(&mut self, anchor_ns: u64) {
        self.word(1 | (4 << 4));
        self.word(1_000_000_000); // ticks_per_second → ns
        self.word(0); // base tick
        self.word(anchor_ns); // wall-clock at the base tick
    }

    fn kernel_object(&mut self, obj_type: u64, koid: u64, name: u16, process: Option<(u16, u64)>) {
        let size = 2 + 2 * process.is_some() as u64; // header, koid, optional koid arg
        // type 7, obj type [16:24), name ref [24:40), arg count [40:44).
        self.word(
            7 | (size << 4) |
                (obj_type << 16) |
                (u64::from(name) << 24) |
                ((process.is_some() as u64) << 40),
        );
        self.word(koid);
        if let Some((arg_name, koid_val)) = process {
            // koid argument: type 8, size 2, name ref [16:32), then the koid.
            self.word(ARG_KOID | (2 << 4) | (u64::from(arg_name) << 16));
            self.word(koid_val);
        }
    }

    fn thread_record(&mut self, index: u64, process_koid: u64, thread_koid: u64) {
        self.word(3 | (3 << 4) | (index << 16)); // type 3, thread index [16:24)
        self.word(process_koid);
        self.word(thread_koid);
    }

    fn event(&mut self, event_type: u64, thread_index: u64, name: u16, ts: u64) {
        // type 4, event type [16:20), thread ref [24:32), empty category, name
        // ref [48:64); header + timestamp, both refs indexed so no inline data.
        self.word(
            4 | (2 << 4) | (event_type << 16) | (thread_index << 24) | (u64::from(name) << 48),
        );
        self.word(ts);
    }
}

fn words(bytes: usize) -> u64 {
    bytes.div_ceil(8) as u64
}
