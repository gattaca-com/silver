//! Encode the retained `#[timed]` marks as a Fuchsia FXT trace — magic-trace's
//! native format, the one Perfetto reads with per-slice wall-clock time. The
//! init record's realtime anchor (wall-clock at tick 0) drives the UI's
//! "Absolute time".
//!
//! Layout mirrors what magic-trace emits (validated against its output): a
//! string table, a process/thread kernel-object pair, a thread record, then
//! duration begin/end events. See the Fuchsia Trace Format spec for the
//! records.

use std::time::{SystemTime, UNIX_EPOCH};

use flux::timing::{Duration, Instant};
use rustc_hash::FxHashMap;

use crate::{
    Schema,
    allocator::AllocSample,
    flamegraph_timer::{
        mark::{Frame, Mark},
        names::untimed,
    },
    perf::PerfSample,
};

/// `Instant`'s top 2 bits hold the socket id, low 62 the rdtscp counter.
const TSC_MASK: u64 = 0x3fff_ffff_ffff_ffff;
/// Perfetto sniffs these 8 bytes to pick its Fuchsia importer; `FxT` sits
/// between the record's fixed framing bytes.
const MAGIC_NUMBER_RECORD: &[u8] = b"\x10\x00\x04FxT\x16\x00";
const PROCESS_KOID: u64 = 1;
const OBJ_PROCESS: u64 = 1; // zx_obj_type PROCESS
const OBJ_THREAD: u64 = 2; // zx_obj_type THREAD
const COUNTER: u64 = 1; // fuchsia event type Counter — Perfetto draws it as a line graph
const DURATION_BEGIN: u64 = 2;
const DURATION_END: u64 = 3;
const ARG_UINT64: u64 = 4;
const ARG_KOID: u64 = 8;

pub(super) struct ThreadTrace<'a> {
    pub(super) name: &'a str,
    pub(super) marks: &'a [Mark],
    pub(super) alloc: &'a [AllocSample],
    pub(super) perf: &'a [PerfSample],
}

pub(super) fn trace<'a>(
    threads: impl Iterator<Item = ThreadTrace<'a>>,
    names: &FxHashMap<u64, String>,
    schema: &Schema,
) -> Vec<u8> {
    let threads: Vec<_> = threads.collect();
    debug_assert!(threads.len() < 256, "thread ref is 8-bit");
    let now_tsc = Instant::now().0 & TSC_MASK;
    let now_epoch_ns =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let base_tsc = threads
        .iter()
        .filter_map(|t| t.marks.first().map(|m| m.ts & TSC_MASK))
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

    for (i, t) in threads.iter().enumerate() {
        let koid = i as u64 + 2; // 1 is the process koid
        let index = i as u64 + 1; // 1-based thread-table index
        let name = fxt.intern(t.name);
        let process_arg = fxt.intern("process");
        fxt.kernel_object(OBJ_THREAD, koid, name, Some((process_arg, PROCESS_KOID)));
        fxt.thread_record(index, PROCESS_KOID, koid);

        // Perfetto scopes counter tracks to the process, keyed by name, so
        // qualifying each track with the thread name keeps threads' thread-local
        // counts from merging into one scrambled line.
        let memory_track = (!t.alloc.is_empty()).then(|| {
            (
                fxt.intern(&format!("memory ({})", t.name)),
                fxt.intern("live"),
                fxt.intern("allocated"),
                fxt.intern("freed"),
            )
        });
        let perf_tracks: Option<Vec<_>> = (!t.perf.is_empty()).then(|| {
            schema
                .iter()
                .map(|e| (fxt.intern(&format!("{} ({})", e.label, t.name)), fxt.intern(&e.label)))
                .collect()
        });

        // Counters are cumulative gauges Perfetto holds flat between points, so a
        // sample equal to the last emitted one on this thread is redundant. Most
        // frames don't allocate, so gating on change drops the bulk of the file.
        let mut prev_alloc: Option<AllocSample> = None;
        let mut prev_perf: Option<PerfSample> = None;

        for (j, mark) in t.marks.iter().enumerate() {
            let (id, ty) = match mark.frame {
                Frame::Open { id, .. } => (id, DURATION_BEGIN),
                Frame::Close { id } => (id, DURATION_END),
            };
            let raw = names.get(&id).map_or("unknown", String::as_str);
            let name = fxt.intern(&untimed(raw));
            fxt.event(ty, index, name, ns(mark.ts));

            if let (Some(&a), Some((track, live, allocated, freed))) =
                (t.alloc.get(j), memory_track) &&
                prev_alloc != Some(a)
            {
                fxt.counter(index, track, ns(mark.ts), &[
                    (live, a.live()),
                    (allocated, a.allocated),
                    (freed, a.freed),
                ]);
                prev_alloc = Some(a);
            }
            if let (Some(&sample), Some(tracks)) = (t.perf.get(j), &perf_tracks) &&
                prev_perf != Some(sample)
            {
                for (slot, &(track, series)) in tracks.iter().enumerate() {
                    fxt.counter(index, track, ns(mark.ts), &[(series, sample.vals[slot])]);
                }
                prev_perf = Some(sample);
            }
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

    /// Counter event: header + timestamp, a uint64 argument per series, then
    /// the trailing counter id. Perfetto keys the (process-scoped) track by
    /// `(name, counter_id)` and plots each argument as a line, labelling it
    /// `name:arg:counter_id`.
    fn counter(&mut self, thread_index: u64, name: u16, ts: u64, args: &[(u16, u64)]) {
        let n_args = args.len() as u64;
        let size = 2 + 2 * n_args + 1; // header + ts, two words per arg, counter id
        self.word(
            4 | (size << 4) |
                (COUNTER << 16) |
                (n_args << 20) |
                (thread_index << 24) |
                (u64::from(name) << 48),
        );
        self.word(ts);
        for &(arg_name, val) in args {
            // uint64 argument: type 4, size 2 words, name ref [16:32), then value.
            self.word(ARG_UINT64 | (2 << 4) | (u64::from(arg_name) << 16));
            self.word(val);
        }
        self.word(0); // counter id
    }
}

fn words(bytes: usize) -> u64 {
    bytes.div_ceil(8) as u64
}

#[cfg(test)]
mod tests {
    use rustc_hash::FxHashMap;

    use super::{COUNTER, ThreadTrace, trace};
    use crate::{
        Schema,
        allocator::AllocSample,
        flamegraph_timer::mark::{Frame, Mark},
        perf::PerfSample,
    };

    fn names() -> FxHashMap<u64, String> {
        FxHashMap::from_iter([(7u64, "work".to_owned())])
    }

    fn frames() -> [Mark; 2] {
        [Mark { frame: Frame::Open { id: 7, len: 4 }, ts: 0 }, Mark {
            frame: Frame::Close { id: 7 },
            ts: 100,
        }]
    }

    fn thread<'a>(
        marks: &'a [Mark],
        alloc: &'a [AllocSample],
        perf: &'a [PerfSample],
    ) -> ThreadTrace<'a> {
        ThreadTrace { name: "t", marks, alloc, perf }
    }

    #[test]
    fn emits_counter_track_when_alloc_present() {
        let marks = frames();
        let allocs =
            [AllocSample { allocated: 0, freed: 0 }, AllocSample { allocated: 4096, freed: 1024 }];
        let buf = trace([thread(&marks, &allocs, &[])].into_iter(), &names(), &Schema::empty());

        // The track/series names are interned only on the counter path, so their
        // presence proves a `memory` counter was emitted.
        assert!(contains(&buf, b"memory") && contains(&buf, b"live"), "counter track present");
        assert!(has_counter_event(&buf), "a Counter event record was written");
    }

    #[test]
    fn emits_perf_track_per_event() {
        let marks = frames();
        let perf =
            [PerfSample::default(), PerfSample { vals: [1_000_000_000, 500, 0, 0, 0, 0, 0, 0] }];
        let schema = Schema::parse("instructions,cache-misses");
        let buf = trace([thread(&marks, &[], &perf)].into_iter(), &names(), &schema);

        // A track is interned per schema event, so both labels present proves a
        // separate counter track was emitted for each.
        assert!(contains(&buf, b"instructions"), "instructions track present");
        assert!(contains(&buf, b"cache-misses"), "cache-misses track present");
        assert!(has_counter_event(&buf), "a Counter event record was written");
    }

    #[test]
    fn unchanged_counter_samples_are_gated() {
        // Four marks, but the alloc gauge never moves after the first sample:
        // Perfetto holds the value between points, so only the first is emitted.
        let marks = [
            Mark { frame: Frame::Open { id: 7, len: 4 }, ts: 0 },
            Mark { frame: Frame::Close { id: 7 }, ts: 10 },
            Mark { frame: Frame::Open { id: 7, len: 4 }, ts: 20 },
            Mark { frame: Frame::Close { id: 7 }, ts: 30 },
        ];
        let flat = AllocSample { allocated: 64, freed: 0 };
        let buf = trace([thread(&marks, &[flat; 4], &[])].into_iter(), &names(), &Schema::empty());
        assert_eq!(count_counter_events(&buf), 1, "only the first sample of a flat run is kept");
    }

    #[test]
    fn timing_only_trace_has_no_counter() {
        let marks = frames();
        let buf = trace([thread(&marks, &[], &[])].into_iter(), &names(), &Schema::empty());
        // The counter path is the only thing that interns these names, so their
        // absence is a deterministic "no counter emitted" signal (unlike the
        // word-pattern scan, which a data word could coincidentally match).
        assert!(!contains(&buf, b"memory") && !contains(&buf, b"live"), "no counter track");
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// True if any 8-byte word is an Event record (type 4) of event-type
    /// [`COUNTER`]. A heuristic scan, but the values here (small ts, byte
    /// strings) don't collide with that bit pattern.
    fn has_counter_event(buf: &[u8]) -> bool {
        count_counter_events(buf) > 0
    }

    /// Counter records walked by their size header (not a word scan), so a data
    /// word matching the Counter bit pattern can't inflate the count.
    fn count_counter_events(buf: &[u8]) -> usize {
        let mut off = 0;
        let mut n = 0;
        while off + 8 <= buf.len() {
            let word = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            let size = ((word >> 4) & 0xfff) as usize;
            if size == 0 {
                break;
            }
            if word & 0xf == 4 && (word >> 16) & 0xf == COUNTER {
                n += 1;
            }
            off += size * 8;
        }
        n
    }
}
