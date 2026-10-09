//! `decompress` on fixed batches, with every value it returns, recorded in
//! `decompress_g2_vectors.txt`. The Lean model in `lean/` is checked against
//! the same file, so while `replay_vectors` passes, the model and this crate
//! agree on those batches. `write_vectors` regenerates the file. The format is
//! documented in `lean/Test/Main.lean`.
#![cfg(target_arch = "x86_64")]

// The crate's unit tests use the parts this file does not.
#[allow(dead_code)]
#[path = "../src/tests/g2_cases.rs"]
mod g2_cases;

use std::{collections::BTreeMap, fmt::Write as _};

use blst::{blst_p2, blst_p2_add_or_double, blst_p2_generator};
use g2_cases::{G2_INFINITY, G2_KINDS, G2Cases, G2Kind, compress_g2, uncompress_g2};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use silver_bls_simd::{
    G2_COMPRESSED_LEN,
    constants::P_U64,
    decompress_g2::{self, Batch},
    fp8::LANES,
    simd_available, uncompress_in_g2_blst,
};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/proof/decompress_g2_vectors.txt");
const SEED: u64 = 0x6c65_616e_6d35_6200;

type Encoding = [u8; G2_COMPRESSED_LEN];

/// Everything `decompress` returns for one batch.
#[derive(PartialEq)]
struct Output {
    on_curve: u8,
    valid: u8,
    undecided: u8,
    /// Per lane: `x.fp[0]`, `x.fp[1]`, `y.fp[0]`, `y.fp[1]`, six limbs each.
    points: [[u64; 24]; LANES],
}

impl Output {
    fn of(inputs: &[Encoding; LANES]) -> Output {
        assert!(simd_available(), "the IFMA path is off");
        let batch: Batch = unsafe { decompress_g2::decompress(inputs) };
        Output {
            on_curve: batch.on_curve,
            valid: batch.valid,
            undecided: batch.undecided,
            points: batch.points.map(|p| {
                let limbs = [p.x.fp[0].l, p.x.fp[1].l, p.y.fp[0].l, p.y.fp[1].l];
                std::array::from_fn(|i| limbs[i / 6][i % 6])
            }),
        }
    }

    fn write(&self, out: &mut String) {
        writeln!(out, "on_curve {:02x}", self.on_curve).unwrap();
        writeln!(out, "valid {:02x}", self.valid).unwrap();
        writeln!(out, "undecided {:02x}", self.undecided).unwrap();
        for (lane, words) in self.points.iter().enumerate() {
            write!(out, "pt {lane}").unwrap();
            for word in words {
                write!(out, " {word:x}").unwrap();
            }
            writeln!(out).unwrap();
        }
    }

    /// What changed from `self` to `now`. `lib.rs` reads `points` only on
    /// `valid` lanes; the model transcribes the others too, so they count.
    fn changes(&self, now: &Output) -> String {
        let mut changes = Vec::new();
        for (name, was, is) in [
            ("on_curve", self.on_curve, now.on_curve),
            ("valid", self.valid, now.valid),
            ("undecided", self.undecided, now.undecided),
        ] {
            if was != is {
                changes.push(format!("{name} {was:08b} -> {is:08b}"));
            }
        }
        let read = self.valid | now.valid;
        let (read, unread): (Vec<usize>, Vec<usize>) = (0..LANES)
            .filter(|&lane| self.points[lane] != now.points[lane])
            .partition(|&lane| read & (1 << lane) != 0);
        if !read.is_empty() {
            changes.push(format!("points on valid lanes {read:?}"));
        }
        if !unread.is_empty() {
            changes.push(format!("points on lanes lib.rs does not read {unread:?}"));
        }
        changes.join(", ")
    }
}

/// A batch as the file records it.
struct Recorded {
    kind: String,
    inputs: [Encoding; LANES],
    output: Output,
}

impl Recorded {
    /// Panics on any departure from the format, so a damaged file cannot pass
    /// by holding fewer batches.
    fn parse_file(text: &str) -> Vec<Recorded> {
        let mut lines = text
            .lines()
            .enumerate()
            .map(|(i, line)| (i + 1, line.trim()))
            .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'));
        let mut next = |key: &str| -> Vec<String> {
            let (n, line) =
                lines.next().unwrap_or_else(|| panic!("{VECTORS}: ends before `{key}`"));
            let mut words = line.split_whitespace();
            assert_eq!(words.next(), Some(key), "{VECTORS}:{n}: expected `{key}`");
            words.map(str::to_owned).collect()
        };
        let hex = |word: &str| u64::from_str_radix(word, 16).expect(word);

        next("seed");
        let count: usize = next("batches")[0].parse().expect("batch count");
        let recorded: Vec<Recorded> = (0..count)
            .map(|index| {
                let batch = next("batch");
                assert_eq!(batch[0], index.to_string(), "batch indices run 0, 1, 2, ...");
                let inputs = std::array::from_fn(|_| {
                    let digits = &next("in")[0];
                    std::array::from_fn(|i| {
                        u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).unwrap()
                    })
                });
                let mut mask = |key| hex(&next(key)[0]) as u8;
                let (on_curve, valid, undecided) =
                    (mask("on_curve"), mask("valid"), mask("undecided"));
                let points = std::array::from_fn(|lane| {
                    let words = next("pt");
                    assert_eq!(words[0], lane.to_string());
                    std::array::from_fn(|i| hex(&words[i + 1]))
                });
                next("end");
                Recorded {
                    kind: batch[1].clone(),
                    inputs,
                    output: Output { on_curve, valid, undecided, points },
                }
            })
            .collect();
        next("endfile");
        recorded
    }
}

/// What a batch must produce, checked against the Rust's output so that a
/// batch's name cannot drift from its content. `on` lanes must be on the
/// curve and `off` lanes must not; `valid` and `undecided` are exact masks.
#[derive(Clone, Copy)]
struct Expect {
    on: u8,
    off: u8,
    valid: Option<u8>,
    undecided: Option<u8>,
}

impl Expect {
    const ANY: Expect = Expect { on: 0, off: 0, valid: None, undecided: None };

    fn exact(on_curve: u8, valid: u8, undecided: u8) -> Expect {
        Expect { on: on_curve, off: !on_curve, valid: Some(valid), undecided: Some(undecided) }
    }

    fn lanes(on: u8, off: u8, valid: Option<u8>, undecided: Option<u8>) -> Expect {
        Expect { on, off, valid, undecided }
    }

    fn check(&self, kind: &str, out: &Output) {
        assert_eq!(out.on_curve & self.on, self.on, "{kind}: on_curve {:08b}", out.on_curve);
        assert_eq!(out.on_curve & self.off, 0, "{kind}: on_curve {:08b}", out.on_curve);
        if let Some(valid) = self.valid {
            assert_eq!(out.valid, valid, "{kind}: valid");
        }
        if let Some(undecided) = self.undecided {
            assert_eq!(out.undecided, undecided, "{kind}: undecided");
        }
    }
}

/// A batch to record: its name, a comment for the file, its inputs and what
/// it must produce.
struct Case {
    kind: String,
    note: String,
    inputs: [Encoding; LANES],
    expect: Expect,
}

struct Batches(Vec<Case>);

impl Batches {
    fn push(&mut self, kind: &str, note: &str, inputs: [Encoding; LANES], expect: Expect) {
        self.0.push(Case { kind: kind.to_owned(), note: note.to_owned(), inputs, expect });
    }
}

/// The batches in file order. The order of the draws from `g2` fixes every
/// seeded input, so reordering these calls changes the file.
struct Cases {
    g2: G2Cases,
    batches: Batches,
}

impl Cases {
    fn all() -> Vec<Case> {
        let g2 = G2Cases(ChaCha8Rng::seed_from_u64(SEED));
        let mut cases = Cases { g2, batches: Batches(Vec::new()) };
        cases.seeded_mixed();
        cases.seeded_single_kind();
        cases.edge();
        cases.early_returns();
        cases.batches.0
    }

    fn seeded_mixed(&mut self) {
        for _ in 0..40 {
            let lanes: [(G2Kind, Encoding); LANES] = std::array::from_fn(|_| self.g2.encoding());
            let kinds: Vec<String> = lanes.iter().map(|(kind, _)| format!("{kind:?}")).collect();
            let note = format!("kinds {}", kinds.join(" "));
            self.batches.push("seeded-mixed", &note, lanes.map(|(_, bytes)| bytes), Expect::ANY);
        }
    }

    fn seeded_single_kind(&mut self) {
        for kind in G2_KINDS {
            for _ in 0..3 {
                let inputs = std::array::from_fn(|_| {
                    loop {
                        let (k, bytes) = self.g2.encoding();
                        if k == kind {
                            break bytes;
                        }
                    }
                });
                let expect = match kind {
                    G2Kind::Member => Expect::exact(0xff, 0xff, 0),
                    G2Kind::Infinity => Expect::exact(0, 0, 0xff),
                    G2Kind::NonCanonical => Expect::exact(0, 0, 0),
                    G2Kind::OutsideG2 | G2Kind::MemberPlusTorsion | G2Kind::ZeroComponent => {
                        Expect::exact(0xff, 0, 0)
                    }
                    G2Kind::Torsion => Expect::lanes(0xff, 0, Some(0), None),
                    G2Kind::RandomX | G2Kind::Flags => Expect::ANY,
                };
                self.batches.push(&format!("seeded-{kind:?}"), "", inputs, expect);
            }
        }
    }

    fn edge(&mut self) {
        let g = generator();
        let members: [Encoding; LANES] = std::array::from_fn(|_| compress_g2(&self.g2.member()));
        let mut g_negated = g;
        g_negated[0] ^= 0x20;
        let all_valid = Expect::exact(0xff, 0xff, 0);

        self.batches.push("edge-generator", "the generator in every lane", [g; LANES], all_valid);
        self.batches.push(
            "edge-generator-signs",
            "the generator with the larger-root flag set and clear, then negated points",
            std::array::from_fn(|i| match i % 4 {
                0 => g,
                1 => g_negated,
                2 => members[0],
                _ => {
                    let mut bytes = members[0];
                    bytes[0] ^= 0x20;
                    bytes
                }
            }),
            all_valid,
        );
        self.batches.push("edge-members", "eight hashed members", members, all_valid);
        self.batches.push(
            "edge-flag-combinations-generator",
            "lane i has flag bits i on the generator",
            std::array::from_fn(|i| {
                let mut bytes = g;
                bytes[0] = (bytes[0] & 0x1f) | ((i as u8) << 5);
                bytes
            }),
            Expect::exact(0x30, 0x30, 0xc0),
        );
        self.batches.push(
            "edge-flag-combinations-infinity",
            "lane i has flag bits i on the zero body, which is x = 0 and the infinity body",
            std::array::from_fn(|i| with_flags((i as u8) << 5)),
            Expect::exact(0, 0, 0xc0),
        );
        self.batches.push(
            "edge-flag-combinations-x0-max",
            "lane i has flag bits i on x1 = 0, x0 = p - 1",
            std::array::from_fn(|i| encoding([0; 48], p_plus(-1), (i as u8) << 5)),
            Expect::lanes(0, 0x0f, None, Some(0xc0)),
        );
        self.batches.push(
            "edge-flag-combinations-small",
            "lane i has flag bits i on x1 = 0, x0 = 1",
            std::array::from_fn(|i| encoding([0; 48], small(1), (i as u8) << 5)),
            Expect::exact(0, 0, 0xc0),
        );
        self.batches.push(
            "edge-flag-combinations-ones",
            "lane i has flag bits i on x1 and x0 all ones below the flags",
            std::array::from_fn(|i| {
                let mut bytes = [0xff; G2_COMPRESSED_LEN];
                bytes[0] = 0x1f | ((i as u8) << 5);
                bytes
            }),
            Expect::exact(0, 0, 0xc0),
        );
        self.batches.push(
            "edge-infinity-canonical",
            "canonical infinity in every lane",
            [G2_INFINITY; LANES],
            Expect::exact(0, 0, 0xff),
        );
        self.batches.push(
            "edge-infinity-noncanonical",
            "infinity flags with data bits set, in the first and second halves",
            std::array::from_fn(|i| {
                let mut bytes = G2_INFINITY;
                match i {
                    0 => bytes[1] = 1,
                    1 => bytes[47] = 1,
                    2 => bytes[48] = 1,
                    3 => bytes[95] = 1,
                    4 => bytes[0] |= 0x20,
                    5 => {
                        bytes[0] = 0x40;
                        bytes[95] = 1
                    }
                    6 => bytes[0] = 0x5f,
                    _ => bytes = [0xff; G2_COMPRESSED_LEN],
                }
                bytes
            }),
            Expect::exact(0, 0, 0x9f),
        );
        self.batches.push(
            "edge-infinity-among-members",
            "one infinity lane among members",
            std::array::from_fn(|i| if i == 3 { G2_INFINITY } else { members[i] }),
            Expect::exact(0xf7, 0xf7, 0x08),
        );
        self.batches.push(
            "edge-x-at-or-above-p-x1",
            "x1 = p - 1, p, p + 1, p + 2^20, 2^381 - 1; x0 = 0",
            std::array::from_fn(|i| match i {
                0 => encoding(p_plus(-1), [0; 48], 0x80),
                1 => encoding(p_plus(0), [0; 48], 0x80),
                2 => encoding(p_plus(1), [0; 48], 0x80),
                3 => encoding(p_plus(1 << 20), [0; 48], 0x80),
                4 => {
                    let mut x1 = [0xff; 48];
                    x1[0] = 0x1f;
                    encoding(x1, [0; 48], 0x80)
                }
                5 => encoding(p_plus(0), [0; 48], 0xa0),
                6 => encoding(p_plus(1), small(1), 0x80),
                _ => encoding(p_plus(-1), p_plus(-1), 0x80),
            }),
            Expect::lanes(0, 0x7e, None, Some(0)),
        );
        self.batches.push(
            "edge-x-at-or-above-p-x0",
            "x0 = p - 1, p, p + 1, p + 2^20, 2^384 - 1; x1 = 0",
            std::array::from_fn(|i| match i {
                0 => encoding([0; 48], p_plus(-1), 0x80),
                1 => encoding([0; 48], p_plus(0), 0x80),
                2 => encoding([0; 48], p_plus(1), 0x80),
                3 => encoding([0; 48], p_plus(1 << 20), 0x80),
                4 => encoding([0; 48], [0xff; 48], 0x80),
                5 => encoding([0; 48], p_plus(0), 0xa0),
                6 => encoding(small(1), p_plus(1), 0x80),
                _ => encoding([0; 48], p_plus(-1), 0x80),
            }),
            Expect::lanes(0, 0x7e, None, Some(0)),
        );
        self.batches.push(
            "edge-x-both-halves-p",
            "x1 = x0 = p, with and without larger-root, and p in one half beside a member",
            std::array::from_fn(|i| match i {
                0 => encoding(p_plus(0), p_plus(0), 0x80),
                1 => encoding(p_plus(0), p_plus(0), 0xa0),
                2 => encoding(p_plus(-1), p_plus(0), 0x80),
                3 => encoding(p_plus(0), p_plus(-1), 0x80),
                _ => members[i],
            }),
            Expect::exact(0xf0, 0xf0, 0),
        );
        for word in 1..=4 {
            for half in [1, 0] {
                self.batches.push(
                    &format!("edge-less-than-p-word-{word}-x{half}"),
                    &format!(
                        "lane 0 has x{half} = p - 2^(64 {word}), lane 1 has p + 2^(64 {word}); \
                         generators beside"
                    ),
                    std::array::from_fn(|i| {
                        if i > 1 {
                            return g;
                        }
                        let x = p_word(word, i == 1);
                        if half == 1 {
                            encoding(x, [0; 48], 0x80)
                        } else {
                            encoding([0; 48], x, 0x80)
                        }
                    }),
                    Expect::lanes(0xfc, 0x02, Some(0xfc), Some(0)),
                );
            }
        }
        self.batches.push(
            "edge-x-small",
            "x1 = 0, x0 = 1..8",
            std::array::from_fn(|i| encoding([0; 48], small(i as u64 + 1), 0x80)),
            Expect::lanes(0, 0, Some(0), Some(0)),
        );
        self.batches.push(
            "edge-x-small-imaginary",
            "x1 = 1..8, x0 = 0, alternating larger-root",
            std::array::from_fn(|i| {
                encoding(small(i as u64 + 1), [0; 48], 0x80 | if i % 2 == 1 { 0x20 } else { 0 })
            }),
            Expect::lanes(0, 0, Some(0), Some(0)),
        );

        let no_root: [Encoding; LANES] = std::array::from_fn(|_| {
            loop {
                let bytes = self.g2.random_x();
                let mut x1 = [0; 48];
                x1.copy_from_slice(&bytes[..48]);
                x1[0] &= 0x1f;
                let canonical = x1 < p_plus(0) && bytes[48..] < p_plus(0)[..];
                if canonical && uncompress_g2(&bytes).is_none() {
                    break bytes;
                }
            }
        });
        self.batches.push(
            "edge-no-root",
            "canonical x, no square root",
            no_root,
            Expect::exact(0, 0, 0),
        );
        self.batches.push(
            "edge-no-root-beside-member",
            "no-root lanes beside one member",
            std::array::from_fn(|i| if i == 5 { members[0] } else { no_root[i] }),
            Expect::exact(0x20, 0x20, 0),
        );
        self.batches.push(
            "edge-outside-subgroup",
            "on the curve, outside G2",
            std::array::from_fn(|_| compress_g2(&self.g2.curve_point())),
            Expect::exact(0xff, 0, 0),
        );
        self.batches.push(
            "edge-torsion",
            "points of small prime order",
            std::array::from_fn(|_| compress_g2(&self.g2.torsion())),
            Expect::lanes(0xff, 0, Some(0), None),
        );
        self.batches.push(
            "edge-member-plus-torsion",
            "a member plus a torsion point",
            std::array::from_fn(|_| {
                let (member, torsion) = (self.g2.member(), self.g2.torsion());
                let mut sum = blst_p2::default();
                unsafe { blst_p2_add_or_double(&mut sum, &member, &torsion) };
                compress_g2(&sum)
            }),
            Expect::exact(0xff, 0, 0),
        );
        self.batches.push(
            "edge-members-and-outsiders",
            "members interleaved with outsiders and torsion",
            std::array::from_fn(|i| match i % 3 {
                0 => compress_g2(&self.g2.member()),
                1 => compress_g2(&self.g2.curve_point()),
                _ => compress_g2(&self.g2.torsion()),
            }),
            Expect::lanes(0xff, 0, Some(0x49), None),
        );
        self.batches.push(
            "edge-zero-component",
            "x with one component of x^3 + 4(1 + i) zero",
            std::array::from_fn(|_| self.g2.zero_component()),
            Expect::exact(0xff, 0, 0),
        );
    }

    fn early_returns(&mut self) {
        let g = generator();
        let mut uncompressed = g;
        uncompressed[0] &= 0x7f;
        let x1_is_p = encoding(p_plus(0), [0; 48], 0x80);
        let x0_is_p = encoding([0; 48], p_plus(0), 0x80);
        let undecodable = [
            G2_INFINITY,
            with_flags(0xe0),
            with_flags(0x40),
            with_flags(0x20),
            uncompressed,
            x1_is_p,
            x0_is_p,
            with_flags(0),
        ];
        self.batches.push(
            "edge-return1-with-infinity",
            "no decodable lane; two infinity lanes, so the first return keeps undecided",
            undecodable,
            Expect::exact(0, 0, 0x03),
        );
        self.batches.push(
            "edge-return1-all-rejected",
            "every lane rejected at decoding, none undecided",
            std::array::from_fn(|i| match i % 4 {
                0 => uncompressed,
                1 => x1_is_p,
                2 => x0_is_p,
                _ => with_flags(0x20 * (i as u8 % 2)),
            }),
            Expect::exact(0, 0, 0),
        );
        self.batches.push(
            "edge-return1-all-undecided",
            "every lane an infinity encoding, with and without the larger-root bit and data",
            std::array::from_fn(|i| {
                let mut bytes = with_flags(0xc0 | (0x20 * (i as u8 % 2)));
                if i >= 4 {
                    bytes[1 + i] = 1;
                }
                bytes
            }),
            Expect::exact(0, 0, 0xff),
        );
        let mut off_curve = undecodable;
        off_curve[6] = with_flags(0x80);
        off_curve[7] = with_flags(0xa0);
        self.batches.push(
            "edge-return2-off-curve",
            "decodable lanes, none on the curve; the second return is taken",
            off_curve,
            Expect::exact(0, 0, 0x03),
        );
        let mut beside_member = off_curve;
        beside_member[7] = g;
        self.batches.push(
            "edge-return2-not-taken",
            "one member beside off-curve lanes",
            beside_member,
            Expect::exact(0x80, 0x80, 0x03),
        );
        let mut rootless = (0..).map(|x0| encoding([0; 48], small(x0), 0x80));
        let rootless = std::array::from_fn(|_| {
            rootless.by_ref().find(|bytes| uncompress_g2(bytes).is_none()).unwrap()
        });
        self.batches.push(
            "edge-all-off-curve-decodable",
            "x1 = 0 and x0 the first eight values with no square root; every lane decodes",
            rootless,
            Expect::exact(0, 0, 0),
        );
        self.batches.push(
            "edge-late-return-valid-only-in-one-lane",
            "one member among seven outsiders",
            std::array::from_fn(|i| if i == 6 { g } else { compress_g2(&self.g2.curve_point()) }),
            Expect::exact(0xff, 0x40, 0),
        );
    }
}

fn generator() -> Encoding {
    compress_g2(unsafe { &*blst_p2_generator() })
}

fn with_flags(flags: u8) -> Encoding {
    let mut bytes = [0; G2_COMPRESSED_LEN];
    bytes[0] = flags;
    bytes
}

/// `x1` and `x0` as stored, with `flags` OR-ed into the top byte.
fn encoding(x1: [u8; 48], x0: [u8; 48], flags: u8) -> Encoding {
    let mut bytes = [0; G2_COMPRESSED_LEN];
    bytes[..48].copy_from_slice(&x1);
    bytes[48..].copy_from_slice(&x0);
    bytes[0] |= flags;
    bytes
}

fn big_endian(limbs: &[u64; 6]) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (word, limb) in limbs.iter().enumerate() {
        bytes[48 - 8 * (word + 1)..48 - 8 * word].copy_from_slice(&limb.to_be_bytes());
    }
    bytes
}

fn small(value: u64) -> [u8; 48] {
    big_endian(&[value, 0, 0, 0, 0, 0])
}

/// p + `delta`, for a `delta` that leaves p's other words unchanged.
fn p_plus(delta: i64) -> [u8; 48] {
    let mut limbs = P_U64;
    limbs[0] = limbs[0].checked_add_signed(delta).unwrap();
    big_endian(&limbs)
}

/// p - 2^(64 `word`) or p + 2^(64 `word`): only word `word` differs from p's,
/// so `less_than_p` must compare it to decide.
fn p_word(word: usize, above: bool) -> [u8; 48] {
    let mut limbs = P_U64;
    limbs[word] = if above { limbs[word] + 1 } else { limbs[word] - 1 };
    big_endian(&limbs)
}

#[test]
fn replay_vectors() {
    assert!(
        simd_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    if !simd_available() {
        return;
    }
    let text = std::fs::read_to_string(VECTORS).expect(VECTORS);
    let recorded = Recorded::parse_file(&text);
    let changed: Vec<String> = recorded
        .iter()
        .enumerate()
        .filter_map(|(index, batch)| {
            let now = Output::of(&batch.inputs);
            (now != batch.output)
                .then(|| format!("batch {index} ({}): {}", batch.kind, batch.output.changes(&now)))
        })
        .collect();
    assert!(
        changed.is_empty(),
        "decompress no longer returns what proof/decompress_g2_vectors.txt records, so the Lean \
         proof in proof/lean may no longer describe this crate; proof/lean/README.md explains \
         what to do. {} of {} batches changed:\n{}",
        changed.len(),
        recorded.len(),
        changed.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
#[ignore = "rewrites proof/decompress_g2_vectors.txt; needs AVX-512 IFMA"]
fn write_vectors() {
    let cases = Cases::all();
    let mut out = format!(
        "# Written by proof/vectors.rs: decompress on each batch, and everything it returned.\n\
         seed {SEED:#x}\n\
         batches {}\n",
        cases.len()
    );
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, case) in cases.iter().enumerate() {
        let output = Output::of(&case.inputs);
        case.expect.check(&case.kind, &output);
        writeln!(out, "batch {index} {}", case.kind).unwrap();
        if !case.note.is_empty() {
            writeln!(out, "# {}", case.note).unwrap();
        }
        for input in &case.inputs {
            let digits: String = input.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "in {digits}").unwrap();
        }
        output.write(&mut out);
        writeln!(out, "end").unwrap();
        *counts.entry(&case.kind).or_default() += 1;
    }
    out.push_str("endfile\n");
    std::fs::write(VECTORS, &out).expect(VECTORS);
    for (kind, n) in &counts {
        eprintln!("{n:3} {kind}");
    }
    eprintln!("{} batches, {} bytes, in {VECTORS}", cases.len(), out.len());
}
