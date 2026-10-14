//! Record and replay fixed batches of G1 and G2 decompression inputs and
//! outputs.
//!
//! `replay_vectors` compares the Rust kernel with `decompress_g2_vectors.txt`
//! when IFMA is available. The Lean differential test checks both the
//! handwritten model and the extracted function against that recording.
//! Together, successful executions establish agreement on these batches.
//! `recorded_matches_blst` checks the recorded results on decided lanes without
//! requiring IFMA. The G1 recording also contains every scalar blst verdict and
//! public-wrapper outputs. Lean checks those scalar verdicts against the spec,
//! including invalid and undecided lanes. Each `write_vectors` regenerates its
//! group's file; `lean/Test/Differential/{G1,G2}.lean` documents the formats.
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
    G2_COMPRESSED_LEN, blst_p2_affine,
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
            points: batch.points.map(|p| point_words(&p)),
        }
    }

    /// Decided lanes whose result, as `lib.rs` reads it, differs from blst's
    /// verdict on the same input.
    fn blst_disagreements(&self, inputs: &[Encoding; LANES]) -> Vec<usize> {
        (0..LANES)
            .filter(|&lane| self.undecided & (1 << lane) == 0)
            .filter(|&lane| {
                let kernel = (self.valid & (1 << lane) != 0).then_some(self.points[lane]);
                let blst = uncompress_in_g2_blst(&inputs[lane]).map(|p| point_words(&p));
                kernel != blst
            })
            .collect()
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

    /// Differences between the recorded and new outputs, including coordinates
    /// on invalid lanes. The Lean refinement covers the whole batch, although
    /// `lib.rs` reads coordinates only on valid lanes.
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
    /// Read the declared number of batches in order and require an `endfile`
    /// marker. A truncated recording panics instead of checking fewer batches.
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
        assert!(count > 0, "{VECTORS}: no batches");
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

/// Expected verdicts for a named test case, checked before recording its
/// output. `on` lanes must be on the curve and `off` lanes must not. When
/// specified, `valid` and `undecided` must match the entire mask.
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

/// A batch's inputs, expected verdicts, and description for the recording.
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

fn point_words(p: &blst_p2_affine) -> [u64; 24] {
    let limbs = [p.x.fp[0].l, p.x.fp[1].l, p.y.fp[0].l, p.y.fp[1].l];
    std::array::from_fn(|i| limbs[i / 6][i % 6])
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

/// Check recorded outputs against blst on decided lanes; no IFMA is required.
/// Combined with an executed `replay_vectors` check, this establishes agreement
/// between the Rust kernel and blst on those lanes.
#[test]
fn recorded_matches_blst() {
    let text = std::fs::read_to_string(VECTORS).expect(VECTORS);
    let disagreements: Vec<String> = Recorded::parse_file(&text)
        .iter()
        .enumerate()
        .filter_map(|(index, batch)| {
            let lanes = batch.output.blst_disagreements(&batch.inputs);
            (!lanes.is_empty()).then(|| format!("batch {index} ({}): lanes {lanes:?}", batch.kind))
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "proof/decompress_g2_vectors.txt records kernel results that differ from blst on lanes the \
         kernel decided, so it was written from a kernel with a bug:\n{}",
        disagreements.join("\n")
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
        let lanes = output.blst_disagreements(&case.inputs);
        assert!(lanes.is_empty(), "{}: lanes {lanes:?} differ from blst", case.kind);
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

mod g1 {
    use std::fmt::Write as _;

    use blst::{
        BLST_ERROR, blst_fp_from_uint64, blst_p1, blst_p1_add_or_double, blst_p1_affine,
        blst_p1_affine_in_g1, blst_p1_compress, blst_p1_from_affine, blst_p1_generator,
        blst_p1_is_inf, blst_p1_mult, blst_p1_uncompress,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use silver_bls_simd::{decompress, simd_available, uncompress_in_g1, uncompress_in_g1_blst};

    use super::{LANES, SEED, g2_cases, p_plus, p_word, small};

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/proof/decompress_g1_vectors.txt");
    type Encoding = [u8; 48];
    type Point = [u64; 12];

    fn point_words(p: &blst_p1_affine) -> Point {
        std::array::from_fn(|i| if i < 6 { p.x.l[i] } else { p.y.l[i - 6] })
    }

    fn scalar(bytes: &Encoding) -> Option<Point> {
        uncompress_in_g1_blst(bytes).as_ref().map(point_words)
    }

    fn sentinel() -> blst_p1_affine {
        let mut p = blst_p1_affine::default();
        p.x.l = [0xfeed; 6];
        p.y.l = [0xbeef; 6];
        p
    }

    fn compress(p: &blst_p1) -> Encoding {
        let mut bytes = [0; 48];
        unsafe { blst_p1_compress(bytes.as_mut_ptr(), p) };
        bytes
    }

    fn times<const N: usize>(p: &blst_p1, scalar: &[u64; N]) -> blst_p1 {
        let mut out = blst_p1::default();
        unsafe { blst_p1_mult(&mut out, p, scalar.as_ptr().cast(), 64 * N) };
        out
    }

    fn with_flags(mut bytes: Encoding, flags: u8) -> Encoding {
        bytes[0] = (bytes[0] & 0x1f) | flags;
        bytes
    }

    fn random_x(rng: &mut ChaCha8Rng) -> Encoding {
        let mut bytes = [0; 48];
        rng.fill(&mut bytes[..]);
        with_flags(bytes, 0x80 | (bytes[0] & 0x20))
    }

    fn curve_point(rng: &mut ChaCha8Rng) -> blst_p1 {
        loop {
            let mut affine = blst_p1_affine::default();
            if unsafe { blst_p1_uncompress(&mut affine, random_x(rng).as_ptr()) } ==
                BLST_ERROR::BLST_SUCCESS &&
                !unsafe { blst_p1_affine_in_g1(&affine) }
            {
                let mut p = blst_p1::default();
                unsafe { blst_p1_from_affine(&mut p, &affine) };
                return p;
            }
        }
    }

    // #E(Fp) = r * h1. Divide out a prime power before projecting to torsion.
    fn order_div(q: u64) -> [u64; 6] {
        let h = [0x8c00aaab0000aaab_u64, 0x396c8c005555e156];
        let mut order = [0_u64; 6];
        for (i, a) in g2_cases::R_LIMBS.iter().enumerate() {
            let mut carry = 0_u128;
            for (j, b) in h.iter().enumerate() {
                let v = u128::from(*a) * u128::from(*b) + u128::from(order[i + j]) + carry;
                order[i + j] = v as u64;
                carry = v >> 64;
            }
            order[i + 2] = carry as u64;
        }
        let mut rem = 0_u128;
        for limb in order.iter_mut().rev() {
            let n = (rem << 64) | u128::from(*limb);
            *limb = (n / u128::from(q)) as u64;
            rem = n % u128::from(q);
        }
        assert_eq!(rem, 0);
        order
    }

    struct Case {
        kind: String,
        inputs: [Encoding; LANES],
    }

    fn cases() -> Vec<Case> {
        let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
        let generator = unsafe { &*blst_p1_generator() };
        let g = compress(generator);
        let mut cases = Vec::new();
        let mut push = |kind: &str, inputs| cases.push(Case { kind: kind.into(), inputs });
        push("generator", [g; LANES]);
        push("multiples", std::array::from_fn(|i| compress(&times(generator, &[i as u64 + 1]))));
        push("generator-flags", std::array::from_fn(|i| with_flags(g, (i as u8) << 5)));
        push("zero-body-flags", std::array::from_fn(|i| with_flags([0; 48], (i as u8) << 5)));
        push(
            "infinity",
            std::array::from_fn(|i| {
                let mut b = with_flags([0; 48], 0xc0);
                match i {
                    0 => (),
                    1 => b[0] = 0xe0,
                    2 => b[47] = 1,
                    3 => b[0] = 0x40,
                    4 => b[1] = 1,
                    5 => b[0] = 0x60,
                    6 => b[0] = 0xc1,
                    _ => b = [0xff; 48],
                }
                b
            }),
        );
        push(
            "x-near-p",
            std::array::from_fn(|i| {
                with_flags(
                    p_plus([-1, -1, 0, 0, 1, 1, 1 << 20, 1 << 20][i]),
                    if i % 2 == 0 { 0x80 } else { 0xa0 },
                )
            }),
        );
        for word in 1..=4 {
            push(
                &format!("p-word-{word}"),
                std::array::from_fn(|i| {
                    with_flags(p_word(word, i % 2 == 1), if i % 4 < 2 { 0x80 } else { 0xa0 })
                }),
            );
        }
        for start in [0, 8] {
            push(
                &format!("small-x-{start}"),
                std::array::from_fn(|i| {
                    with_flags(small(start + (i / 2) as u64), if i % 2 == 0 { 0x80 } else { 0xa0 })
                }),
            );
        }
        // x=0 has y=±2 and order 3; verify the fixture's order independently.
        let mut affine = blst_p1_affine::default();
        unsafe { blst_fp_from_uint64(&mut affine.y, [2, 0, 0, 0, 0, 0].as_ptr()) };
        let mut order_three = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut order_three, &affine) };
        assert_eq!(compress(&order_three), with_flags([0; 48], 0x80));
        assert!(!unsafe { blst_p1_is_inf(&order_three) });
        assert!(unsafe { blst_p1_is_inf(&times(&order_three, &[3])) });
        push("nonmembers", std::array::from_fn(|_| compress(&curve_point(&mut rng))));
        push(
            "nonresidues",
            std::array::from_fn(|_| {
                loop {
                    let bytes = random_x(&mut rng);
                    let mut body = bytes;
                    body[0] &= 0x1f;
                    let mut p = blst_p1_affine::default();
                    if body < p_plus(0) &&
                        unsafe { blst_p1_uncompress(&mut p, bytes.as_ptr()) } ==
                            BLST_ERROR::BLST_POINT_NOT_ON_CURVE
                    {
                        break bytes;
                    }
                }
            }),
        );
        for q in [3, 11, 10177, 859267, 52437899] {
            let scalar = order_div(if q == 3 { q } else { q * q });
            let torsion = loop {
                let mut p = times(&curve_point(&mut rng), &scalar);
                let next = times(&p, &[q]);
                if !unsafe { blst_p1_is_inf(&next) } {
                    p = next;
                }
                if !unsafe { blst_p1_is_inf(&p) } {
                    assert!(unsafe { blst_p1_is_inf(&times(&p, &[q])) });
                    break p;
                }
            };
            let mut sum = blst_p1::default();
            unsafe { blst_p1_add_or_double(&mut sum, generator, &torsion) };
            let t = compress(&torsion);
            let sum = compress(&sum);
            push(
                &format!("order-{q}"),
                std::array::from_fn(|i| {
                    let mut bytes = if i % 4 < 2 { t } else { sum };
                    if i % 2 == 1 {
                        bytes[0] ^= 0x20;
                    }
                    bytes
                }),
            );
        }
        for _ in 0..24 {
            push(
                "seeded-mixed",
                std::array::from_fn(|i| match i {
                    0 | 1 => compress(&times(generator, &[rng.r#gen::<u64>() | 1])),
                    2 => compress(&curve_point(&mut rng)),
                    3 => with_flags([0; 48], 0xc0),
                    4 => with_flags(g, (rng.r#gen::<u8>() & 7) << 5),
                    _ => random_x(&mut rng),
                }),
            );
        }
        for _ in 0..4 {
            push(
                "random-bytes",
                std::array::from_fn(|_| {
                    let mut bytes = [0; 48];
                    rng.fill(&mut bytes[..]);
                    bytes
                }),
            );
        }
        cases
    }

    #[derive(Debug, PartialEq)]
    struct Output {
        valid: u8,
        undecided: u8,
        points: [Point; LANES],
    }

    impl Output {
        fn of(inputs: &[Encoding; LANES]) -> Self {
            assert!(simd_available(), "G1 recording/replay requires AVX-512 IFMA");
            let b = unsafe { decompress::decompress(inputs) };
            Self {
                valid: b.valid,
                undecided: b.undecided,
                points: b.points.map(|p| point_words(&p)),
            }
        }

        fn check_blst(&self, expected: &[Option<Point>; LANES]) {
            for (lane, scalar) in expected.iter().enumerate() {
                if self.undecided & (1 << lane) == 0 {
                    assert_eq!(
                        (self.valid & (1 << lane) != 0).then_some(self.points[lane]),
                        *scalar,
                        "decided G1 lane {lane} differs from blst"
                    );
                }
            }
        }
    }

    struct Recorded {
        inputs: [Encoding; LANES],
        output: Output,
        blst: [Option<Point>; LANES],
    }
    struct Wrapper {
        refs: Vec<(usize, usize)>,
        output: Vec<Option<Point>>,
    }

    fn parse(text: &str) -> (Vec<Recorded>, Vec<Wrapper>) {
        let mut lines =
            text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
        let mut next = |key: &str| -> Vec<String> {
            let words: Vec<_> =
                lines.next().expect("truncated G1 fixture").split_whitespace().collect();
            assert_eq!(words[0], key);
            words[1..].iter().map(|s| (*s).into()).collect()
        };
        let hex = |s: &str| u64::from_str_radix(s, 16).unwrap();
        let point = |words: &[String]| -> Point {
            assert_eq!(words.len(), 12);
            std::array::from_fn(|i| hex(&words[i]))
        };
        let verdict = |words: &[String], lane: usize| -> Option<Point> {
            assert_eq!(words[0], lane.to_string());
            if words[1] == "none" {
                assert_eq!(words.len(), 2);
                None
            } else {
                Some(point(&words[1..]))
            }
        };
        assert_eq!(next("seed").len(), 1);
        let count: usize = next("batches")[0].parse().unwrap();
        assert!(count > 0);
        let mut batches = Vec::new();
        for index in 0..count {
            assert_eq!(next("batch")[0], index.to_string());
            let inputs = std::array::from_fn(|_| {
                let digits = &next("in")[0];
                assert_eq!(digits.len(), 96);
                std::array::from_fn(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).unwrap())
            });
            let valid = u8::try_from(hex(&next("valid")[0])).unwrap();
            let undecided = u8::try_from(hex(&next("undecided")[0])).unwrap();
            let points = std::array::from_fn(|lane| {
                let words = next("pt");
                assert_eq!(words[0], lane.to_string());
                point(&words[1..])
            });
            let blst = std::array::from_fn(|lane| verdict(&next("blst"), lane));
            assert!(next("end").is_empty());
            batches.push(Recorded { inputs, output: Output { valid, undecided, points }, blst });
        }
        let count: usize = next("wrappers")[0].parse().unwrap();
        assert!(count > 0);
        let mut wrappers = Vec::new();
        for index in 0..count {
            let header = next("wrapper");
            assert_eq!(header[0], index.to_string());
            let n: usize = header[2].parse().unwrap();
            let refs = (0..n)
                .map(|_| {
                    let r = next("ref");
                    let (b, l): (usize, usize) = (r[0].parse().unwrap(), r[1].parse().unwrap());
                    assert!(b < batches.len() && l < LANES);
                    (b, l)
                })
                .collect();
            let output = (0..n).map(|lane| verdict(&next("out"), lane)).collect();
            assert!(next("end").is_empty());
            wrappers.push(Wrapper { refs, output });
        }
        assert!(next("endfile").is_empty());
        assert!(lines.next().is_none(), "text after endfile");
        (batches, wrappers)
    }

    fn write_point(out: &mut String, key: &str, lane: usize, p: Option<Point>) {
        write!(out, "{key} {lane}").unwrap();
        if let Some(words) = p {
            for w in words {
                write!(out, " {w:x}").unwrap();
            }
        } else {
            out.push_str(" none");
        }
        out.push('\n');
    }

    #[test]
    fn recorded_matches_blst() {
        let (batches, wrappers) = parse(&std::fs::read_to_string(VECTORS).unwrap());
        for batch in &batches {
            assert_eq!(batch.blst, batch.inputs.map(|b| scalar(&b)));
            batch.output.check_blst(&batch.blst);
        }
        for w in wrappers {
            let expected: Vec<_> = w.refs.iter().map(|&(b, l)| batches[b].blst[l]).collect();
            assert_eq!(w.output, expected);
        }
    }

    #[test]
    fn replay_vectors() {
        assert!(
            simd_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
            "SILVER_REQUIRE_IFMA is set, but IFMA is unavailable"
        );
        let (batches, wrappers) = parse(&std::fs::read_to_string(VECTORS).unwrap());
        if simd_available() {
            for (index, b) in batches.iter().enumerate() {
                assert_eq!(Output::of(&b.inputs), b.output, "G1 batch {index}");
            }
        }
        for (index, w) in wrappers.iter().enumerate() {
            let inputs: Vec<_> = w.refs.iter().map(|&(b, l)| batches[b].inputs[l]).collect();
            let mut out = vec![Some(sentinel()); inputs.len()];
            uncompress_in_g1(&inputs, &mut out);
            assert_eq!(
                out.iter().map(|p| p.as_ref().map(point_words)).collect::<Vec<_>>(),
                w.output,
                "G1 wrapper {index}"
            );
        }
    }

    #[test]
    #[ignore = "rewrites proof/decompress_g1_vectors.txt; needs AVX-512 IFMA"]
    fn write_vectors() {
        let cases = cases();
        let mut out = format!(
            "# Recorded by proof/vectors.rs; G1 kernel, scalar oracle, public wrapper.\nseed {:#x}\nbatches {}\n",
            SEED ^ 1,
            cases.len()
        );
        for (index, c) in cases.iter().enumerate() {
            let got = Output::of(&c.inputs);
            let blst = c.inputs.map(|b| scalar(&b));
            got.check_blst(&blst);
            writeln!(out, "batch {index} {}", c.kind).unwrap();
            for bytes in c.inputs {
                writeln!(
                    out,
                    "in {}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )
                .unwrap();
            }
            writeln!(out, "valid {:02x}\nundecided {:02x}", got.valid, got.undecided).unwrap();
            for (lane, p) in got.points.into_iter().enumerate() {
                write_point(&mut out, "pt", lane, Some(p));
            }
            for (lane, p) in blst.into_iter().enumerate() {
                write_point(&mut out, "blst", lane, p);
            }
            out.push_str("end\n");
        }
        let lengths = [0, 1, 7, 8, 9, 15, 16, 17];
        writeln!(out, "wrappers {}", lengths.len() * 3).unwrap();
        let mut index = 0;
        for kind in ["members", "mixed", "rejected"] {
            for len in lengths {
                let refs: Vec<_> = (0..len)
                    .map(|i| match kind {
                        "members" => (1, i % 8),
                        "rejected" => (5, 2 + i % 6),
                        _ => match i % 5 {
                            0 => (1, i % 8),
                            1 => (4, 0),
                            2 => (4, 1),
                            3 => (12, i % 8),
                            _ => (5, 2),
                        },
                    })
                    .collect();
                let inputs: Vec<_> = refs.iter().map(|&(b, l)| cases[b].inputs[l]).collect();
                let mut result = vec![Some(sentinel()); len];
                uncompress_in_g1(&inputs, &mut result);
                let result: Vec<_> = result.iter().map(|p| p.as_ref().map(point_words)).collect();
                assert_eq!(result, inputs.iter().map(scalar).collect::<Vec<_>>());
                writeln!(out, "wrapper {index} {kind} {len}").unwrap();
                for (b, l) in refs {
                    writeln!(out, "ref {b} {l}").unwrap();
                }
                for (lane, p) in result.into_iter().enumerate() {
                    write_point(&mut out, "out", lane, p);
                }
                out.push_str("end\n");
                index += 1;
            }
        }
        out.push_str("endfile\n");
        std::fs::write(VECTORS, &out).unwrap();
        eprintln!(
            "G1: {} batches, {} lanes, {index} wrappers, {} bytes",
            cases.len(),
            cases.len() * 8,
            out.len()
        );
    }
}
