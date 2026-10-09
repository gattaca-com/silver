# Formal proof of the G2 decompression kernel

This folder holds a Lean 4 proof about `decompress_g2::decompress` in `../src`, the AVX-512 IFMA kernel that decodes and subgroup-checks eight compressed G2 points at once. The proof is about a hand-written Lean model of the Rust. A recorded set of batches ties the model to the Rust: a Rust test checks that the kernel still produces them, and a Lean test checks that the model does.

| Path | Content |
|---|---|
| `lean/` | The Lean project: the model, the proofs, the controls and the Lean side of the vector test. `lean/README.md` is a guide for fixing a failed `replay_vectors`. |
| `vectors.rs` | The Rust side of the vector test, a test target of `silver_bls_simd`: `replay_vectors` and `write_vectors`. |
| `decompress_g2_vectors.txt` | The recorded batches: inputs, and everything `decompress` returned for them. |

## What is proved

`lib.rs` reads three parts of a `Batch`: `undecided`, `valid`, and `points` on valid lanes. The headline theorem, in `lean/LeanBlsSimd/Proofs/Kernel.lean`, covers exactly those, lane by lane:

```lean
theorem decompress_eq_spec (hC : ScottComplete)
    (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    (if (decompress inputs).valid.toNat.testBit l then some (decompress inputs).points[l]
      else none) =
    (match G2.uncompress (toBytes inputs[l]) with
      | .error _ => none
      | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none)
```

For every input batch, each lane the model decides gives the specification's answer. Here `l : Fin 8` selects a lane; `some` and `none` correspond to Rust's `Some` and `None`. The specification is [ethereum/cryptography-specs](https://github.com/ethereum/cryptography-specs). It decodes with `G2.uncompress` and checks membership with `G2.inSubgroup`. That is the signature-checking stage of its `coreVerify`. Full verification also validates the public key, hashes the message to G2, and checks a pairing. `toBytes` passes the lane's 96 bytes unchanged. `blstLimbs P` lays out P's coordinates as blst's `blst_p2_affine` holds them.

The left side is how `decompress_g2_chunk` in `lib.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

Two hypotheses remain:

- `hu`: the kernel decides the lane. `lib.rs` sends undecided lanes to blst, and the proof says nothing about them. The canonical infinity encoding is one such lane.
- `hC : ScottComplete`: every point P of E′ with [r]P = O satisfies ψ(P) = [z]P. This is assumed, not proved. `scottComplete_of_cyclic` derives it from a premise without ψ or z: every P on E′ with [r]P = O is a multiple of the generator G.

The supporting theorems:

| Theorem | Statement |
|---|---|
| `valid_sound` | A `valid` lane decodes to a point of G2, and `points` holds it. It needs no Scott completeness, and `valid` implies the lane is decided. |
| `valid_complete` | Under `hC`, a decided lane that decodes to a point of G2 is `valid`. |
| `decode_lane` | On a decided lane, `on_curve` is set exactly when `G2.uncompress` succeeds. |
| `psi_generator` | ψ(G) = [z]G for the specification's generator G, in `Spec/Generator.lean`. |

A false `ScottComplete` hypothesis would make `valid_complete` vacuous. `psi_generator` checks the claim at G, without assuming completeness. Its controls reject the opposite sign of z and two wrong ψ constants. This check does not prove completeness for every subgroup point.

## What a reader must trust

1. Lean's kernel, v4.29.1, and the axioms `propext`, `Classical.choice` and `Quot.sound`. `lean/LeanBlsSimd/Axioms.lean` checks the library's theorems and their dependencies, failing the build if they use another axiom. No library proof uses `native_decide` or `bv_decide`.
2. The definitions the statement uses: Mathlib v4.29.1 for the curve's group law, and cryptography-specs at `d1331f02` for `G2.uncompress`, `G2.inSubgroup` and the field.
3. The statement's two interfaces. `toBytes` reads a lane's bytes as the spec's `ByteArray`. `blstLimbs` reads decoded coordinates through `Fp2.toField` and lays them out as blst 0.3.16's `blst_p2_affine`. Each Fp uses Montgomery form with R = 2^384 and six little-endian `u64` words. The order is c0 before c1, x before y.
4. `lean/LeanBlsSimd/Model/Intrinsics.lean`: the semantics of the 12 AVX-512 intrinsics, written by hand.
5. The transcription. `lean/LeanBlsSimd/Constants.lean` and `lean/LeanBlsSimd/Model/` transcribe the Rust files below by hand. `Fp8::mul` is modelled per lane, not as its vector code. The vector test checks the model against the Rust on the recorded batches, and on no others; its Lean side runs through Lean's compiler.
6. Two readings by eye: the headline's left side against `decompress_g2_chunk` in `lib.rs`, and its right side against `coreVerify`. Neither `lib.rs` nor `coreVerify` is modelled.
7. Scott completeness, as the hypothesis `hC`.

The theorem proves the Lean model correct; it does not prove that the Rust implements that model. End-to-end correctness also requires blst for undecided lanes, short chunks and hosts without SIMD support. The proof does not cover Rust compilation, linking, ABI, CPU feature detection or hardware.

## The vector test

`decompress_g2_vectors.txt` holds 105 batches of eight encodings, 840 lanes, with all three masks and every lane's `points` as `decompress` returned them. The batches mix seeded cases from `src/tests/g2_cases.rs`, the generator the crate's own tests use, with hand-picked edge cases: flag combinations, infinity encodings, coordinates at and around p in every word, x with no square root, points outside G2 and of small order, and both early returns, taken and not taken.

Two tests read the file:

- `replay_vectors`, in `vectors.rs`, runs the current kernel on the recorded inputs and fails if any output differs. It runs with the crate's other tests, in about 10 ms. Without AVX-512 IFMA it skips, unless `SILVER_REQUIRE_IFMA=1` is set, which makes it fail instead.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model on the same inputs and fails if any output differs. It needs the Lean toolchain and about 75 s.

While both pass, the Rust and the model agree on every recorded batch. The Lean side needs rerunning only when the model or the file changes; `replay_vectors` catches a change to the kernel's behaviour as it happens. It ignores changes to comments and formatting, which the hashes below do not. It does compare `points` on lanes `lib.rs` never reads, since the model transcribes those too. The batches do not isolate every part of the kernel: for example, Scott's two coordinate comparisons always agree on them, so a change to only one of them can pass.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the file, on a host with AVX-512 IFMA:

```sh
cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

`write_vectors` checks each edge batch against the masks it was built to produce, so a batch's name cannot drift from its content.

## The Rust this proof covers

The model transcribes these files of `crates/bls_simd/src`. They come from `main` at commit `6e70dc0e`, whose commit date is 2026-10-08T16:43:58+01:00.

| File | sha256 | git blob |
|---|---|---|
| `constants.rs` | `ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0` | `975320c4667ced6bb2d87f8a7689e7e1a212d691` |
| `fp8.rs` | `0809be23a1827013505f57d7a97b611665648ed5a8256eda07863dad1abaf258` | `60befd6ef6ccd157b030691d453cb18a6d8131c1` |
| `fp2x8.rs` | `47225004d9c06ebc064aba11b3ac5051178ce84435d0d998ab39d1b101b6f2bd` | `25c02b1474ee59662df326e2f465431d0d0d3ee2` |
| `g2x8.rs` | `718e92666499e94aa0e0dcd6f0b064fd575eea8e7f324d2aa77f905c7eab1f0d` | `015b21fc9338f74077aac1f22948336388dec614` |
| `decompress_g2.rs` | `8bac0146edb9d1914ab13a176923bf6d2164b8e39676b44662935abb4926b8d6` | `c9136a0a99d243d199ca5c24ecf64a592ba067ac` |

The headline's left side was read against `lib.rs` with sha256 `a29b07b4e1d24d702b4166d7a107dd3364862fc08de101a29fdd85b1b5b09bf0`, git blob `c63ddbc2d347aee884f6937de1b06bccec51731c`. `lib.rs` is not modelled, so the check below leaves it out.

To check for changes since the proof, run this from `crates/bls_simd/src`:

```sh
sha256sum -c <<'EOF'
ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0  constants.rs
0809be23a1827013505f57d7a97b611665648ed5a8256eda07863dad1abaf258  fp8.rs
47225004d9c06ebc064aba11b3ac5051178ce84435d0d998ab39d1b101b6f2bd  fp2x8.rs
718e92666499e94aa0e0dcd6f0b064fd575eea8e7f324d2aa77f905c7eab1f0d  g2x8.rs
8bac0146edb9d1914ab13a176923bf6d2164b8e39676b44662935abb4926b8d6  decompress_g2.rs
EOF
```

If a file fails, find its proved version with `git log --all --find-object=<blob>` and diff the two. A change to comments or formatting leaves the proof valid. Any other change needs the model updated and everything below rerun.

## Building and checking the proof

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; it must run from `lean/`. `lake build` compiles every proof, then runs the axiom guard. Its last lines report the theorem count and `axioms used: [propext, Quot.sound, Classical.choice]`. The first build takes about two minutes on 24 cores, and `.lake/` grows to about 8 GB.

Negative controls check that selected mutations are rejected. Other controls check concrete inputs and the axiom list. Every file must exit 0:

```sh
(
  for f in controls/*.lean; do
    lake env lean "$f" || exit 1
  done
)
```

| File | Shows |
|---|---|
| `Guard.lean` | The axiom guard rejects `native_decide`, `bv_decide` and `Lean.ofReduceBool`. |
| `Statements.lean`, `Limbs.lean`, `Fp8.lean`, `G2Group.lean`, `Decompress.lean` | A mutated constant, formula, carry or mask breaks the proof that uses it. |
| `Generator.lean` | −z, or a wrong ψ constant, breaks `psi_generator`. |
| `Kernel.lean` | The headline's input premises hold on concrete batches. Scott completeness stays assumed. |
| `AxiomLog.lean` | Prints the axioms of every theorem. |

The Lean side of the vector test, also from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt
```

It exits 0 when every value matches, 1 on a mismatch, and 2 on a malformed or incomplete file. The first build of `differential` takes about 100 s more.

| Path under `lean/` | Content |
|---|---|
| `LeanBlsSimd/Constants.lean` | p, r, z, R, and the Rust's constant tables proved equal to their derivations. |
| `LeanBlsSimd/Spec/` | Fp2 as a field, E′, ψ, Scott soundness, both square roots, the G2 group law, and the generator check. |
| `LeanBlsSimd/Model/` | The Rust, transcribed. |
| `LeanBlsSimd/Proofs/` | The model against the specification, ending in `Kernel.lean`. |
| `LeanBlsSimd/Axioms.lean` | The axiom guard. |
| `controls/` | Negative controls and the axiom log. |
| `Test/Main.lean` | The Lean side of the vector test; its docstring gives the file format. |
