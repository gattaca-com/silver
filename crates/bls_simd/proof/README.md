# Formal proof of the G2 decompression kernel

This folder holds a Lean 4 proof about `decompress_g2::decompress` in `../src`, the AVX-512 IFMA kernel that decodes and subgroup-checks eight compressed G2 points at once. Charon and Aeneas translate the Rust into Lean, and the proof is about that generated code. A hand-written Lean model of the Rust sits between the generated code and the specification. Lean proves the generated code equal to the model, function by function, and the model correct. A recorded set of batches ties both to the compiled Rust. A Rust test checks that the kernel still produces them; a Lean test checks that the model and the generated code do.

| Path | Content |
|---|---|
| `lean/` | The Lean project: the generated code, the model, the proofs, the controls and the Lean side of the vector test. `lean/README.md` is a guide for fixing a failed `replay_vectors`. |
| `vectors.rs` | The Rust side of the vector test, a test target of `silver_bls_simd`: `replay_vectors` and `write_vectors`. |
| `decompress_g2_vectors.txt` | The recorded batches: inputs, and everything `decompress` returned for them. |

## What is proved

`lib.rs` reads three parts of a `Batch`: `undecided`, `valid`, and `points` on valid lanes. The headline theorem, in `lean/LeanBlsSimd/Refines/Kernel.lean`, covers exactly those, lane by lane. It is about `silver_bls_simd.decompress_g2.decompress`, the Lean function that Aeneas generates from the Rust:

```lean
theorem decompress_extracted_eq_spec (hC : ScottComplete)
    (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_bls_simd.decompress_g2.decompress inputs = ok batch ∧
      ∀ l : Fin 8, (ofBatch batch).undecided.toNat.testBit l = false →
        (if (ofBatch batch).valid.toNat.testBit l then some (ofBatch batch).points[l]
          else none) =
        (match G2.uncompress (toBytes (ofArray (ofArray ofU8) inputs (m := 8))[l]) with
          | .error _ => none
          | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none)
```

For every input batch, the generated `decompress` returns a batch, and each lane it decides gives the specification's answer. Returning `ok` rules out Aeneas's other two outcomes: a panic, such as an out-of-bounds index or an overflow, and a loop that never ends. Here `l : Fin 8` selects a lane; `some` and `none` correspond to Rust's `Some` and `None`. The specification is [ethereum/cryptography-specs](https://github.com/ethereum/cryptography-specs). It decodes with `G2.uncompress` and checks membership with `G2.inSubgroup`. That is the signature-checking stage of its `coreVerify`. Full verification also validates the public key, hashes the message to G2, and checks a pairing.

The conversions read Aeneas's values as plain Lean values. `ofArray (ofArray ofU8)` reads the input arrays as `Vector`s of bytes. `ofBatch` reads the returned `Batch` field by field: each mask through `ofU8`, each point through `ofBlstP2Affine`. `toBytes` passes the lane's 96 bytes unchanged. `blstLimbs P` lays out P's coordinates as blst's `blst_p2_affine` holds them.

The left side is how `decompress_g2_chunk` in `lib.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

The theorem joins two others:

- `decompress_refines`, in `lean/LeanBlsSimd/Refines/DecompressG2.lean`: on every input, the generated `decompress` returns `ok` of the model's result, converted back by `toBatch`. It has no hypothesis. The other files of `Refines/` prove the same for the Rust functions that `decompress` calls, directly or through others, each against its counterpart in the model.
- `decompress_eq_spec`, in `lean/LeanBlsSimd/Proofs/Kernel.lean`: the same claim about the model's `decompress`, over `Vector`s.

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

So the model is a proved intermediate step. A reader does not need to trust that it transcribes the Rust.

Two hypotheses remain:

- The undecided bit is clear (`hu` in `decompress_eq_spec`): the kernel decides the lane. `lib.rs` sends undecided lanes to blst, and the proof says nothing about them. The canonical infinity encoding is one such lane.
- `hC : ScottComplete`: every point P of E′ with [r]P = O satisfies ψ(P) = [z]P. This is assumed, not proved. `scottComplete_of_cyclic` derives it from a premise without ψ or z: every P on E′ with [r]P = O is a multiple of the generator G.

The supporting theorems below that mention `decompress` are stated for the model's, in `lean/LeanBlsSimd/Proofs/Kernel.lean`. Through `decompress_refines`, they apply equally to the generated `decompress` read through `ofBatch`.

| Theorem | Statement |
|---|---|
| `valid_sound` | A `valid` lane decodes to a point of G2, and `points` holds it. It needs no Scott completeness, and `valid` implies the lane is decided. |
| `valid_complete` | Under `hC`, a decided lane that decodes to a point of G2 is `valid`. |
| `decode_lane` | On a decided lane, `on_curve` is set exactly when `G2.uncompress` succeeds. |
| `psi_generator` | ψ(G) = [z]G for the specification's generator G, in `Spec/Generator.lean`. |

A false `ScottComplete` hypothesis would make `valid_complete` vacuous. `psi_generator` checks the claim at G, without assuming completeness. Its controls reject the opposite sign of z and two wrong ψ constants. This check does not prove completeness for every subgroup point.

## What a reader must trust

1. Lean's kernel, v4.29.1, and the axioms `propext`, `Classical.choice` and `Quot.sound`. `lean/LeanBlsSimd/Axioms.lean` checks the library's theorems, the generated `decompress` and their dependencies, failing the build if they use another axiom. No library proof uses `native_decide` or `bv_decide`. Aeneas's Lean library contains `sorry`s, which Lean records as the axiom `sorryAx`. The same check shows that neither the headline nor the generated `decompress` reaches one.
2. The definitions the statement uses: Mathlib v4.29.1 for the curve's group law, and [ethereum/cryptography-specs](https://github.com/ethereum/cryptography-specs) at `d1331f02` for `G2.uncompress`, `G2.inSubgroup` and the field.
3. The statement's interfaces. `ofArray`, `ofU8`, `ofBatch` and `ofBlstP2Affine` read Aeneas's arrays, integers and structures element by element and field by field; integers convert through their bit-vectors. `toBytes` reads a lane's bytes as the spec's `ByteArray`. `blstLimbs` reads decoded coordinates through `Fp2.toField` and lays them out as blst 0.3.16's `blst_p2_affine`. Each Fp uses Montgomery form with R = 2^384 and six little-endian `u64` words. The order is c0 before c1, x before y.
4. The extraction: Charon's reading of the crate's MIR, and Aeneas's translation of it into `lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`. Charon compiles the crate with its own pinned nightly, nightly-2026-02-07, not the workspace's Rust 1.91.0. `lean/extract.sh` runs both tools at the Aeneas commit that `lean/lake-manifest.json` pins, `d9733413`, with Charon at the commit that Aeneas pins, `ed22146b`.
5. Aeneas's Lean library at the same commit. It models Rust's integers, arrays and slices, with their overflow and bounds checks, and defines `loop` as a `partial_fixpoint`.
6. The 15 hand-written externals in `lean/LeanBlsSimd/Extracted/TypesExternal.lean` and `FunsExternal.lean`. They stand for the items that Aeneas does not translate: the type `__m512i`, defined as the model's `M512`; the 12 AVX-512 intrinsics; `fp8::lanes`, a `transmute`; and blst's `Default` for `blst_p2_affine`. Each intrinsic returns its definition in `lean/LeanBlsSimd/Model/Intrinsics.lean`, written by hand from the Intel SDM and the `core::arch` of Rust 1.91.0. `fp8::lanes` returns lane `l` as element `l`, and blst 0.3.16 derives a `Default` that sets every limb to 0.
7. Two readings by eye: the headline's left side against `decompress_g2_chunk` in `lib.rs`, and its right side against `coreVerify`. Neither `lib.rs` nor `coreVerify` is modelled.
8. Scott completeness, as the hypothesis `hC`.

The theorem proves the generated Lean code correct. That this code behaves as the compiled Rust does rests on items 4 to 6. The vector test checks them on the recorded batches, and on no others. End-to-end correctness also requires blst for undecided lanes, short chunks and hosts without SIMD support. The proof does not cover Rust compilation, linking, ABI, CPU feature detection or hardware.

## The vector test

`decompress_g2_vectors.txt` holds 105 batches of eight encodings, 840 lanes, with all three masks and every lane's `points` as `decompress` returned them. The batches mix seeded cases from `src/tests/g2_cases.rs`, the generator the crate's own tests use, with hand-picked edge cases: flag combinations, infinity encodings, coordinates at and around p in every word, x with no square root, points outside G2 and of small order, and both early returns, taken and not taken.

Three tests read the file:

- `replay_vectors`, in `vectors.rs`, runs the current kernel on the recorded inputs and fails if any output differs. It runs with the crate's other tests, in about 10 ms. On x86_64 it skips when the `simd` feature or AVX-512F/IFMA support is unavailable; setting `SILVER_REQUIRE_IFMA` to any value makes that a failure. On other architectures this test target contains no tests, even with that variable set.
- `recorded_matches_blst`, also in `vectors.rs`, checks the recorded outputs against blst. For each lane marked decided in the recording, 716 of the 840, it compares acceptance and any accepted point's limbs with `uncompress_in_g2_blst` on the recorded input. It uses recorded outputs instead of running the kernel, so it needs no IFMA and never skips on x86_64.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model and the generated `decompress` on the same inputs through Lean's compiler. It fails if either output differs. It needs the Lean toolchain and about 3 minutes, of which the generated code takes about 100 s.

When `replay_vectors` actually runs and all three pass, the Rust, the model and the generated code agree on every recorded batch. All of them agree with blst on acceptance and accepted points for every decided lane in those batches. The proof covers the generated code. So the vector test mainly checks items 4 to 6 above against the compiled Rust: the extraction, Aeneas's library and the externals. Rerun the Lean side when its code, toolchain, dependencies or vector file changes; `replay_vectors` catches a change to the kernel's behaviour as it happens. It ignores changes to comments and formatting, which the hashes below do not. It does compare `points` on lanes `lib.rs` never reads, since the model and the generated code compute those too. The batches do not isolate every part of the kernel: for example, Scott's two coordinate comparisons always agree on them, so a change to only one of them can pass.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the file, run this from the silver repository root on an x86_64 host with AVX-512F and AVX-512 IFMA:

```sh
cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

`write_vectors` checks the mask expectations attached to each edge batch before writing the file. Some expectations constrain only selected lanes or masks. It also checks acceptance and accepted points against blst on every lane the new kernel marks decided, leaving the file untouched if any check fails.

## The Rust this proof covers

`lean/LeanBlsSimd/Extracted/` is generated from these files of `crates/bls_simd/src`, and the model transcribes them. They come from `main` at commit `017cc38c`, the squash merge of #383, whose commit date is 2026-10-09T16:20:32+01:00.

| File | sha256 | git blob |
|---|---|---|
| `constants.rs` | `ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0` | `975320c4667ced6bb2d87f8a7689e7e1a212d691` |
| `fp8.rs` | `bc900b65daf13d1e4b45e025f57eb3ebb5a2fc0a495986d1cbe3a769ed7e7434` | `dddf760e7b44139f9164ec067d3778d4cb09282a` |
| `fp2x8.rs` | `85affbafedca3bf15a85146bdcfe51a072ecde5a151c19fdd0d1ba95d7dd4b01` | `fe9cd24d01e624bad40f68b87bc59285c5c8f113` |
| `g2x8.rs` | `13ff8a6afb7e1f701843fb4da53ae698a5033db38e567fccf00e30be0ee84d00` | `684629e2239fe98f65c64101725cf7f9573548ca` |
| `decompress_g2.rs` | `af44730b948e574b0945d4b647f28ff065ddb963d2a4e111b00c384bf9ed566f` | `b16bb0e2e32ff77f547222a745a5d331e2b8776d` |

The headline's left side was read against `lib.rs` with sha256 `de8a59bf67aea7a413e916d19a65e93a3ecb53ef538829ab63d069f2a1c67d31`, git blob `6174d1cabd2dd6fef926bbb4e46e816e51f8a93e`. `lib.rs` is neither extracted nor modelled, so the check below leaves it out.

To check for changes since the proof, run this from `crates/bls_simd/src`:

```sh
sha256sum -c <<'EOF'
ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0  constants.rs
bc900b65daf13d1e4b45e025f57eb3ebb5a2fc0a495986d1cbe3a769ed7e7434  fp8.rs
85affbafedca3bf15a85146bdcfe51a072ecde5a151c19fdd0d1ba95d7dd4b01  fp2x8.rs
13ff8a6afb7e1f701843fb4da53ae698a5033db38e567fccf00e30be0ee84d00  g2x8.rs
af44730b948e574b0945d4b647f28ff065ddb963d2a4e111b00c384bf9ed566f  decompress_g2.rs
EOF
```

If a file fails, find its proved version with `git log --all --find-object=<blob>` and diff the two, then check the extraction for drift.

### Regenerating the extraction

`lean/extract.sh` reruns Charon and Aeneas on `crates/bls_simd/src` and compares the result with `lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`. It needs `AENEAS_DIR`, a checkout of [Aeneas](https://github.com/AeneasVerif/aeneas) at the commit that `lean/lake-manifest.json` pins for `aeneas`. In that checkout, `make setup-charon` builds Charon at the commit in `charon-pin`, and `make` builds Aeneas. Charon also needs rustup, which installs its nightly. The script refuses to run if either checkout or either binary differs from its pin. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Aeneas records where each item comes from in a `Source: '<file>', lines <span>` comment. The comparison ignores lines that hold only such a location. A change to Rust comments or formatting therefore shows no drift, and leaves the proof valid. With `--check`, the script leaves the tree alone: it prints any other difference and exits 1, or exits 0 when there is none.

On drift, run `./extract.sh` without `--check`, which replaces `Types.lean` and `Funs.lean`, and follow `lean/README.md`. In short: rebuild, and fix the refinement proofs in `lean/LeanBlsSimd/Refines/` that break. Update the model and `Proofs/` only where the change alters behaviour. Then rerun the controls and both vector tests, and update the table above. A passing vector test does not replace the drift check, since it covers only the recorded inputs.

## Building and checking the proof

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; it must run from `lean/`. `lake build` compiles Aeneas's Lean library and every proof, then runs the axiom guard. Building the library prints five `declaration uses 'sorry'` warnings; the guard shows that nothing it checks uses them. The build's last lines report the theorem count, the checked `silver_bls_simd.decompress_g2.decompress`, and `axioms used: [propext, Quot.sound, Classical.choice]`. The first build takes about three minutes on 24 cores, and `.lake/` grows to about 8 GB.

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
| `Kernel.lean` | The input premises of `decompress_eq_spec` hold on concrete batches, and on the generator's batch so does the headline's. Scott completeness stays assumed. |
| `Refines.lean` | A mutated generated function fails its refinement proof: swapped coordinates or operands, a wrong row, lane order, word order or loop start, or a missing addition. For six of the eight mutants, a kernel-checked proof shows the mutated claim false; for `times_minus_z`, the claim about one loop step. |
| `AxiomLog.lean` | Prints the axioms of every theorem. |

The Lean side of the vector test, also from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt
```

It exits 0 when every value matches, 1 on a mismatch, and 2 on a malformed or incomplete file. The first build of `differential` takes about two and a half minutes more.

| Path under `lean/` | Content |
|---|---|
| `LeanBlsSimd/Constants.lean` | p, r, z, R, and the Rust's constant tables proved equal to their derivations. |
| `LeanBlsSimd/Spec/` | Fp2 as a field, E′, ψ, Scott soundness, both square roots, the G2 group law, and the generator check. |
| `LeanBlsSimd/Extracted/` | The Lean code that Aeneas generates from the Rust, `Types.lean` and `Funs.lean`, never edited by hand; and the 15 hand-written externals, in `TypesExternal.lean` and `FunsExternal.lean`. |
| `LeanBlsSimd/Model/` | The Rust, transcribed by hand: the proved intermediate step between the generated code and the specification. |
| `LeanBlsSimd/Proofs/` | The model against the specification, ending in `Kernel.lean`. |
| `LeanBlsSimd/Refines/` | The generated code against the model, function by function, ending in `Kernel.lean` with the headline theorem. |
| `LeanBlsSimd/Axioms.lean` | The axiom guard. |
| `controls/` | Negative controls and the axiom log. |
| `Test/Main.lean` | The Lean side of the vector test; its docstring gives the file format. |
| `extract.sh` | Regenerates `LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`, or checks them for drift. |
