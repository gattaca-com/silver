# Formal proof of the G2 decompression kernel

## G1 extension: correctness proved, validation in progress

The G1 extension is at milestone M3: its generated code refines its executable model, and the model satisfies the specification on decided lanes. Scott soundness and completeness, KZG acceptance, infinity handling, and the public wrapper theorem and corollaries are proved. The default axiom guard covers the complete G1 and G2 proofs and both generated entry points. M4 controls, differential vectors and final documentation checks are in progress.

`UncompressG1.uncompress_in_g1_eq_spec_or_blst` covers the generated public wrapper, including output writes and all scalar fallbacks. An index uses the kernel's verdict exactly when SIMD is available, the index belongs to a complete eight-input chunk, and the kernel's undecided bit is clear. Every other index uses the scalar external's result. `UncompressG1.uncompress_in_g1_eq_spec` assumes only that the scalar external agrees with the specification on all 48-byte inputs, in addition to the API's equal-length precondition.

The G1 specification verdict calls `bytesToKzgProof`, decodes its accepted bytes with `G1.uncompress`, and converts the point to blst's affine layout. The bridge lemmas prove that acceptance agrees with both `bytesToKzgProof` and `bytesToKzgCommitment`. The conversion first calls `G1.toAffine`, then represents each coordinate as six little-endian Montgomery words with R = 2^384. Infinity has both coordinates zero.

The pinned specification and blst 0.3.16 agree on canonical compressed infinity: `0xc0` followed by 47 zero bytes is accepted; other infinity encodings are rejected. `validateKzgG1` explicitly allows this encoding, and `G1.uncompress` returns `G1.zero`. blst's `POINTonE1_Uncompress_Z` zeroes the affine output for it, and `blst_p1_affine_in_g1` accepts it. The kernel marks compressed infinity lanes undecided and delegates them to blst. The Lean infinity lemmas prove the specification verdict and kernel fallback behavior; blst agreement also receives a recorded-vector check.

The G1 externals are parameterized by `silver_bls_simd.G1Externals`: an arbitrary Boolean CPU observation and an arbitrary total function from 48 bytes to an optional affine point. Their Lean wrappers return `ok`, which trusts termination of feature detection and blst, but imposes no correctness assumption on blst in the first theorem. The corollary states that assumption explicitly. Shared intrinsic and `fp8::lanes` models retain their G2 meanings; the added `blst_p1_affine` default model zeroes every limb.

`extract.sh` starts from both `decompress_g2::decompress` and `uncompress_in_g1`. After Aeneas runs, it inserts `variable [G1Externals]`; Lean propagates that parameter only through definitions which use those externals. It also quotes the generated identifier `full`, which is reserved in the imported Lean environment. Both adaptations are part of the extraction trust boundary and are included in `--check`. No Rust source is changed.

The Scott lemmas use σ(x, y) = (βx, y), with β fixed by the kernel's `BETA_MONT`, and the identity σ²(P) = [−z²]P. Completeness uses the spec's generator-order proof and the elementary bound `Nat.card E.Point ≤ 2 * p + 1 < r²`. Formula correctness is conditional on a clear undecided bit; the headline theorem does not require proving that subgroup members always avoid exceptional formulas.

This directory contains a Lean 4 correctness proof for the code that Charon and Aeneas generate from `decompress_g2::decompress` in `../src`. The Rust kernel uses AVX-512 IFMA to decode and subgroup-check eight compressed G2 points at a time.

The proof has two parts: the generated code returns exactly the result of a hand-written model, and the model agrees with the specification on every lane the kernel decides. Scott completeness is proved using a character-sum bound on the curve's point count. Recorded test vectors also compare the generated code and model with the compiled Rust. Those tests check the translation on particular inputs; they are not a proof of the translation itself.

| Path | Content |
|---|---|
| `lean/` | The Lean project: the generated code, the model, the proofs, the controls and the Lean side of the vector test. `lean/README.md` is a guide for fixing a failed `replay_vectors`. |
| `vectors.rs` | The Rust side of the vector test, a test target of `silver_bls_simd`: `replay_vectors` and `write_vectors`. |
| `decompress_g2_vectors.txt` | The recorded batches: inputs, and everything `decompress` returned for them. |

## What is proved

`lib.rs` reads three parts of a `Batch`: `undecided`, `valid`, and `points` on valid lanes. The headline theorem, in `lean/LeanBlsSimd/Refines/Complete.lean`, covers exactly those, lane by lane. It is about `silver_bls_simd.decompress_g2.decompress`, the Lean function that Aeneas generates from the Rust:

```lean
theorem decompress_extracted_eq_spec_complete (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_bls_simd.decompress_g2.decompress inputs = ok batch ∧
      (∀ l : Fin 8, (ofBatch batch).undecided.toNat.testBit l = false →
        (if (ofBatch batch).valid.toNat.testBit l then some (ofBatch batch).points[l]
          else none) =
        (match G2.uncompress (toBytes (ofArray (ofArray ofU8) inputs (m := 8))[l]) with
          | .error _ => none
          | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none))
```

The generated `decompress` returns `ok batch` for every input. In Aeneas's semantics, this rules out both a panic and divergence. Agreement with the specification requires a clear `undecided` bit for the lane being checked. The conditional API `decompress_extracted_eq_spec` remains in `Refines/Kernel.lean`; the headline theorem supplies its `ScottComplete` argument using `scott_complete`.

Here `l : Fin 8` selects one of the eight lanes. The expression returns `some point` for an accepted lane and `none` for a rejected lane. On the right, [ethereum/cryptography-specs](https://github.com/ethereum/cryptography-specs) decodes with `G2.uncompress` and checks subgroup membership with `G2.inSubgroup`. These are the signature decoding and subgroup checks used by `coreVerify`; the theorem does not cover the rest of signature verification, which also validates the public key, hashes the message to G2, and checks a pairing.

The conversions make the representation on each side explicit. `ofArray (ofArray ofU8)` converts Aeneas's input arrays to `Vector`s of bytes. `ofBatch` converts each returned mask through `ofU8` and each point through `ofBlstP2Affine`. `toBytes` passes the lane's 96 bytes unchanged. `blstLimbs P` expresses P's coordinates in blst's `blst_p2_affine` layout.

The left side is how `decompress_g2_chunk` in `lib.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

The theorem combines two results:

- `decompress_refines`, in `lean/LeanBlsSimd/Refines/DecompressG2.lean`: on every input, the generated `decompress` returns `ok` of the model's result, converted back by `toBatch`. This unconditional equality covers every field, including points on rejected and undecided lanes. The other files in `Refines/` establish the corresponding equalities for the functions it calls.
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

The model's agreement with the generated code is therefore proved. Agreement between that generated code and Rust still depends on the extraction and external definitions described below.

The model theorem takes two hypotheses; the headline theorem keeps only the first:

- The undecided bit is clear (`hu` in `decompress_eq_spec`): the kernel decides the lane. `lib.rs` sends undecided lanes to blst. The theorem gives no specification result for those lanes, although unconditional refinement still covers their computed fields. The canonical infinity encoding is one such lane.
- `hC : ScottComplete`: every point P of E′ with [r]P = O satisfies ψ(P) = [z]P. The model theorem retains this parameter; `scott_complete` proves it and supplies it to the headline theorem.

The supporting theorems that mention `decompress` refer to the model function and are stated in `lean/LeanBlsSimd/Proofs/Kernel.lean`. Through `decompress_refines`, they also apply to the generated `decompress`, with its result converted by `ofBatch`.

| Theorem | Statement |
|---|---|
| `valid_sound` | A `valid` lane decodes to a point of G2, and `points` holds it. It needs no Scott completeness, and `valid` implies the lane is decided. |
| `valid_complete` | Under `hC`, a decided lane that decodes to a point of G2 is `valid`. |
| `decode_lane` | On a decided lane, `on_curve` is set exactly when `G2.uncompress` succeeds. |
| `psi_generator` | ψ(G) = [z]G for the specification's generator G, in `Spec/Generator.lean`. |

`psi_generator` proves the Scott identity at G without assuming completeness. Its controls reject the opposite sign of z and two wrong ψ constants. `ScottCardinality.lean` and `CubicHasse.lean` extend this identity to every rational r-torsion point.

`Spec/ScottCardinality.lean` proves that G has exact order r, using the spec dependency's primality certificate for r. If r² does not divide the curve's point count, the quotient by G's cyclic subgroup has order coprime to r, so every rational r-torsion point is a multiple of G. The numerical Hasse interval `(p - 1)² ≤ Nat.card E'.Point ≤ (p + 1)²` contains no multiple of r²; both exclusions are checked in Lean's kernel.

`Spec/CubicHasse.lean` proves these Hasse bounds and concludes `scott_complete : ScottComplete`. `PointCount.lean` expresses the count as p² + 1 plus a quadratic-character sum. `CubeFiber.lean` and `CharacterSum.lean` express that sum as two weighted Jacobi sums, each with a coefficient of norm one. `JacobiNorm.lean` proves that a Jacobi sum has norm √q over a field of size q when both characters and their product are nontrivial. The character-order arguments and `cubic_mul_quadratic_ne_one` establish these conditions for both sums here. With q = p², the triangle inequality then gives the required bound of 2p. This proves the bounds for the existing twist; it does not compute its exact point count. The conditional cardinality and cyclicity APIs remain available.

## What a reader must trust

1. Lean's kernel, v4.29.1, and the axioms `propext`, `Classical.choice` and `Quot.sound`. `lean/LeanBlsSimd/Axioms.lean` checks the library's theorems, the generated `decompress` and their dependencies, failing the build if they use another axiom. No library proof uses `native_decide` or `bv_decide`. Aeneas's Lean library contains `sorry`s, which Lean records as the axiom `sorryAx`. The same check shows that neither the headline theorem nor the generated `decompress` depends on one.
2. The definitions the statement uses: Mathlib v4.29.1 for the curve's group law, and [ethereum/cryptography-specs](https://github.com/ethereum/cryptography-specs) at `d1331f02` for `G2.uncompress`, `G2.inSubgroup` and the field.
3. The interpretation of the theorem's inputs and outputs. `ofArray`, `ofU8`, `ofBatch` and `ofBlstP2Affine` convert Aeneas's arrays, integers and structures element by element and field by field; integers convert through their bit-vectors. `toBytes` converts a lane's bytes to the spec's `ByteArray`. `blstLimbs` converts decoded coordinates through `Fp2.toField` and represents them in blst 0.3.16's `blst_p2_affine` layout. Each Fp uses Montgomery form with R = 2^384 and six little-endian `u64` words. The order is c0 before c1, x before y.
4. The extraction: Charon's reading of the crate's MIR, and Aeneas's translation of it into `lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`. Charon compiles the crate with its own pinned nightly, nightly-2026-02-07, not the workspace's Rust 1.91.0. `lean/extract.sh` runs both tools at the Aeneas commit that `lean/lake-manifest.json` pins, `d9733413`, with Charon at the commit that Aeneas pins, `ed22146b`.
5. Aeneas's Lean library at the same commit. It models Rust's integers, arrays and slices, with their overflow and bounds checks, and defines `loop` as a `partial_fixpoint`.
6. The 15 hand-written externals in `lean/LeanBlsSimd/Extracted/TypesExternal.lean` and `FunsExternal.lean`. They stand for the items that Aeneas does not translate: the type `__m512i`, defined as the model's `M512`; the 12 AVX-512 intrinsics; `fp8::lanes`, a `transmute`; and blst's `Default` for `blst_p2_affine`. Each intrinsic returns its definition in `lean/LeanBlsSimd/Model/Intrinsics.lean`, written by hand from the Intel SDM and the `core::arch` of Rust 1.91.0. `fp8::lanes` returns lane `l` as element `l`, and blst 0.3.16 derives a `Default` that sets every limb to 0.
7. Manual review that the headline theorem's left side matches how `decompress_g2_chunk` in `lib.rs` consumes a lane, and that its right side matches the signature decoding and subgroup checks in `coreVerify`. Neither complete function is modelled here.

The theorem establishes the stated property of the generated Lean code. Transferring that result to Rust requires items 4 to 6; the vector test checks their combined effect on the recorded batches. Execution of the compiled Rust also depends on compilation, linking, ABI, CPU feature detection and hardware, none of which this proof covers. The caller additionally relies on blst for undecided lanes, short chunks and hosts without SIMD support.

## The vector test

`decompress_g2_vectors.txt` holds 105 batches of eight encodings, 840 lanes, with all three masks and every lane's `points` as `decompress` returned them. The batches mix seeded cases from `src/tests/g2_cases.rs`, the generator the crate's own tests use, with hand-picked edge cases: flag combinations, infinity encodings, coordinates at and around p in every word, x with no square root, points outside G2 and of small order, and both early returns, taken and not taken.

Three tests read the file:

- `replay_vectors`, in `vectors.rs`, runs the current kernel on the recorded inputs and fails if any output differs. It runs with the crate's other tests. On x86_64 it skips when the `simd` feature or AVX-512F/IFMA support is unavailable; setting `SILVER_REQUIRE_IFMA` to any value makes that a failure. On other architectures this test target contains no tests, even with that variable set.
- `recorded_matches_blst`, also in `vectors.rs`, checks the recorded outputs against blst. For each lane marked decided in the recording, 716 of the 840, it compares acceptance and any accepted point's limbs with `uncompress_in_g2_blst` on the recorded input. It uses recorded outputs instead of running the kernel, so it needs no IFMA and never skips on x86_64.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model and the generated `decompress` on the same inputs through Lean's compiler. It fails if either output differs from the recording. This requires the Lean toolchain and can take several minutes.

When all three checks pass and `replay_vectors` has run rather than skipped, the Rust, model and generated code agree on every recorded batch. They also agree with blst on acceptance and accepted points for every decided lane in those batches.

Rerun the Lean check when its code, toolchain, dependencies or vector file changes. `replay_vectors` detects changes to the kernel's outputs on these inputs, including `points` on lanes the caller never reads. Unlike the source hashes below, it ignores changes to comments and formatting. The batches do not exercise every possible discrepancy: Scott's two coordinate comparisons, for example, always agree on them, so changing only one comparison can go undetected.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the file, run this from the silver repository root on an x86_64 host with AVX-512F and AVX-512 IFMA:

```sh
cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

`write_vectors` checks the mask expectations attached to each edge batch before writing the file. Some expectations constrain only selected lanes or masks. It also checks acceptance and accepted points against blst on every lane the new kernel marks decided, leaving the file untouched if any check fails.

## The Rust this proof covers

`lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean` contain items generated from the following Rust files in `crates/bls_simd/src`; the model transcribes those items. They come from `main` at commit `017cc38c`, the squash merge of #383, whose commit date is 2026-10-09T16:20:32+01:00.

| File | sha256 | git blob |
|---|---|---|
| `lib.rs` | `de8a59bf67aea7a413e916d19a65e93a3ecb53ef538829ab63d069f2a1c67d31` | `6174d1cabd2dd6fef926bbb4e46e816e51f8a93e` |
| `constants.rs` | `ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0` | `975320c4667ced6bb2d87f8a7689e7e1a212d691` |
| `fp8.rs` | `bc900b65daf13d1e4b45e025f57eb3ebb5a2fc0a495986d1cbe3a769ed7e7434` | `dddf760e7b44139f9164ec067d3778d4cb09282a` |
| `fp2x8.rs` | `85affbafedca3bf15a85146bdcfe51a072ecde5a151c19fdd0d1ba95d7dd4b01` | `fe9cd24d01e624bad40f68b87bc59285c5c8f113` |
| `g2x8.rs` | `13ff8a6afb7e1f701843fb4da53ae698a5033db38e567fccf00e30be0ee84d00` | `684629e2239fe98f65c64101725cf7f9573548ca` |
| `decompress_g2.rs` | `af44730b948e574b0945d4b647f28ff065ddb963d2a4e111b00c384bf9ed566f` | `b16bb0e2e32ff77f547222a745a5d331e2b8776d` |

Only `Membership` and `G2_COMPRESSED_LEN` from `lib.rs` are extracted and modelled. The rest of `lib.rs`, including how `decompress_g2_chunk` consumes a lane, remains outside the proof and requires manual review (trust item 7). The extraction also includes `blst_fp`, `blst_fp2` and `blst_p2_affine` from blst 0.3.16's `src/bindings.rs` in the Cargo registry.

To check for changes since the proof, run this from `crates/bls_simd/src`:

```sh
sha256sum -c <<'EOF'
de8a59bf67aea7a413e916d19a65e93a3ecb53ef538829ab63d069f2a1c67d31  lib.rs
ed9fe69eafbb055b35e9754ec2cace49aeac45df13e4e1a97de7092f3c4fc2b0  constants.rs
bc900b65daf13d1e4b45e025f57eb3ebb5a2fc0a495986d1cbe3a769ed7e7434  fp8.rs
85affbafedca3bf15a85146bdcfe51a072ecde5a151c19fdd0d1ba95d7dd4b01  fp2x8.rs
13ff8a6afb7e1f701843fb4da53ae698a5033db38e567fccf00e30be0ee84d00  g2x8.rs
af44730b948e574b0945d4b647f28ff065ddb963d2a4e111b00c384bf9ed566f  decompress_g2.rs
EOF
```

If a file fails, find its proved version with `git log --all --find-object=<blob>` and diff the two, then check the generated code for drift.

### Regenerating the extraction

`lean/extract.sh` reruns Charon and Aeneas on `crates/bls_simd/src` and compares the result with `lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`. It needs `AENEAS_DIR`, a checkout of [Aeneas](https://github.com/AeneasVerif/aeneas) at the commit that `lean/lake-manifest.json` pins for `aeneas`. In that checkout, `make setup-charon` builds Charon at the commit in `charon-pin`, and `make` builds Aeneas. Charon also needs rustup, which installs its nightly. The script refuses to run if either checkout differs from its pin. It also checks the binaries: Aeneas reports the commit it was built from, but Charon reports only its crate version, so a Charon binary built from another commit with the same version would pass. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Aeneas records each item's origin in a `Source: '<file>', lines <span>` comment. The comparison ignores the line numbers in these comments and compares everything else exactly, including comment delimiters. A Rust edit that only moves these source locations therefore produces no reported drift. With `--check`, the script does not replace the generated files: it prints any other difference and exits 1, or exits 0 when there is none.

If the generated code has drifted, run `./extract.sh` without `--check`, which replaces `Types.lean` and `Funs.lean`, and follow `lean/README.md`. Rebuild and fix the refinement proofs in `lean/LeanBlsSimd/Refines/` that break. Update the model and `Proofs/` only where the change alters behaviour. Then rerun the controls, the Lean differential test and the Rust vector tests (`replay_vectors` and `recorded_matches_blst`), and update the table above. A passing vector test does not replace the drift check, since it covers only the recorded inputs.

## Building and checking the proof

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; run it from `lean/`. Lean imports those files without rechecking Mathlib's proofs. Building Mathlib from source avoids reliance on those prebuilt artifacts.

`lake build` compiles Aeneas's Lean library and the proof, then runs the axiom guard. Aeneas's library prints five `declaration uses 'sorry'` warnings; the guard checks that none of the declarations it covers depend on those `sorry`s. The build's last lines report the theorem count, the checked `silver_bls_simd.decompress_g2.decompress`, and `axioms used: [propext, Quot.sound, Classical.choice]`. Allow several minutes for the first build and roughly 8 GB for `.lake/`.

Negative controls check that selected mutations are rejected. Other controls check concrete inputs and the axiom list. Every file must exit 0:

```sh
(
  for f in controls/*.lean; do
    lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false "$f" || exit 1
  done
)
```

| File | Shows |
|---|---|
| `Guard.lean` | The axiom guard rejects `native_decide`, `bv_decide` and `Lean.ofReduceBool`. |
| `G1Consumer.lean` | A downstream module imports only the G1 public theorem, applies it with arbitrary externals, and constructs an instance satisfying its blst hypothesis. |
| `Statements.lean`, `Limbs.lean`, `Fp8.lean`, `G2Group.lean`, `Decompress.lean` | A mutated constant, formula, carry or mask breaks the proof that uses it. |
| `Generator.lean` | −z, or a wrong ψ constant, breaks `psi_generator`. |
| `ScottCardinality.lean` | The generator's order is not r²; dropping either Hasse bound makes the numerical exclusion of multiples of r² false. |
| `CharacterSums.lean` | Scott soundness and completeness together; zero, cube and noncube fibers over F₇; the affine point count over F₅; and a counterexample to the Jacobi norm identity for trivial characters. |
| `Kernel.lean` | Checks the input premises and conclusions on concrete batches, including the generator's batch. These examples need no Scott completeness assumption, but do not prove completeness for arbitrary inputs. |
| `Refines.lean` | A mutated generated function fails its refinement proof: swapped coordinates or operands, a wrong row, lane order, word order or loop start, or a missing addition. For five of the eight mutants, a proof checked by Lean's kernel shows that the mutated claim is false; for `times_minus_z`, it refutes the claim about one loop step instead. |
| `AxiomLog.lean` | Prints the axioms of every theorem. |

The Lean side of the vector test, also from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt
```

It exits 0 when every value matches, 1 on an output mismatch or an extracted computation returning `fail` or `div`, and 2 on invalid arguments or an unreadable, malformed or incomplete file. Building the executable for the first time can take several additional minutes.

| Path under `lean/` | Content |
|---|---|
| `lean-toolchain`, `lakefile.toml`, `lake-manifest.json` | Lean and dependency pins: Lean v4.29.1, Mathlib v4.29.1, ethereum/cryptography-specs at `d1331f02` and Aeneas at `d973341320c1` (`backends/lean`). `lakefile.toml` also sets `autoImplicit` and `relaxedAutoImplicit` to `false`. The manifest records exact resolved revisions; `extract.sh` reads the Aeneas pin from it. |
| `LeanBlsSimd/Constants.lean` | p, r, z, R, and the Rust's constant tables proved equal to their derivations. |
| `LeanBlsSimd/Spec/` | Fp2 as a field, E′, ψ, Scott soundness and completeness, the character-sum point-count bound, both square roots, the G2 group law, and the generator check. |
| `LeanBlsSimd/Extracted/` | The Lean code that Aeneas generates from the Rust, `Types.lean` and `Funs.lean`, never edited by hand; and the 15 hand-written externals, in `TypesExternal.lean` and `FunsExternal.lean`. |
| `LeanBlsSimd/Model/` | The Rust, transcribed by hand: the proved intermediate step between the generated code and the specification. |
| `LeanBlsSimd/Proofs/` | The model against the specification, ending in `Kernel.lean`. |
| `LeanBlsSimd/Refines/` | The generated code against the model, function by function, with the conditional correctness API in `Kernel.lean` and the headline theorem in `Complete.lean`. |
| `LeanBlsSimd/Axioms.lean` | The axiom guard. |
| `controls/` | Negative controls and the axiom log. |
| `Test/Main.lean` | The Lean side of the vector test; its docstring gives the file format. |
| `extract.sh` | Regenerates `LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`, or checks them for drift. |
