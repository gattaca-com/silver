# Formal proof of BLS decoding and KZG cell batch verification

One Lean project checks the Charon/Aeneas translation of `silver_crypto_simd`'s
G1 and G2 batch decoders and its `kzg::CellBatchVerifier`. BLS decoding is proved
for all inputs and lengths, with an explicit scalar-blst agreement premise for
specification equality on fallback paths. KZG verification is proved under its
blst operation contracts and that same G1 scalar premise. The statements concern
generated Lean code; the consolidated [trust list](#what-a-reader-must-trust)
explains their connection to Rust and the linked implementation.

The BLS scope is point decoding and subgroup checks, including SIMD kernels,
scalar routes and output writes. It does not include full BLS signature
verification. The KZG scope is `CellBatchVerifier::new` and `verify`, including
repeated calls. Its generated `Default` delegates to `new`. `CellExtender` is
outside the proof's scope.

`silver_crypto_simd.bls.BlsExternals` contains a SIMD observation and the two scalar
decoder observations. `silver_crypto_simd.kzg.KzgExternals` extends it with thirteen
operation fields. BLS-only consumers supply only `BlsExternals`; generated KZG
functions use only `KzgExternals`, obtaining the same scalar decoders through
inheritance. The batch G1 decoder is generated and proved, so KZG calls it directly
rather than relying on an external slice-decoder contract.

The library and Lake package retain the names `LeanBlsSimd` and `lean_bls_simd`.
[The maintenance guide](lean/README.md) maps source changes to the proofs.

## Reproducing the proof and checks

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; run it from `lean/`. Lean imports those files without rechecking Mathlib's proofs. Building Mathlib from source avoids reliance on those prebuilt artifacts.

`lake build` compiles Aeneas's Lean library and the proof, then runs the axiom guard. Aeneas's library may print `declaration uses 'sorry'` warnings; the guard checks that none of the declarations it covers depend on those `sorry`s. The build's last lines report the theorem count, the checked generated entry points, and `axioms used: [propext, Quot.sound, Classical.choice]`. A cold build also compiles uncached dependencies and needs substantially more time than a rebuild.

Negative controls check that selected mutations are rejected. Other controls check concrete inputs and the axiom list. Every top-level control must exit 0:

```sh
(
  for f in controls/*.lean; do
    lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false "$f" || exit 1
  done
)
```

Run the extraction fixtures separately from the Lean control loop:

```sh
python3 -I controls/extraction-check.py
```

Build the independent downstream package from its own root:

```sh
(cd controls/downstream && lake update && lake build)
```

The Lean side of the vector test, also from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt
python3 Test/check_g1_controls.py
```

The differential executable exits 0 when every value matches, 1 on an output mismatch or an extracted computation returning `fail` or `div`, and 2 on invalid arguments or an unreadable, malformed or incomplete file. The Python entry point runs both `check_g1_controls.py` and `check_g2_controls.py`. They require those exit codes and diagnostics on valid small fixtures with permitted whitespace/comments, corrupted kernel/scalar/wrapper values, truncated input and out-of-range references. G2 also checks corruption of an undecided infinity verdict, missing wrapper cases, count mismatch, wrong limb count and trailing text. Building the executable for the first time can take several additional minutes.

| Path under `lean/` | Content |
|---|---|
| `lean-toolchain`, `lakefile.toml`, `lake-manifest.json` | Lean and dependency pins: Lean v4.29.1, Mathlib v4.29.1, ethereum/cryptography-specs at `d1331f02` and Aeneas at `d973341320c1` (`backends/lean`). `lakefile.toml` also sets `autoImplicit` and `relaxedAutoImplicit` to `false`. The manifest records exact resolved revisions; `extract.sh` reads the Aeneas pin from it. |
| `LeanBlsSimd/Constants.lean` | p, r, z, R, and the Rust's constant tables proved equal to their derivations. |
| `LeanBlsSimd/Spec/` | G1 and G2 Scott soundness and completeness, point-count bounds, generator identities, field and group laws, square roots, G1 KZG encoding bridges, and both groups' affine-layout bridges. |
| `LeanBlsSimd/Extracted/` | The Lean code that Aeneas generates from the Rust, `Types.lean` and `Funs.lean`, never edited by hand; and the hand-written external definitions in `TypesExternal.lean` and `FunsExternal.lean`. |
| `LeanBlsSimd/Model/` | The Rust, transcribed by hand: the proved intermediate step between the generated code and the specification. |
| `LeanBlsSimd/Proofs/` | The model against the specification, including G1's `DecompressG1.lean`, G2's `Kernel.lean` and the G2 wrapper verdict bridge in `UncompressG2.lean`. |
| `LeanBlsSimd/Refines/` | The generated code against the model, function by function, with public wrapper APIs in `UncompressG1.lean` and `UncompressG2.lean`, both length-mismatch theorems in `WrapperLengths.lean`, and G2's kernel headline in `Complete.lean`. |
| `LeanBlsSimd/Kzg/` | KZG specification decomposition, setup certificates, decoder bridge, representation laws, verifier refinements and public statements. |
| `LeanBlsSimd/Axioms.lean` | The common axiom guard for BLS and KZG. |
| `controls/` | Negative controls and the axiom log. |
| `Test/Main.lean`, `Test/Differential/` | The differential CLI, shared parser and separate G1/G2 checks; the G1/G2 module docstrings describe the formats. |
| `Test/check_g1_controls.py`, `Test/check_g2_controls.py` | Positive formatting and negative value/parser controls for both differential runners; the G1 entry point runs both groups for CI. |
| `extract.sh` | Regenerates `LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`, or checks them for drift. |

From the repository root, fetch the KZG specification vectors and run the crate's
Rust checks, including comparison with the c-kzg reference implementation:

```sh
make -C crates/crypto_simd
SILVER_REQUIRE_IFMA=1 cargo test --locked -p silver_crypto_simd --all-features
```

The IFMA requirement applies to the BLS kernel checks on a supported x86_64 host.
Lean jobs can use substantial memory; run one at a time. The default build and the
controls must be rebuilt after changing an import before their results are used.

### Reproducing the extraction

`lean/extract.sh` reruns Charon and Aeneas on the `silver_crypto_simd` crate and compares the result with `lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`. It needs `AENEAS_DIR`, a checkout of [Aeneas](https://github.com/AeneasVerif/aeneas) at the commit that `lean/lake-manifest.json` pins for `aeneas`. In that checkout, `make setup-charon` builds Charon at the commit in `charon-pin`, and `make` builds Aeneas. Charon also needs rustup, which installs its nightly. The script refuses to run if either checkout differs from its pin. It also checks the binaries: Aeneas reports the commit it was built from, but Charon reports only its crate version, so a Charon binary built from another commit with the same version would pass. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Aeneas records each item's origin in a `Source: '<file>', lines <span>` comment. The comparison ignores the line numbers in these comments and compares everything else exactly, including comment delimiters. A Rust edit that only moves these source locations therefore produces no reported drift. With `--check`, the script does not replace the generated files: it prints any other difference and exits 1, or exits 0 when there is none.

If the generated code has drifted, run `./extract.sh` without `--check`, which replaces `Types.lean` and `Funs.lean`, and follow `lean/README.md`. Rebuild and fix the affected BLS or KZG refinements. Update the models and specification proofs where behaviour changes. Then rerun the controls, Lean differential tests and Rust checks, and update the BLS source table below when its files change. A passing vector test does not replace the drift check, since it covers only the recorded inputs.

The extraction roots are `crate::bls::decompress_g2::decompress`,
`crate::bls::uncompress_in_g1`, `crate::bls::uncompress_in_g2` and
`crate::kzg::verify`. The last root reaches the constructor and verifier; individual
`kzg::blst_ops` functions remain opaque. `prepare-extraction.py` then:

- scopes BLS definitions over `BlsExternals` and KZG definitions over its child
  `KzgExternals`, so the latter inherit a single BLS dictionary;
- quotes exactly six generated `full` identifiers;
- supplies structural `Array.make` length witnesses, including at BLS sites;
- hoists exactly 64 G1 setup rows without changing their terms, order or outer type.

All adaptations run before the drift comparison. Only numeric source spans are
masked; the rest of both generated files is compared exactly. `COMPRESSED_LEN` is
the shared generated pure constant. The handwritten external files are preserved
by regeneration.

## BLS G1 and G2 decoding

The BLS proof establishes correctness of the Lean code generated by Charon and Aeneas from the complete `uncompress_in_g1` and `uncompress_in_g2` wrappers in `silver_crypto_simd::bls`. Both use AVX-512 IFMA to process batches of eight compressed points. The theorems cover output writes, chunks, scalar paths and fallback calls, for every input length and both SIMD settings. Rust filenames below are relative to `crates/crypto_simd/src/bls/` unless stated otherwise.

Each unconditional result gives the specification verdict on decided kernel lanes and the scalar external's result elsewhere. The G2 model uses SIMD availability, the threshold of three inputs per chunk, and padding that repeats the last input. Padding contents are unobservable in the public result by the lane-independence lemma `DecompressG2.decompress_lane_independent`. The refinement proves that padding accesses stay in bounds and that the generated padding equals `chunkAt` exactly, in `UncompressG2.chunk_slice_refines`. Equality with the scalar wrapper on every input additionally requires the group's `BlstMatchesSpec` premise.

On unequal input and output lengths, both generated public wrappers return `fail .assertionFailure`. The generated code drops the Rust panic text, `"one verdict slot per input"`; the mismatch theorems express only the generated failure value.

The proof has two parts: the generated code returns exactly the result of a hand-written model, and the model agrees with the specification on every lane the kernel decides. G2's Scott completeness uses a character-sum bound on the curve's point count; G1 uses the elementary finite point-count bound described below. Recorded test vectors also compare the generated code and model with the compiled Rust. Those tests check the translation on particular inputs; they are not a proof of the translation itself.

### Public decoder contracts

#### G1: `uncompress_in_g1`

`UncompressG1.uncompress_in_g1_eq_spec_or_blst` covers the generated public wrapper, including output writes and all scalar fallbacks.

```lean
theorem uncompress_in_g1_eq_spec_or_blst [BlsExternals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG1 inputs.val[i.val])
```

An index uses the kernel's verdict exactly when SIMD is available, the index belongs to a complete eight-input chunk, and the kernel's undecided bit is clear. Every other index uses the scalar external's result. `UncompressG1.uncompress_in_g1_eq_spec` assumes only that the scalar external agrees with the specification on all 48-byte inputs, in addition to the API's equal-length precondition.

The unconditional result is “specification or the scalar external” according to the characterized route. Equality with blst on every index additionally uses `BlstMatchesSpec`.

The G1 specification verdict calls `bytesToKzgProof`, decodes its accepted bytes with `G1.uncompress`, and converts the point to blst's affine layout. The bridge lemmas prove that acceptance agrees with both `bytesToKzgProof` and `bytesToKzgCommitment`. The conversion first calls `G1.toAffine`, then represents each coordinate as six little-endian Montgomery words with R = 2^384. Infinity has both coordinates zero.

The Scott lemmas use σ(x, y) = (βx, y), with β fixed by the kernel's `BETA_MONT`, and the identity σ²(P) = [−z²]P. Completeness uses the spec's generator-order proof and the elementary bound `Nat.card E.Point ≤ 2 * p + 1 < r²`. Formula correctness is conditional on a clear undecided bit; the headline theorem does not require proving that subgroup members always avoid exceptional formulas.

#### G2: `uncompress_in_g2`

`UncompressG2.uncompress_in_g2_eq_spec_or_blst` covers the generated public wrapper:

```lean
theorem uncompress_in_g2_eq_spec_or_blst [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG2 inputs.val[i.val])
```

`usesKernelAt_iff` characterizes the route exactly: SIMD is available, the index is in range, its chunk has at least three inputs, and its lane's undecided bit is clear. Chunks contain at most eight inputs. A short kernel chunk repeats its last input to fill eight lanes; only the original lanes are written back. Smaller chunks, undecided lanes and calls without SIMD use the same scalar external.

Under `UncompressG2.BlstMatchesSpec`, `uncompress_in_g2_eq_spec_list` returns `inputs.val.map specVerdict`, and `uncompress_in_g2_eq_spec_model_list` expresses the result in model types as `inputs.val.map (G2Spec.verdict ∘ ofArray ofU8)`. The pointwise corollary and `uncompress_in_g2_eq_blst` are also available. The premise requires exact agreement on every 96-byte input, including acceptance, affine limbs and infinity.

`G2Spec.verdict` calls the pinned specification's `G2.uncompress` and `G2.inSubgroup`. Its affine conversion calls `G2.toAffine` before writing the coordinates in blst's layout. `G2Spec.verdict_some_iff` and `UncompressG2.specVerdict_some_iff` characterize acceptance and exact limbs. `G2Spec.infinity_verdict` proves that canonical compressed infinity returns `some` of the all-zero affine limbs. The decided-lane bridge `decompress_eq_verdict` uses `G2Spec.blstLimbs_eq_of_z_one` to relate this affine conversion to the kernel's conversion of decoded finite points.

#### G2: `decompress_g2::decompress`


`mod.rs` reads three parts of a `Batch`: `undecided`, `valid`, and `points` on valid lanes. The headline theorem, in `lean/LeanBlsSimd/Refines/Complete.lean`, covers exactly those, lane by lane. It is about `silver_crypto_simd.bls.decompress_g2.decompress`, the Lean function that Aeneas generates from the Rust:

```lean
theorem decompress_extracted_eq_spec_complete (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_crypto_simd.bls.decompress_g2.decompress inputs = ok batch ∧
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

The left side is how `decompress_g2_chunk` in `mod.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

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

- The undecided bit is clear (`hu` in `decompress_eq_spec`): the kernel decides the lane. `mod.rs` sends undecided lanes to blst. The theorem gives no specification result for those lanes, although unconditional refinement still covers their computed fields. The canonical infinity encoding is one such lane.
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

#### Using the public results

The downstream API is `LeanBlsSimd.Refines.UncompressG1`. Its list-form corollary is:

```lean
theorem uncompress_in_g1_eq_spec_list [BlsExternals]
    (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict
```

`BlstMatchesSpec` names the sole external-correctness premise: blst returns `specVerdict` on every 48-byte input. `specVerdict_some_iff` relates an accepted Aeneas point to `bytesToKzgProof` and the decoded point's exact limbs. The pointwise corollary and a model-type list variant are also available.

`controls/G1Consumer.lean` imports only this public module and applies the theorem with arbitrary externals. In the independent package in `controls/downstream/`, `G1Smoke.lean` declares a generic consumer's separate blst structs, proves the list result across those copies, and checks the root external's name collision. Its facade under the example namespace `silver_kzg` reads a downstream-owned external function. A caller in the generated spelling requires only `Fixed.Externals`; the adapter fixes an explicit upstream `BlsExternals` instance and discharges the downstream hypothesis from `BlstMatchesSpec`.

For G2, import `LeanBlsSimd.Refines.UncompressG2` and use `UncompressG2.uncompress_in_g2_eq_spec_list` with `UncompressG2.BlstMatchesSpec`. `controls/G2Consumer.lean` applies both list forms and constructs a specification-backed external for either SIMD setting. `controls/downstream/G2Smoke.lean` transports the result across independently declared Fp2 and affine structs, then checks the same adapter pattern under the `silver_bls` namespace.

### Vector evidence

Rerun the Lean check when its code, toolchain, dependencies or vector file changes.

`decompress_g1_vectors.txt` contains 47 batches (376 lanes), both masks and twelve limbs per kernel point, plus the scalar blst verdict on every lane. Cases include both signs, generator multiples, all five small cofactor prime orders, non-members, non-residues, x at and around p, all flag combinations and malformed infinity.

The same file records 24 wrapper cases in three families at lengths 0, 1, 7, 8, 9, 15, 16 and 17.

The G1 checks are:

- `g1::replay_vectors` runs the G1 replay check.
- `g1::recorded_matches_blst` checks the G1 recording against blst.
- `lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt` checks the model and extraction at both SIMD settings, with recorded scalar results as externals. The generated wrapper starts with nonzero output sentinels. The runner also compares the specification verdict with the recorded blst result on **every** input, including undecided and infinity lanes. This is a finite control on `BlstMatchesSpec`, not a proof of that universal premise.

The pinned specification and blst 0.3.16 agree on canonical compressed infinity: `0xc0` followed by 47 zero bytes is accepted; other infinity encodings are rejected. `validateKzgG1` explicitly allows this encoding, and `G1.uncompress` returns `G1.zero`. blst's `POINTonE1_Uncompress_Z` zeroes the affine output for it, and `blst_p1_affine_in_g1` accepts it. The kernel marks compressed infinity lanes undecided and delegates them to blst. The Lean infinity lemmas prove the specification verdict and kernel fallback behavior; blst agreement also receives a recorded-vector check.

`decompress_g2_vectors.txt` holds 105 batches of eight encodings, 840 lanes, with all three masks, every lane's `points` as `decompress` returned them, and a scalar blst verdict on every lane. The batches mix seeded cases from `src/bls/tests/g2_cases.rs`, the generator the crate's own tests use, with hand-picked edge cases: flag combinations, infinity encodings, coordinates at and around p in every word, x with no square root, points outside G2 and of small order, and both early returns, taken and not taken.

The same file records 39 G2 wrapper cases: member, mixed and rejected families at lengths 0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 15, 16 and 17. Mixed cases include canonical infinity, malformed infinity and rejected encodings. These lengths exercise the threshold, full chunks and tails on both sides of the threshold.

The G2 checks are:

- `replay_vectors`, in `vectors.rs`, runs the current kernel and public wrapper on the recorded inputs and fails if any output differs. The wrapper starts with nonzero output sentinels. It runs with the crate's other tests. On x86_64 it skips when the `simd` feature or AVX-512F/IFMA support is unavailable; setting `SILVER_REQUIRE_IFMA` to any value makes that a failure. On other architectures this test target contains no tests, even with that variable set.
- `recorded_matches_blst`, also in `vectors.rs`, checks the recorded outputs against blst. It checks every recorded scalar verdict against `uncompress_in_g2_blst`, checks wrapper outputs against those verdicts, and compares acceptance and accepted kernel limbs on all 716 decided lanes. It uses recorded outputs instead of running the kernel, so it needs no IFMA and never skips on x86_64.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model and generated kernel on the same inputs through Lean's compiler. It also compares `G2Spec.verdict` with the recorded blst verdict on every input, including undecided and infinity lanes, and checks both SIMD settings of the model and generated wrapper with recorded scalar results as externals and nonzero output sentinels. It fails if any compared value differs. These finite checks do not prove `BlstMatchesSpec`. The runner reports kernel, spec/blst and wrapper times separately; they are test-run timings, not performance benchmarks.

When all three checks pass and `replay_vectors` has run rather than skipped, the Rust, model and generated code agree on every recorded batch. The specification agrees with blst on all recorded inputs, including canonical infinity (`0xc0` followed by 95 zero bytes), whose verdict is `some` of 24 zero limbs. The wrapper checks exercise the recorded cases, while the Lean theorem covers all lengths and inputs under its stated premise.

`replay_vectors` detects changes to the kernel's outputs on these inputs, including `points` on lanes the caller never reads. Unlike the source hashes below, it ignores changes to comments and formatting. The batches do not exercise every possible discrepancy: Scott's two coordinate comparisons, for example, always agree on them, so changing only one comparison can go undetected.

Format details live in `lean/Test/Differential/G1.lean`; G2's format lives in `G2.lean`.

`g1::write_vectors` is the ignored G1 generator.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the files, run this from the silver repository root on an x86_64 host with AVX-512F and AVX-512 IFMA:

```sh
cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

G2's `write_vectors` checks the mask expectations attached to each edge batch before writing the file. Some expectations constrain only selected lanes or masks. Both generators check acceptance and accepted points against blst on every lane the new kernel marks decided, leaving the file untouched if any check fails.

### BLS proof controls

Paths below are relative to `lean/controls/`. The common reproduction commands run these files alongside the KZG controls.

| File | Shows |
|---|---|
| `Guard.lean` | The axiom guard rejects `native_decide`, `bv_decide` and `Lean.ofReduceBool`. |
| `G1.lean` | Concrete G1 constants, routing flags, signs and limb order; skipping canonicality makes the kernel accept a noncanonical encoding of 2G. Also covers full chunks, scalar tails, empty output and arbitrary fallback. |
| `downstream/` | A separate Lake package transports both groups' list results across independently extracted structs, checks a generated-spelling caller with only downstream externals, and guards the root-name collision and proof axiom lists. |
| `G2Wrapper.lean` | Wrong SIMD routing, thresholds, ignoring undecided lanes and dropping accepted kernel results change observable verdicts (the accepted-result mutation is a compiled `#eval`). Tail controls distinguish scalar and kernel routing after a full chunk; reading the chunk's first input on fallback changes the verdict. Rejecting infinity, accepting malformed infinity or returning wrong affine limbs violates `BlstMatchesSpec`; unequal lengths fail. These controls do not claim to observe padding contents. |
| `G2Consumer.lean` | The public G2 list and model corollaries and length mismatch result can be applied from a separate module; a specification-backed external satisfies the universal premise at both SIMD settings. |
| `G1Consumer.lean` | A downstream module imports only the G1 public theorem, applies it with arbitrary externals, and constructs an instance satisfying its blst hypothesis. |
| `Statements.lean` | Changed constants and formulas break their proof scripts, including G1's Scott-membership proof when the model drops the y negation. |
| `Limbs.lean`, `Fp8.lean`, `G2Group.lean`, `Decompress.lean` | A mutated constant, formula, carry or mask breaks the proof that uses it. |
| `Generator.lean` | −z, or a wrong ψ constant, breaks `psi_generator`. |
| `ScottCardinality.lean` | The generator's order is not r²; dropping either Hasse bound makes the numerical exclusion of multiples of r² false. |
| `CharacterSums.lean` | Scott soundness and completeness together; zero, cube and noncube fibers over F₇; the affine point count over F₅; and a counterexample to the Jacobi norm identity for trivial characters. |
| `Kernel.lean` | Checks the input premises and conclusions on concrete batches, including the generator's batch. These examples need no Scott completeness assumption, but do not prove completeness for arbitrary inputs. |
| `Refines.lean` | Mutated generated functions fail their refinement proofs, including G1's chunk fallback reading lane zero instead of the current lane. Concrete refutations cover five complete G2 refinements and the required loop steps for `times_minus_z` and G1's fallback. |
| `AxiomLog.lean` | Prints the axioms of every theorem. |


### Extracted BLS source

`lean/LeanBlsSimd/Extracted/Types.lean` and `Funs.lean` contain items generated from the following Rust files. These content hashes pin the source read by the extraction.

| File | sha256 | git blob |
|---|---|---|
| `mod.rs` | `b0a85004d44096d34032190c2a26f35bf69afa35da4c36c271bdeb738d2771d5` | `099bade6d9bfa27953083b8167571f1da29a5a4e` |
| `constants.rs` | `903c4ea8360c254f1bd048d1be4df95511fd7a6e1db2257f47704e270589449f` | `87190c24741f42bc50d3cae4ed384995cdc15f14` |
| `fp8.rs` | `0ba4b0f9dbc78dfe5032722d46739c58ec91ac86960c1257b201ae9a3d870512` | `11d1dbb2c69b3bd2dad3e502247e0165ef25b9ed` |
| `fp2x8.rs` | `9d5c8b5e87d996b2c374f8c38438c16f171bd8e39cab012267337e8baee5b069` | `951eadde84eca23e2ebe8626bc0382a205497071` |
| `g1x8.rs` | `2063afb8b7b931b44006b7979df3f0846bd0bc4e832ab8728d06735ecb18b7c9` | `ddbd6159490ff0f58b27dbf4b4e63db92bac5391` |
| `g2x8.rs` | `57a02d26fda9dd934c647fe7020e961a6c2efcd1e20ed72a09202cf2ccef7295` | `804ebf1d0e6681d20f07ede1867cef929ebe190c` |
| `decompress.rs` | `718f280500e78890c78b175fe36378b62cf57244b356b6555ede1c829e93e184` | `1a9052c76f9797fd07e760df899ef017aa0adf62` |
| `decompress_g2.rs` | `14df66f6f153149fc329bce2f2229a1f10c190bb9727d1604cd52a552df82cb8` | `e8f7d7cef432288936367f602a7b79838095bead` |

G1 coverage includes `uncompress_in_g1`, `decompress_g1_chunk`, the decoder, group operations and shared arithmetic. Feature detection and the scalar blst wrapper remain the explicit trusted externals. G2 coverage includes `uncompress_in_g2`, `decompress_g2_chunk`, the decoder, group operations and shared arithmetic. The G2 wrapper refinement proves the chunk routing, padding bounds, fallback calls and output writes. The correspondence to `coreVerify` is described in the consolidated trust list. The extraction also includes blst 0.3.16's field and affine structures from `src/bindings.rs`.

To check for changes since the proof, run this from `crates/crypto_simd/src/bls`:

```sh
sha256sum -c <<'EOF'
b0a85004d44096d34032190c2a26f35bf69afa35da4c36c271bdeb738d2771d5  mod.rs
903c4ea8360c254f1bd048d1be4df95511fd7a6e1db2257f47704e270589449f  constants.rs
0ba4b0f9dbc78dfe5032722d46739c58ec91ac86960c1257b201ae9a3d870512  fp8.rs
9d5c8b5e87d996b2c374f8c38438c16f171bd8e39cab012267337e8baee5b069  fp2x8.rs
2063afb8b7b931b44006b7979df3f0846bd0bc4e832ab8728d06735ecb18b7c9  g1x8.rs
57a02d26fda9dd934c647fe7020e961a6c2efcd1e20ed72a09202cf2ccef7295  g2x8.rs
718f280500e78890c78b175fe36378b62cf57244b356b6555ede1c829e93e184  decompress.rs
14df66f6f153149fc329bce2f2229a1f10c190bb9727d1604cd52a552df82cb8  decompress_g2.rs
EOF
```

If a file fails, find its proved version with `git log --all --find-object=<blob>` and diff the two, then check the generated code for drift.

## KZG cell batch verification

`LeanBlsSimd.Kzg.verify_eq_spec` states that the generated constructor returns
`ok` with an initialized invariant, and every invariant-satisfying verifier state
returns the embedded specification's Boolean verdict on every representable input.
The next state preserves the invariant, so the theorem covers repeated calls,
including calls after rejected batches. Specification errors become `false`.
Length mismatches, invalid encodings and out-of-range indices are included.

```lean
theorem verify_eq_spec [e : KzgExternals] (hblst : BlstCorrect e)
    (hg1 : UncompressG1.BlstMatchesSpec) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        Model.rejectErrors i.embeddedSpec = verdict
```

The headline takes `[e : KzgExternals]`, `(hblst : BlstCorrect e)` and
`(hg1 : UncompressG1.BlstMatchesSpec)`. `BlstCorrect` covers the thirteen KZG
operations and G2 decoding at the two embedded setup constants. A consumer with
full G2 scalar agreement can discharge the latter via
`g2_decode_of_blstMatchesSpec`; the KZG headline requires only the two-input law.

`verify_eq_upstream` has the same execution and state conclusion for the literal
upstream `verifyCellKzgProofBatch` action. It additionally requires
`TrustedSetup.get! = pure embeddedSetup`. The principal embedded-setup theorem has
no runtime-loader premise. The same distinction applies to `model_eq_embedded_spec`
and `model_eq_spec`.

A fixed dictionary `e` is quantified over the complete KZG statement. Equality to
the specification holds for either value of its SIMD flag. The BLS theorem models
one SIMD observation per decoder call; the KZG theorem does not formalize arbitrary
changes to that observation between calls.

### Input and runtime scope

The input premise states Rust's slice-size restriction in bytes: each slice occupies
at most `isize::MAX` bytes. It imposes no application-level batch-size limit.
Aeneas models logical vectors and execution results, not heap availability or process
termination caused by allocation failure.
Rust also rejects capacities above `isize::MAX` bytes before Aeneas's logical
`Usize.max` element bound. The challenge preimage uses `48 + 48u + 2112n` bytes,
where `u` is the number of unique commitments and `n` the number of cells. Near
`isize::MAX/2048` cells it can exceed Rust's capacity limit even though the input
slices satisfy the premise. These physically unreachable inputs can panic with
"capacity overflow" in Rust. The theorem does not exclude them by an extra premise
and does not establish absence of Rust allocation or capacity panics.

### Shared decoder bridge and consistent contracts

`Kzg/Decoder.lean` proves `specVerdict_eq_bls`: the KZG and BLS verdicts are equal
as optional affine points, including all limbs and infinity. Both validate with
`bytesToKzgProof`, decode the accepted bytes and normalize through `G1.toAffine`.
`g1DecoderCorrect_of_blstMatchesSpec` applies the BLS list theorem directly to the
generated G1 decoder. Consequently `G1DecoderCorrect` is derived from the scalar
premise, and is not an additional headline assumption. There is one shared scalar
G1 observation and one generated batch implementation, with no separate extraction
or copied blst structures at this sibling-module boundary.

`Kzg/SpecExternals.lean` defines `specExternals` from specification functions and
proves `specExternals_correct`: `BlstCorrect` and both groups' full scalar contracts
hold together for its inherited BLS dictionary. This witnesses joint consistency
of the premises; a specification-backed dictionary is not a proof of blst itself.

### Verifier proof structure

| Selected files under `lean/LeanBlsSimd/Kzg/` | Role |
|---|---|
| `Representation.lean` | Byte, Montgomery-limb, affine and Jacobian interpretations |
| `Externals.lean`, `SpecExternals.lean` | External contracts and a joint specification-backed witness |
| `Model.lean` | Spec decomposition, column-aggregated IFFT and intermediate computations |
| `IOLawful.lean` | Monad laws missing from Lean v4.29.1's IO interface |
| `SpecBridge.lean` | Full-result correspondence between the pure model and upstream |
| `SetupArithmetic.lean`, `SetupPoints.lean` | Kernel-checked decoding and subgroup certificates for the embedded points |
| `Setup.lean` | Embedded-byte connection and persistent-state invariant |
| `PolynomialModel.lean`, `PolynomialArithmetic.lean`, `PolynomialInterpolation.lean` | Exact coefficient-array sizes and their polynomial interpretations |
| `CosetPolynomial.lean`, `ColumnPolynomial.lean`, `InterpolationIdentity.lean` | Coset IFFT correctness and weighted column interpolation |
| `ModelSpec.lean` | Input invariants and full-result spec equivalence |
| `Statements.lean` | T0a, T0b, T1, T2, construction, refinement and headline theorems |
| `Refines.lean` | Supporting statements for decoding, challenge, roots, IFFT and pairing inputs |
| `Refines/` | Proofs for the extracted functions and shared loop lemmas |
| `Decoder.lean` | Direct composition with the shared BLS decoder proofs |
| `G1Bridge.lean` | Generic transport theorem for independent extractions; the shared verifier uses `Decoder.lean` |

`column_ifft_eq_interpolation` states T1 for aligned arrays, 64 field elements per cell
and indices below 128. These are intermediate invariants established by the front
half, not new assumptions on untrusted inputs. `spec_eq_column_ifft` states T2 for all
spec inputs, preserving both the Boolean and errors as `KzgM` actions.
`RliInputs` retains equality of the powers and index lengths: T1 could omit it,
but the front half establishes it and the refinement uses aligned batches.
The proofs establish index bounds and compression/decompression round trips
explicitly; Lean's logical `get!` and panic fallback values do not certify that
the executable avoids those branches.

The challenge preimage proof matches upstream's serialization of decoded cells.
The inverse FFT proof covers the generated recursive transform and scaling.
The aggregation, bit-reversed column copy and shift-add loops are proved separately;
`InterpolationModel.lean` proves that their pure composition equals `columnRli`,
including skipped zero columns. The interpolation commitment and pairing proofs
compose these loops with the external group-operation contracts.
`ModelPairing.lean` proves the corresponding pure-model computation, including
successful compression round trips and empty linear combinations.
`glue_refinement` combines every generated verifier branch with that model and
preserves the state invariant, under the reviewed external and slice-size premises.
`InterpolationIdentity.lean` proves that the column IFFT equals the spec's per-cell
interpolation. It interprets coefficient arrays as Mathlib polynomials, relates the
spec interpolation loops to Lagrange interpolation, and proves the shifted IFFT
has the same evaluations at all 64 distinct coset nodes. Interpolation linearity
then regroups the weighted cells by column. Both arrays retain size 64, so polynomial
injectivity recovers exact array equality, including trailing zero coefficients.
`ModelSpec.lean` derives the intermediate shape contract from successful decoding
and replaces the interpolation step while preserving the full `Except` result and
arbitrary setup-loader actions. These proofs establish `column_ifft_eq_interpolation` (T1) and `spec_eq_column_ifft` (T2).

### Field and point representations

`frEncode` uses four little-endian 64-bit limbs for the reduced Montgomery residue
`x * 2^256 mod r`. Scalar laws apply to this encoding, not arbitrary limb arrays.
The extraction and representation target blst's 64-bit platform layout,
`limb_t = u64`; they do not describe a 32-bit-limb build.
The v0.3.16 source audit covered `blst/src/exports.c`'s Fr wrappers, the final
conditional subtraction in `blst/src/no_asm.h::mul_mont_n` and `add_mod_n`, the
corresponding x86-64 ADX assembly, and `blst/src/recip.c::reciprocal_fr`. Addition,
subtraction and Montgomery multiplication preserve reduction on reduced inputs.
`blst_fr_from_scalar` also handles a full 256-bit SHA-256 digest: its other operand
is the reduced Montgomery conversion constant, so the product is below `r * 2^256`.
These are reviewed external semantics, not a formal proof of blst.

`G1Rep` relates a Jacobian result to the spec by its infinity status and affine
coordinates. It does not require blst and the spec to choose the same Jacobian
representative. Affine coordinates use six reduced Montgomery limbs with `R = 2^384`.
The pairing contract calls the spec's `pairingCheck`; both implementations omit pairs
with either a G1 or a G2 point at infinity. `hash` uses the spec's SHA-256 through `Fr.hashToBlsField`,
and `fr_bytes` rejects field encodings greater than or equal to `r`.
`g1_affine` retains its `G1Valid` premise so the trusted law covers only the
verifier's valid-point call sites. `G1Valid` checks subgroup membership on the
Jacobian representative. `G1Validity.lean` transports this predicate through
`G1Rep`, including arbitrary infinity representatives such as blst's all-zero
triple, and proves that valid points have valid affine encodings.
`G1Arithmetic.lean` proves closure and point equivalence for addition, negation,
doubling and scalar multiplication under the same validity predicate.
`G1Msm.lean` extends these results to multi-scalar multiplication, using upstream's
weighted-sum theorem after normalizing infinity inputs.
`G1Compression.lean` proves successful decompression after compression of a valid
point, preserving infinity status and affine coordinates. Its header-bit certificate
uses kernel reduction over 32 values. `PairingRepresentation.lean` transports the
pairing inputs across these representative changes.

### Setup connection

`embeddedSetup` is the pinned spec's private `TrustedSetup.buildEmbedded` value,
accessed with Batteries' `open private`. `embedded_setup_matches` proves equality
of the 64 G1 compressed encodings used by the verifier, successful G2 decodes at
indices 0 and 64, subgroup membership and successful G1 validation.

The proof compares the Rust constants directly with the pinned spec's embedded
data. `SetupPoints.lean` checks explicit witnesses for all 64 G1 points and both
G2 points. Structural exponentiation and scalar multiplication reduce in the
kernel, with general lemmas relating them to the spec operations. The certificate
uses only the three standard axioms and needs no separate setup-file assumption.
Relating the pinned spec's data to Ethereum's intended ceremony remains part of
trusting the specification.

### KZG specification and controls

The target is the pinned `EthCryptographySpecs.Kzg.verifyCellKzgProofBatch`.
Cryptography-specs vectors execute that Lean specification; tests against them
supply finite implementation evidence, while differential tests compare with the
c-kzg reference implementation. Neither replaces the universal Lean theorem or
its external premises. Vector cases for `CellExtender` do not extend the proof's
scope.

The top-level `controls/Kzg*.lean` files check the concrete spec instance,
representations, setup and scoped axiom lists. Their negative controls corrupt
each external law separately, including G1 output
writes. Mathematical controls distinguish bit reversal, inverse coset shifting
and inverse FFT scaling. The setup control rejects a changed embedded G2 point.
The pairing control corrupts the specification's Boolean result symbolically:
its Miller-loop `while` loops use `Lean.Loop.forIn`, opaque in Lean's logic, so
these controls do not kernel-evaluate the pairing. Extraction controls accept
source-span changes and reject changed setup-row order or added declarations.
The common axiom guard checks the theorem dependencies, generated entry points
and concrete contract witness.

## What a reader must trust

1. **Lean and dependencies.** Lean v4.29.1's kernel and only `propext`,
   `Classical.choice` and `Quot.sound`. `LeanBlsSimd/Axioms.lean` checks the imported
   BLS and KZG theorems, generated entry points and their transitive dependencies.
   `acceptedAxioms` is empty; `sorryAx`, `native_decide` and `bv_decide` dependencies
   are rejected. Aeneas's library can contain unrelated proof placeholders without
   those entering the checked closure. Using `lake exe cache get` additionally
   trusts downloaded Mathlib `.olean` artifacts, which Lean imports without
   rechecking their proofs; building Mathlib from source avoids that reliance.
2. **Specification and mathematics.** Mathlib v4.29.1 and
   [ethereum/cryptography-specs at `d1331f02`](https://github.com/ethereum/cryptography-specs/tree/d1331f02e308fe6d0aedda8601e4d5b0fc360318),
   including its field, group law, decoders, subgroup checks, KZG validation and
   cell-batch specification, and their fidelity to Ethereum's requirements.
   Agreement with vectors is finite evidence, not a proof of equivalence to other
   specifications or of the provenance of the embedded ceremony data.
3. **Input and output interpretation.** `ofArray`, `ofU8`, `ofBatch` and the affine
   conversions preserve bit-vectors, lanes and fields. Coordinates use six
   little-endian 64-bit Montgomery limbs with R = 2^384; G2 orders c0 before c1
   and x before y. G1 and G2 public verdicts normalize through `toAffine`, including
   all-zero infinity. The G2 kernel conversion reads projective x/y; its bridge to
   the normalized verdict is proved for decoded finite points with z = 1.
   KZG's reduced scalar encoding uses four 64-bit Montgomery limbs with R = 2^256.
   The representation targets blst's 64-bit platform layout.
4. **Extraction and generated-code preparation.** Charon's MIR semantics, Aeneas's
   translation and the deterministic adaptations in `prepare-extraction.py`
   described above. The pinned Aeneas revision is `d9733413`, Charon is `ed22146b`,
   and Charon uses nightly-2026-02-07 rather than the workspace's Rust 1.91.0.
   `extract.sh` verifies checkout pins and available binary version information;
   a Charon binary from another commit with the same reported crate version is
   not distinguished. The extraction uses the x86_64 chunk helpers. Transfer to
   targets selecting other helpers relies on feature detection selecting the
   scalar route. Exact `--check` reproduction detects drift, not translator bugs.
5. **External semantics and bindings.** Aeneas's pinned Lean library models
   integers, arrays, slices, bounds/overflow checks and `partial_fixpoint` loops.
   The handwritten definitions in `Extracted/TypesExternal.lean` and
   `FunsExternal.lean` bind the vector type, twelve AVX-512 intrinsics, lane
   extraction, affine defaults, feature detection, scalar wrappers, KZG dictionary
   fields, cloning, vector defaults and `u32` stepping. Intrinsics implement the
   Intel SDM/Rust `core::arch` model; lane extraction preserves order and defaults
   zero every limb. `LincombScratch.new` and `COMPRESSED_LEN` are generated.
6. **Shared scalar and SIMD observations.** `BlsExternals` supplies an arbitrary
   Boolean and deterministic total scalar functions. `uncompressG1` has the full
   48-byte agreement law `UncompressG1.BlstMatchesSpec` for G1 specification
   equality, including KZG. `uncompressG2` has the full 96-byte law
   `UncompressG2.BlstMatchesSpec` for G2 specification equality; KZG's
   `BlstCorrect.g2_decode` requires that same observation to agree only at
   `G2_MONOMIAL_0` and `G2_MONOMIAL_64`. Each law covers acceptance, exact affine
   limbs and infinity. The scalar wrappers return `ok`, trusting termination and
   absence of Rust-level failure, and use the same function on every fallback.
   Without the scalar law the BLS result still characterizes specification
   verdicts on decided kernel lanes and scalar verdicts elsewhere. Each BLS call
   reads feature detection once after checking lengths; this does not assert
   stability between calls. KZG fixes the inherited observation for its theorem.
7. **KZG operation contracts.** `BlstCorrect` assumes the thirteen `blst_ops` laws
   for scalar arithmetic/conversion, SHA-256 hashing, group operations, linear
   combination and pairing. Laws apply at the stated representation and validity
   premises; inversion needs a nonzero field element. Jacobian results need only
   represent the same point, and scratch threading is retained. The specification
   pairing has opaque loop semantics, so neither the kernel certificates nor the
   controls prove blst's implementation. The joint `specExternals_correct` witness
   rules out contradictory contracts, but the linked blst implementation remains
   an external assumption.
8. **Runtime setup for literal-upstream corollaries.** Only `verify_eq_upstream`
   and `model_eq_spec` require `TrustedSetup.get! = pure embeddedSetup`, including
   that no importer changes the public `TrustedSetup.globalRef`. The initialized
   reference and `ST.Prim.Ref.get` are opaque in Lean. The embedded-setup theorem
   instead uses the explicit value and the proved embedded-byte certificates.
9. **G2 signature-decoding correspondence.** Manual review connects
   `G2Spec.verdict` to the private decoding stage of `coreVerify`: its fixed-size
   type supplies length 96, then it calls `G2.uncompress` and `G2.inSubgroup`.
   The stage accepts canonical infinity. Public-key validation, hash-to-curve and
   pairing in full signature verification are outside this proof.

Compiled Rust additionally depends on the compiler, linking, ABI, CPU detection
and hardware. The theorem describes Aeneas execution results; it does not prove
absence of allocation failures or capacity panics, as detailed in the KZG runtime
scope above. `CellExtender` is excluded.
