# Maintaining the shared BLS and KZG proof

One extraction and one Lake project cover BLS decoding, KZG cell batch verification and cell extension. [The parent README](../README.md) states their contracts, scope and consolidated trust boundary. See [common setup](#common-reproduction-and-extraction), [BLS maintenance](#bls-decoding-maintenance) or [KZG maintenance](#kzg-maintenance). Use this directory for Lake commands and `extract.sh`; run Cargo commands from the silver repository root.

## Claims

The generated x86_64 APIs cover BLS decoding and subgroup checks, KZG batch verification, and cell extension through both the Fr FFT kernel and scalar fallback. The extender's single `compute_eq_spec` theorem includes canonicality, exact cell bytes, unchanged cells on rejection, construction and repeated calls. See the [full statements](../README.md#what-is-proved) for their premises and runtime scope.

## Usage

Import `LeanBlsSimd.Kzg.Extender.Statements` for cell extension and `LeanBlsSimd.Kzg.Statements` for verification. BLS consumers use the public `Refines.UncompressG1` and `Refines.UncompressG2` modules. The [consumer examples](../README.md#using-the-public-results) show how to supply CPU feature observations and the named generated-component correctness premises. Only G2 signature fallback requires an opaque decoder observation.

## Trust

The [shared trust list](../README.md#what-a-reader-must-trust) covers extraction, dependencies, intrinsic models, component premises and runtime behavior. The verifier takes seven named propositions about actual generated functions: `FrCorrect`, `FrBytesCorrect`, `ShaCorrect`, `PortableFpCorrect`, `G1DecoderCorrect`, `PortableMsmCorrect` and `PairingCorrect`. These remain proof obligations, not axioms or completed implementation proofs. The extender takes only `FrCorrect` and `FrBytesCorrect`; its constructor needs `FrCorrect` alone. Its internal kernel computation needs neither premise after its invariant is established.

`RuntimeFeatures` separates SIMD, SHA and BMI2 observations. The intrinsic boundary includes AVX-512, SHA/SSE and carry operations, plus Aeneas's byte and collection semantics. `BlsExternals` contains only the G2 decoder for signatures; G1 and KZG use generated portable implementations. The extraction targets x86_64; other target configurations are not separately extracted here. The pinned `gattaca-com/EthLib` fork supplies total pairing definitions on Lean and Mathlib v4.29.1.

## Common reproduction and extraction

```sh
lake exe cache get
lake build
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
python3 -I controls/extraction-check.py
```

Run one Lean job at a time. A cold build also compiles uncached Aeneas and specification modules. The [parent README](../README.md#reproducing-the-proof-and-checks) explains the default build and its guard reports.

`extract.sh` checks tool pins and starts from the three BLS roots, `crate::kzg::verify` and `crate::kzg::cell_extender`. Portable field, scalar, G1, MSM, pairing and streaming SHA functions are extracted. Only the signature path's G2 decoder remains opaque. `prepare-extraction.py` introduces `RuntimeFeatures` and G2-only `BlsExternals` parameters; Lean retains each parameter only where the definition uses it.

Preparation quotes the eight generated `full` identifiers and supplies structural `Array.make` length witnesses. It recursively hoists G1 rows and pairing steps/lanes into `Extracted/Literals.lean`, preserving their types, order and contents. It validates required verifier/extender entries and literal structure. All adaptations run before `--check`, which compares complete `Types.lean`, `Literals.lean` and `Funs.lean` after masking only numeric source spans. The explicit Rust `Fp2::new` helper makes the nested pairing-table write translate to the intended Fp2 value.

After changing any import, rebuild its artifacts before running controls. The parent README lists the control loop, downstream build, differential runner and Rust checks. `controls/extraction-check.py` tests the drift boundary, including missing and duplicated entry points, literal mutations and harmless source-span changes. `controls/ExtractedLiterals.lean` checks the hoisted values against their extracted literals. The real-tool `--check` is a separate required check.

### Working in Lean

- `lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false <file>` checks one file with the project's elaboration options, using the built versions of its imports. After changing an imported file, run `lake build` first.
- Never edit `Extracted/Types.lean`, `Extracted/Literals.lean` or `Extracted/Funs.lean`; regenerate them. Importing Aeneas makes `name` a keyword.
- A refinement theorem has the form `gen args = ok (toX (model (ofX args)))`. It rewrites a generated call for any arguments; the round-trip lemmas in `Refines/Basic.lean` then cancel nested conversions. Prefer explicit rewrite lemmas and `simp` when comparing large terms. Trying to close a mismatched goal by unfolding definitions can obscure the difference or exhaust Lean's resource limits.
- Keep each proof well inside the default of 200000 heartbeats, or set explicit headroom with a comment saying why. `#count_heartbeats` under-reports unless `set_option Elab.async false in` precedes it.
- When two sides hold the same large model term with arguments in different forms, unification can unfold the model function and evaluate it. The reduction and square refinements keep their row steps locally irreducible for this reason. `simp only`, `unfold` and `rw` still reach their bodies there, but a proof step that relies on unification, such as `rfl`, can exhaust heartbeats at `whnf` when it needs that unfolding.
- Use the same dimension expression on both sides of array/vector conversions. For example, keep `2 * LIMBS + 1` throughout an accumulator refinement; `simp` may not unfold the dimension definitions when matching a round-trip lemma.
- `get_elem_tactic` can time out in large contexts; give index bounds explicitly.

### Controls and axioms

`acceptedAxioms` remains empty: the complete BLS and KZG proof closures use only `propext`, `Classical.choice` and `Quot.sound`.

- In a control, close the mutated proof with `ring1` or `module`, never `ring`. `ring` can leave a goal open without throwing, so `fail_if_success` may treat the tactic as successful and reject the control. `ring1` throws when it cannot close the goal. `fail_if_success` accepts any failure, so after writing or changing a control, remove the wrapper once and check that the error is the one the control names.
- The guard rejects dependencies on axioms other than `propext`, `Classical.choice` and `Quot.sound`. This includes the axioms introduced by `native_decide` and `bv_decide`. Extending `acceptedAxioms` in `LeanBlsSimd/Axioms.lean` changes the proof's trust assumptions; it requires a documented justification and a corresponding update to the parent README. Use `#print axioms <theorem>` to inspect one theorem or `controls/AxiomLog.lean` for the library's theorems.
- Aeneas's library may print `declaration uses 'sorry'` warnings while it builds. A `sorry` adds the axiom `sorryAx`, so the guard also shows that the checked generated entry points and every imported theorem avoid them.

## BLS decoding maintenance

The following guide starts with a `replay_vectors` failure after changing `crates/crypto_simd/src/bls`. Rust filenames in this section are relative to that directory unless stated otherwise.

### Read the failure first

Resolve IFMA availability or vector-file errors before investigating output differences.

**G2 mismatches.**

For the G2 kernel, an output mismatch reports the number of changed batches and details the first 20. For each batch it lists changed masks and point lanes, distinguishing points the caller returns from points it never reads. A lane belongs to the first category if its `valid` bit is set in either the recorded or current output.

- **A mask or a `valid` lane's point changed.** The recorded behaviour changed, but the caller's result may not have: `on_curve` is not read by `mod.rs`, and `undecided` routes a lane to blst. Determine whether acceptance, a returned point or only the route to that result changed. If the change is unintended, fix the Rust. The blst comparison tests in `src/bls/tests.rs` can help diagnose acceptance or point errors; they do not necessarily exercise this exact recorded batch.
- **Only points on lanes `mod.rs` never reads changed.** The caller's acceptance decisions and returned points are unchanged on these batches, but the kernel computes different values on rejected or undecided lanes. This can happen when it skips work on rejected lanes or changes the arithmetic there. If the change is intended, update the model too: refinement requires exact agreement on every lane, even where the headline theorem does not inspect the point.

G2 also compares scalar verdicts on every input and public-wrapper outputs. The wrapper cases detect wrong slots, missing writes, a wrong fallback input, out-of-bounds padding and kernel/blst disagreement. The Lean runner checks the model and extraction at both SIMD settings; its spec/blst comparison includes undecided lanes and infinity.

**G1 mismatches.**

G1 compares its two masks and all twelve point limbs, recorded scalar verdicts and wrapper outputs. A specification/blst mismatch concerns the recorded reference or its representation; kernel refinement alone cannot resolve it. Its wrapper cases check output slots, writes, portable fallback inputs and agreement with recorded blst results. The Lean runner executes the actual generated portable decoder at both SIMD settings and starts with nonzero output sentinels. Only its independent wrapper model uses recorded fallback observations. The public G1 theorem takes `G1DecoderCorrect` for the generated singleton and pair decoders.

The recordings make the kernel and scalar verdicts agree, so a routing change alone cannot cause a wrapper mismatch. Routing rests on the proof and the drift check; the model-routing controls use arbitrary scalar verdicts that differ from the kernel's result. Those observations do not replace the generated portable G1 decoder.

Keep the original recording until you understand the difference. `write_vectors` checks the new kernel's acceptance and accepted points against blst before replacing the file; `recorded_matches_blst` checks the recorded results. Kernel/blst comparisons skip undecided lanes. Both groups record the scalar result on every lane, and the Lean specification/blst check covers all of them. Regenerating the vectors can make `replay_vectors` pass while the Lean model or generated code still disagrees. Run the Lean differential check against the new recording as well.

### When the change in behaviour is intended

Set up the [toolchain and cache](../README.md#reproducing-the-proof-and-checks) and [`AENEAS_DIR`](../README.md#reproducing-the-extraction) as described in the parent README. Run Cargo commands from the silver repository root; run Lake commands and `extract.sh` from this directory. Keep the original failure output so a reviewer can compare the old and new behaviour.

1. Regenerate the extraction with `AENEAS_DIR=/path/to/aeneas ./extract.sh`. It replaces `LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean`, and prints how they changed, with the line numbers of Aeneas's `Source:` locations masked. The shared extraction includes both public wrappers, their kernels, the KZG verifier and the cell extender. The common preparation steps above are checked by `--check`; regenerate through the script rather than editing `Extracted/Funs.lean`. If the Rust now calls an item that Aeneas does not translate, such as a new intrinsic, add it to the externals (see below).
2. Regenerate the vectors on a host with AVX-512 IFMA:

   ```sh
   SILVER_REQUIRE_IFMA=1 cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
   ```

   G2's `write_vectors` checks each edge batch's specified mask expectations before writing the file. If one fails, your change altered a case that batch exists to cover: make sure that is intended before changing its expectation in `../vectors.rs`.
3. Run `lake build differential && lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt`. This compares the generated code and model with the new Rust outputs on the recorded batches. A mismatch identifies the batch, its kind, the lane, the field, both values, and the Lean implementation: `model` or `extraction`. For an `extraction` mismatch, investigate the translation, Aeneas's library and the externals. If the extraction agrees but the model differs, update the model.
4. Update each model function whose result changed (see the table below). Exact refinement cannot hold if the generated function and its model compute different results. Keep the model close to the Rust's operations, layout and names so they remain easy to compare. Preserve the per-lane treatment of `Fp8::mul` unless that modelling choice also needs to change. Edit named stages such as `decodeStep`, `chainStep` and `tail` in place; their proofs refer to those definitions. Repeat step 3 until both implementations match the recording.
5. Run `lake build`. Repair the affected equalities in `LeanBlsSimd/Refines/`, then the correctness proofs in `LeanBlsSimd/Proofs/`. A change that preserves every computed result, such as reordering independent operations, can leave the model and its correctness proofs unchanged. If refinement still fails after the vector checks pass, determine whether the proof needs a new equality lemma or the implementations differ on an untested input. Do not weaken a theorem to close a goal. A necessary change to the claim requires updating and reviewing `../README.md` too.
6. Run every control (command in `../README.md`). `controls/Refines.lean` holds hand-written copies of generated functions, pinned to the originals by `rfl`; if such an `rfl` fails after regeneration, copy the function again from the new `LeanBlsSimd/Extracted/Funs.lean` and reapply the mutation, rather than deleting the control. If a mutated proof now succeeds, investigate whether the mutation still tests the intended property; that result alone does not establish a lost dependency.
7. From the silver repository root, run `SILVER_REQUIRE_IFMA=1 cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors replay_vectors` on the IFMA host. Review the vector diff alongside the changes to the Rust, generated code, model and proofs.
8. From this folder, `AENEAS_DIR=/path/to/aeneas ./extract.sh --check` must report no drift.
9. Update `../README.md`: the sha256 and git blob of each changed file, and any counts that changed. Changes to `mod.rs` must preserve or update the corresponding wrapper model, refinement and public theorem.

### Mapping Rust changes to Lean

| Rust file | Model | Refinement | Proofs that read the model |
|---|---|---|---|
| `mod.rs` (shared `Membership` and G2 length) | `Model/G2x8.lean` (`Membership`), `Model/DecompressG2.lean` (`G2_COMPRESSED_LEN`) | `Refines/G2x8.lean` (`ofMembership`, `toMembership` and their uses), `Refines/DecompressG2.lean` (`G2_COMPRESSED_LEN`) | `Proofs/G2x8.lean` and `Proofs/DecompressG2.lean` (`Membership`); `Proofs/Decode.lean`, `Proofs/DecompressG2.lean` and `Proofs/Kernel.lean` (`G2_COMPRESSED_LEN`) |
| `mod.rs` (G1 chunk and wrapper) | `Model/UncompressG1.lean` | `Refines/G1Wrapper*.lean`, `Refines/UncompressG1.lean` | `Spec/G1Encoding.lean` and the G1 kernel proof |
| `mod.rs` (G2 chunk and wrapper) | `Model/UncompressG2.lean` | `Refines/G2Wrapper*.lean`, `Refines/UncompressG2.lean` | `Spec/G2Encoding.lean`, `Proofs/UncompressG2.lean` and the G2 kernel proof |
| `constants.rs` | `LeanBlsSimd/Constants.lean`, which also proves each table equal to its derivation | `Refines/Constants.lean` | every file |
| `fp8.rs` | `LeanBlsSimd/Model/Fp8.lean`, over the intrinsics in `Model/Intrinsics.lean` | `Refines/Fp8.lean`, `Refines/Transpose.lean` | `Proofs/Limbs.lean` (`mul`), `Proofs/EarlyCarry.lean`, `Proofs/Reduction.lean`, `Proofs/Square.lean`, `Proofs/Vector.lean`, `Proofs/Carries.lean`, `Proofs/Fp8.lean` (the other operations), `Proofs/Pow.lean`, `Proofs/Convert.lean` |
| `fp2x8.rs` | `LeanBlsSimd/Model/Fp2x8.lean` | `Refines/Fp2x8.lean` | `Proofs/Fp2x8.lean`, which relates the computed square root to `Kernel.sqrt` in `Spec/Sqrt.lean` |
| `g1x8.rs` | `Model/G1x8.lean` | `Refines/G1x8.lean` | `Proofs/G1x8.lean`, against `Spec/G1Curve.lean` |
| `decompress.rs` | `Model/DecompressG1.lean` | `Refines/DecompressG1.lean` | `Proofs/DecodeG1.lean`, `G1Finite.lean`, `G1KernelFacts.lean`, `DecompressG1.lean` |
| `g2x8.rs` | `LeanBlsSimd/Model/G2x8.lean` | `Refines/G2x8.lean` | `Proofs/G2x8.lean`, against the field-level chain and Scott test in `Spec/Membership.lean` |
| `decompress_g2.rs` | `LeanBlsSimd/Model/DecompressG2.lean` | `Refines/DecompressG2.lean`, then `Refines/Kernel.lean` and `Refines/Complete.lean` with the headline | `Proofs/Decode.lean` (bytes and flags), `Proofs/DecompressG2.lean` (lanes and early returns), `Proofs/Kernel.lean` |

Abbreviated paths such as `Model/Intrinsics.lean` and `Proofs/Limbs.lean` are relative to `LeanBlsSimd/`. `Refines/Basic.lean` contains conversions between Aeneas's values and the model's values, plus lemmas for evaluating Aeneas's primitives. `Refines/Loop.lean` equates Aeneas's loops with folds: `loop_range` for a `for` over a range, `loop_countdown` for a `while` that counts down. Changes to either wrapper, `Membership` or `G2_COMPRESSED_LEN` in `mod.rs` follow the extraction and refinement process above. The public wrappers' length checks are proved in `Refines/WrapperLengths.lean`.

`extract.sh` specifies the BLS and KZG roots to extract and the functions to keep opaque. Aeneas leaves calls to untranslated items; Lean then needs definitions for them. Add function definitions to `Extracted/FunsExternal.lean` and type definitions to `Extracted/TypesExternal.lean`. A new intrinsic needs a definition in `Model/Intrinsics.lean` and an external that returns `ok` of that definition. Their agreement with the actual intrinsic is trusted, so check its semantics against the Intel SDM and Rust's `core::arch`, including arithmetic, lane order, mask bit order and shifts of 64 or more.

### Working in Lean

G1 uses `Spec/G1Curve.lean` for the elementary finite point-count bound and Scott equivalence, `Spec/G1Encoding.lean` for KZG validation, and `Proofs/G1Finite.lean` for finite encoding and square-root selection. `Spec/G1.lean` imports Scott's criterion and the KZG acceptance and layout bridges. `Proofs/G1.lean` imports decided-lane formula and kernel correctness. `Refines/UncompressG1.lean` composes those with the wrapper refinement. For G2, `Spec/CubicHasse.lean` proves the character-sum bound for E′, derives the Hasse bounds and concludes Scott completeness. `Refines/Complete.lean` supplies that proof to the conditional extracted correctness theorem. `Spec/G2Encoding.lean` defines the affine verdict and proves the unit-z conversion bridge and infinity verdict; `Proofs/UncompressG2.lean` bridges decided kernel lanes to that verdict. `Refines/UncompressG2.lean` composes these with the complete wrapper refinement and names the G2 `BlstMatchesSpec` premise.

Changes to the field, curve, generator or subgroup constants must preserve this chain as well as the extraction refinements; a successful generator check alone does not establish completeness.

`Model/G1x8.lean`, `Model/DecompressG1.lean` and `Model/UncompressG1.lean` contain executable definitions. `Refines/G1.lean` imports exact extraction refinements for the group operations, decoder, kernel and public wrapper. `Refines/UncompressG1.lean` contains the public pointwise and list-form results, with the named `G1DecoderCorrect` premise for actual portable decoder calls. The downstream examples in `controls/downstream/` show how to discharge another extraction's named hypothesis without sharing its struct declarations.

- `Fp2x8.sqrt_refines` simplifies one stage at a time and generalizes matching intermediate values before continuing. Later goals can then refer to these values without printing the entire exponentiation chain. It accepts either `square x` or `mul x x` for the two squares forming the norm in the generated `Fp2x8::sqrt`; this does not extend to squares inside `pow_p_minus_3_over_4`. `DecompressG2.decompress_refines` uses `if_congr` to check branch conditions separately, exposing mask mismatches before comparing branch contents. Changes that prevent a stage from matching may still produce larger errors.
- `Proofs/MulComm.lean` proves exact multiplication commutativity for arbitrary limbs, including truncation and wrapping. Only `Fp2x8.mul_refines` uses it as a local simp rule to accept swapped operands. `Fp8.mul_refines` does not use commutativity, and swapping multiplication operands inside the generated `Fp2x8::sqrt` still fails its refinement proof. Field equality alone would not justify this rewrite: refinement also compares the representation, even for inputs outside `Fp8Inv`.
- Use the compiled `differential` executable when evaluating many batches; reserve `#eval` for small checks.
- The model's `UInt64` arithmetic wraps modulo 2^64. For inputs satisfying `Fp8Inv`, `Proofs/Limbs.lean` proves that no addition in `Lane.mul` overflows. Changes to limb layout, row count or carry handling require rechecking those bounds.

Proof-writing pitfalls:

- Avoid `decide` on universal statements over `Fp2Field`. `Spec/PointCount.lean` declares a global noncomputable `Fintype Fp2Field` instance, so importers can obtain `Fintype.decidableForallFintype` instead of a missing-instance error. Evaluating that decision procedure in Lean's kernel would attempt to enumerate p² field elements. Use a mathematical proof instead.
- Avoid unfolding the spec's `Fp2.sqrt` or `Fp.inverse` in proofs: evaluating their large powers can produce a "deep recursion" error. Use `cases h : Fp2.sqrt a` to obtain an equation for the result, then apply `Kernel.sqrt_agrees` or `Kernel.sqrt_fails`. Rewrite `Fp2.inverse` with `Fp2.toField_inverse` before its definition unfolds.
- `decide +kernel` exhausted memory when evaluating `decompress` directly; Mathlib's `dblXYZ` also proved impractical to evaluate through `MvPolynomial`. Go through `decompress_lane` and the lane functions, or `Kernel.dblXYZ_eq_dblFormula`.
- `rfl`, `show` or `unfold` across a structure whose fields mention `Kernel.sqrt` can send the elaborator into the same powers. Separate definitions rewritten by their equations, such as `laneX` and `laneY`, avoid it.
- `generalize` on a large `Fp2x8` term can time out on structure eta. The model's `decompress` computes x and x³ + b′ in `xOf` and `rhsOf`, whose applications generalise cheaply; `decompress_lane` and `decompress_refines` rely on that.
- `split` followed by `rfl` on `decide (val64 x < p)` hits deep recursion in Lean's kernel; `by_cases` with `if_pos` and `if_neg` does not.
- `(x.c0 : ZMod p)` keeps the type `Fp`. State helpers over `ZMod` binders and apply them with `exact`.

### Controls

After `lake build differential`, run `python3 -I Test/check_g1_controls.py` to check both differential runners' value comparisons, accepted formatting and parser failures. Run the BLS Lean controls, independent downstream package and Rust replay/blst comparisons through the parent README's reproduction commands.

### Adding a batch

For G2, if your change needs a case the file lacks, add it to `Cases` in `../vectors.rs` with an `Expect`, and regenerate. Every batch drawn from the seeded generator depends on all draws before it, so add batches that use the generator at the end; a batch built only from fixed values can go anywhere.

For G1, add cases to `g1::cases` in `../vectors.rs`. For both groups, record the scalar blst result even when the kernel leaves a lane undecided. Wrapper cases refer to recorded batch/lane inputs and must include the complete expected optional output. Regenerate with the ignored `write_vectors` tests, then run the combined Lean differential command and the Rust replay checks.

## KZG maintenance

Start with `LeanBlsSimd.Kzg.Statements`: `verify_eq_spec` uses the explicit `embeddedSetup`, while `verify_eq_upstream` additionally assumes the runtime loader returns it. Both take the seven generated-component contracts listed above. Preserve their component scope, slice-byte bounds, successful construction, specification verdict and next-state invariant. The input theorem includes malformed or rejected batches and repeated calls. `new_returns_ok` needs only `FrCorrect`, `PortableFpCorrect` and `G1DecoderCorrect`; `default_eq_new` relates generated `Default` to `new`.

The supporting wrappers in `Kzg/Refines.lean` take the generated cell arguments. `interpolation_commitment_refines` and `pairing_holds_refines` require `InterpolationKernel.CellsRep cells evals`. This relation fixes batch and row sizes and requires successful canonical decoding to every matching evaluation. Their evaluation-scratch premise applies only when `v.kernel = none`; `decode_cells_refines` provides its scratch postcondition under the same condition. `controls/downstream/KzgSmoke.lean` checks conditional consumers of these interfaces.

`Kzg/Decoder.lean` composes the actual generated G1 wrapper with equality of the KZG/BLS optional affine verdicts. Keep `G1DecoderCorrect` at the portable singleton/pair boundary; do not replace it with an external batch decoder assumption. KZG needs no G2 decoder observation: independent certificates establish the two embedded G2 points, while generated execution uses the fixed pairing table.

The seven component contracts concern fixed generated definitions. Their satisfiability requires proofs of those implementations; conditional consumers do not provide such witnesses.

For cell extension, start with `LeanBlsSimd.Kzg.Extender.Statements`. `Extender.compute_eq_spec` takes `FrCorrect` and `FrBytesCorrect`; construction needs only `FrCorrect`. Preserve total construction and execution, canonicality in both directions, and exact `computeCells` output bytes. Rejection must produce a specification error and leave output cells unchanged. Every call preserves the state invariant, including the optional kernel's tables. It permits arbitrary scratch contents of the fixed lengths, covering calls after rejection. There is no group, hash, pairing, G1 decoder or runtime setup premise. `Extender.default_eq_new` covers `Default`. `Extender.model_eq_spec` preserves the complete specification result, and `Extender.model_accepts_iff` characterizes valid inputs.

### Mapping Rust changes to Lean

| Rust file under `src/kzg/` | Lean modules under `LeanBlsSimd/Kzg/` |
|---|---|
| `verify.rs` | `Statements.lean`, `Model.lean`, `InterpolationModel.lean`, `Refines/Verify.lean`, `Refines/Cells.lean`, `Refines/Points.lean`, `Refines/Checks.lean`, `Refines/Deduplicate.lean`, `Refines/Pairing.lean`, `Refines/Interpolation.lean` and `Refines/InterpolationCommitment.lean` |
| `interpolation_kernel.rs` | `InterpolationKernel/Basic.lean`, `Construct.lean`, `Roots.lean`, `Check.lean`, `AddCell.lean`, `Aggregate.lean`, `Accumulate.lean`, `Column.lean`, `Model.lean`, `Store.lean` and `Interpolate.lean`; `InterpolationKernel/Fr8Splat.lean` proves the shared `Fr8::splat` weight conversion |
| `cell_extender.rs` | `Extender/Basic.lean`, `Extender/Model.lean`, `Extender/Acceptance.lean`, `Extender/Decode.lean`, `Extender/Scale.lean`, `Extender/WriteStep.lean`, `Extender/WriteBytes.lean`, `Extender/Write.lean`, `Extender/Refines.lean` and `Extender/Statements.lean` |
| `fft.rs` | `Refines/Fft.lean` |
| `fr8.rs` | Shared `../Model/Fr8.lean`, `../Model/Fr8Product.lean`, `../Model/SignedLimbs.lean`, `../Proofs/SignedLimbs.lean`, `../Refines/Fr8.lean`, `../Refines/Fr8Core.lean`, `../Refines/Fr8Interleaving.lean`, `../Refines/Fr8Lazy.lean`, `../Refines/Transpose.lean`, `../Proofs/Fr8*.lean`, `../Proofs/EarlyCarry.lean`, `../Proofs/Reduction.lean`; `Extender/Kernel/Fr8.lean`, `Fr8Arithmetic.lean`, `Fr8Model.lean`, `Fr8Lazy.lean`, `Fr8Mul.lean`, `Fr8Offset.lean`, `Fr8Reduced.lean`, `Fr8AddSub.lean`, `Lazy.lean`, `Fr8Transpose.lean` and `Fr8Bytes*.lean` |
| `fft8.rs` | `Extender/Kernel/Fft.lean`, `FftMath.lean`, `FftTableBuild.lean`, `FftTables.lean`, `FftShort.lean`, `FftShortModel.lean`, `FftShortSteps.lean`, `FftShortOne.lean`, `FftShortPipeline.lean`, `FftBlocks.lean`, `FftPairIndex.lean`, `FftWidePair.lean`, `FftWidePipeline.lean`, `FftWideOperands.lean`, `FftWideRun.lean` and `FftWide.lean` |
| `fr8/u256x8.rs` | `Extender/Kernel/Fr8ByteLoad.lean`, `Fr8Swap.lean`, `Fr8Endian.lean`, `Fr8Words.lean`, `Fr8WordStore.lean`, `Fr8BytesDecode.lean` and `Fr8BytesEncode.lean`; the left-shift intrinsic in `../Model/Intrinsics.lean` and `../Extracted/FunsExternal.lean` |
| `extension_kernel.rs` | `Extender/Kernel/Basic.lean`, `Construct.lean`, `Decode.lean`, `Shift.lean`, `Encode.lean` and `Refines.lean` |
| `domain.rs` | `Refines/Roots.lean`, `Refines/Bits.lean` and `Extender/Primitives.lean` |
| `challenge.rs` | `ByteSerialization.lean`, `ShaContracts.lean` and `Refines/Challenge.lean` |
| `cosets.rs` | `Refines/Cosets.lean` |
| `setup.rs`, `trusted_setup.rs` | `Setup.lean`, `SetupPoints.lean`, `SetupArithmetic.lean` and `Refines/Setup.lean` |
| `fr.rs` | `ScalarContracts.lean`, `ScalarConstants.lean`, `Representation.lean`, `RepresentationWords.lean` and `RepresentationLemmas.lean` |

The verifier's specification bridge uses the polynomial modules, `InterpolationIdentity.lean`, `ModelSpec.lean` and `SpecBridge.lean`. The extender's bridge uses `Extender/SpecMath.lean`, `Extender/Spec.lean` and `Extender/SpecBytes.lean` for polynomial evaluation and byte layout.

### Working in Lean

Regenerate through `extract.sh`, repair affected refinements, and rebuild the shared library before running controls. For changed mathematical code, check both the exact coefficient-array result and its interpretation: trailing zero coefficients and fixed array sizes are part of the refinement. Jacobian point results are compared by `G1Rep`, not by equality of their coordinate triples. Changes to setup constants require the kernel-checked point certificates and the connection to the pinned spec's embedded setup; the reference-loader hypothesis cannot stand in for those proofs.

The verifier's roots and scalar FFT refinements use `FrCorrect`. `ExternalsCorrect` bundles the seven generated-component premises for higher-level composition; it is not an operation dictionary. Preserve the smaller component premises when changing shared arithmetic. Portable Fp/G1 adapters live in `Kzg/PortableFp.lean` and `Kzg/PortableG1.lean`; the decoder contract lives in `Portable/G1DecoderContract.lean`. `PortableMsmContract.lean` constrains actual portable MSM. `Lincomb.lean` composes it with scalar-word conversion and the proved MSM8 path for `CurveWork.sum`.

For Fr8 kernels, prove generated-code equality to the per-lane model before reasoning about five-limb carries. `Kernel.RootsValid` uses `IsPrimitiveRoot` and root powers, matching the specification's FFT lemmas. Keep the pure iterative-transform induction valid down to size 1; only the generated FFT contracts require sizes 64 through 4096. Data lanes are ordinary integers and multipliers carry `2^260`; blst's four-word encoding carries `2^256`, so the constructor's factor of 16 is essential.

Preserve exact raw decode values on rejection: they support the range-mask controls and may be outside the arithmetic invariant. `Kernel.StateInvariant` deliberately permits those data contents, while fixing table contents and buffer lengths. Its FFT and shift multipliers satisfy `MultiplierRep`, including canonical representatives below `r`; the constructors prove this bound. `Kernel.compute_refinement` must remain independent of `FrBytesCorrect` and `FrCorrect`; `Kernel.new_refinement` supplies the invariant under `FrCorrect`. Compose that route with the scalar route for the public headline.

The verifier's optional `InterpolationKernel` reuses the same FFT and arithmetic contracts at size 64. Its invariant permits arbitrary scratch columns: `interpolate` clears the used flags, and `add_cell` normalizes each first product before the DIT reads it. Preserve the canonical-cell relation `CellsRep` and the conditional evaluation-scratch premise for the scalar route. Canonical coefficient stores use `FrBytesCorrect.fr_bytes`. Keep this scalar boundary separate from group, hash and pairing premises.

Keep array dimensions and collections explicit when rewriting 4096-element transforms. An unresolved collection argument in `getElem!_pos` or a large serialization expression in `change` can make unification evaluate the entire array. Use getter and size lemmas before specializing dimensions. Align the specification's `Cell` alias in serialization helpers to avoid unfolding its 2048-byte fold merely to compare getter instances. A mismatched model term can also appear as a maximum recursion depth failure. Inspect the competing terms before raising the limit.

`G1Bridge.lean` provides a generic transport theorem for independent extractions; the shared verifier uses the direct decoder bridge.

`StateInvariant` includes `CurveWorkInvariant`: portable work must hold a table satisfying the fixed field interpretation `PortableLinesRep`. `PairingTableBounds.lean` certifies the literal lanes individually; `PairingTableConstruction.lean` proves actual construction from `PortableFpCorrect`, packing and radix conversion. Keep that constructor independent of `PairingCorrect`. `CurveWork.sum_frame` preserves the exact stored table and route. Replacing work requires its invariant through `stateInvariant_lincomb`; arbitrary table replacement is not valid. Interpolation and curve-work routes may differ in an invariant-satisfying state, so preserve mixed-route proofs rather than restricting to constructor-reachable states. The model covers all four stored-route combinations independently of the eight CPU feature assignments. Real execution still requires instruction support on the selected routes; constructor-produced states align their routes with stable CPU observations.

`ShaRep` gives streaming states a fixed observational meaning: every finite continuation yields the specification digest of the prefix and continuation. Keep `ShaCorrect` at actual portable/extension `new`, `update`, `finish` calls. Challenge refinement uses aligned chunk arrays without a total-transcript-fit or 2^61-byte premise. The generated verifier challenge returns a scalar without modifying verifier state.

#### Constructor panic message

The constructor's panic message in `verify.rs` must remain constant to avoid pulling Aeneas's opaque `core.fmt.Formatter` into its generated guard closure. No exception is accepted for this dependency.

### Controls

The [KZG controls table](../README.md#evidence-and-controls) describes each checked boundary, including the production G1 decoder control. Run the files through the common `controls/*.lean` loop.

`ExtenderExternalBoundary.lean` tests independent specification-model serialization laws. `ExtenderMathematical.lean` checks the blob-sized transform steps; `ExtenderLayout.lean` checks copying and rejection behavior. `ExtenderSpecInstance.lean` applies the generated-runtime headline conditionally on `FrCorrect` and `FrBytesCorrect`. Kernel controls cover raw decode/masks, multiplier scaling, permutation selection, canonical output, byte order, table/stage ordering and output frames. `InterpolationKernel.lean` checks shift factors, first-product normalization, used-column tracking and canonical-cell verdicts.

`KzgStreamingSha.lean` rejects constant-zero hashing, and checks chunk segmentation and agreement of the two generated paths under their contracts. `ShaIntrinsics.lean` checks SHA/SSE packing and round inputs. `ExtractedLiterals.lean` checks hoisted tables. `KzgPairingTable.lean` checks the persistent table invariant and scratch freedom. `KzgRuntimeBoundary.lean` rejects transitive KZG dependencies on the signature-only opaque G2 decoder. The default `KzgStrictAxioms.lean` includes the component controls and the shared generated-entry inventory; use the final guard output for measured counts.

After the Lean checks and extraction controls, run from the repository root:

```sh
make -C crates/crypto_simd
SILVER_REQUIRE_IFMA=1 cargo test --locked -p silver_crypto_simd --all-features
```

Read the Rust test output to confirm the KZG specification-vector and c-kzg reference comparisons ran, and that BLS kernel replay did not skip. Finite tests provide evidence at the extraction and external boundaries; they do not discharge the universal generated-component contracts.

#### Scoped checks

To inspect one KZG layer, these targets rebuild imports and print its theorem axioms:

```sh
lake build controls.KzgSetupAxioms
lake build controls.KzgRefinementAxioms
lake build controls.KzgRepresentationAxioms
lake build controls.KzgSpecBridgeAxioms
lake build controls.KzgPolynomialAxioms
```

The top-level control loop runs these checks alongside `controls/KzgStrictAxioms.lean`. That module checks conditional runtime consumers, independent model witnesses and KZG negative controls with the shared guard.
