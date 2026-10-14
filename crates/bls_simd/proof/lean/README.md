# Maintaining the G2 decompression proof

## G1 correctness (M3)

The G1 extraction refinements, model/spec proofs, Scott criterion, KZG bridges and public correctness theorem are proved and covered by the default axiom guard. `lake build` checks them together with G2. The public import is `LeanBlsSimd.Refines.UncompressG1`.

`Model/G1x8.lean`, `Model/DecompressG1.lean` and `Model/UncompressG1.lean` contain executable definitions. `Refines/G1.lean` imports exact extraction refinements for the group operations, decoder, kernel and public wrapper. `Spec/G1.lean` imports Scott's criterion and the KZG acceptance and layout bridges. `Proofs/G1.lean` imports decided-lane formula and kernel correctness. `Refines/UncompressG1.lean` contains the public pointwise and list-form results, with the named `BlstMatchesSpec` premise. Paths are relative to `LeanBlsSimd/`.

`acceptedAxioms` remains empty: the complete G1 and G2 proof closures use only `propext`, `Classical.choice` and `Quot.sound`. M4 controls and differential validation are in progress.

The extraction includes both G1's public wrapper and G2's kernel. `extract.sh` inserts a `G1Externals` instance parameter and quotes the identifier `full` after Aeneas runs. These deterministic adaptations are checked by `--check`; regenerate through the script rather than editing `Extracted/Funs.lean`.

This guide explains how to update the proof after changing `crates/bls_simd/src`, starting with a `replay_vectors` failure. [The parent README](../README.md) describes the correctness claim, its assumptions, and the checks that connect the proof to Rust.

## Read the failure first

An output mismatch reports the number of changed batches and details the first 20. For each batch it lists changed masks and point lanes, distinguishing points the caller returns from points it never reads. A lane belongs to the first category if its `valid` bit is set in either the recorded or current output. Resolve IFMA availability or vector-file errors before investigating output differences.

- **A mask or a `valid` lane's point changed.** The recorded behaviour changed, but the caller's result may not have: `on_curve` is not read by `lib.rs`, and `undecided` routes a lane to blst. Determine whether acceptance, a returned point or only the route to that result changed. If the change is unintended, fix the Rust. The blst comparison tests in `src/tests.rs` can help diagnose acceptance or point errors; they do not necessarily exercise this exact recorded batch.
- **Only points on lanes `lib.rs` never reads changed.** The caller's acceptance decisions and returned points are unchanged on these batches, but the kernel computes different values on rejected or undecided lanes. This can happen when it skips work on rejected lanes or changes the arithmetic there. If the change is intended, update the model too: refinement requires exact agreement on every lane, even where the headline theorem does not inspect the point.

Keep the original recording until you understand the difference. `write_vectors` checks the new kernel's acceptance and accepted points against blst before replacing the file; `recorded_matches_blst` checks the recorded results. Both skip lanes marked undecided in the outputs they examine. Regenerating the vectors can make `replay_vectors` pass while the Lean model or generated code still disagrees. Run the Lean differential check against the new recording as well.

## When the change in behaviour is intended

Set up the [toolchain and cache](../README.md#building-and-checking-the-proof) and [`AENEAS_DIR`](../README.md#regenerating-the-extraction) as described in the parent README. Run Cargo commands from the silver repository root; run Lake commands and `extract.sh` from this directory. Keep the original failure output so a reviewer can compare the old and new behaviour.

1. Regenerate the extraction with `AENEAS_DIR=/path/to/aeneas ./extract.sh`. It replaces `LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`, and prints how they changed, with the line numbers of Aeneas's `Source:` locations masked. If the Rust now calls an item that Aeneas does not translate, such as a new intrinsic, add it to the externals (see below).
2. Regenerate the vectors on a host with AVX-512 IFMA:

   ```sh
   SILVER_REQUIRE_IFMA=1 cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
   ```

   `write_vectors` checks each edge batch's specified mask expectations before writing the file. If one fails, your change altered a case that batch exists to cover: make sure that is intended before changing its expectation in `../vectors.rs`.
3. Run `lake build differential && lake exe differential ../decompress_g2_vectors.txt`. This compares the generated code and model with the new Rust outputs on the recorded batches. A mismatch identifies the batch, its kind, the lane, the field, both values, and the Lean implementation: `model` or `extraction`. For an `extraction` mismatch, investigate the translation, Aeneas's library and the externals. If the extraction agrees but the model differs, update the model.
4. Update each model function whose result changed (see the table below). Exact refinement cannot hold if the generated function and its model compute different results. Keep the model close to the Rust's operations, layout and names so they remain easy to compare. Preserve the per-lane treatment of `Fp8::mul` unless that modelling choice also needs to change. Edit named stages such as `decodeStep`, `chainStep` and `tail` in place; their proofs refer to those definitions. Repeat step 3 until both implementations match the recording.
5. Run `lake build`. Repair the affected equalities in `LeanBlsSimd/Refines/`, then the correctness proofs in `LeanBlsSimd/Proofs/`. A change that preserves every computed result, such as reordering independent operations, can leave the model and its correctness proofs unchanged. If refinement still fails after the vector checks pass, determine whether the proof needs a new equality lemma or the implementations differ on an untested input. Do not weaken a theorem to close a goal. A necessary change to the claim requires updating and reviewing `../README.md` too.
6. Run every control (command in `../README.md`). `controls/Refines.lean` holds hand-written copies of generated functions, pinned to the originals by `rfl`; if such an `rfl` fails after regeneration, copy the function again from the new `LeanBlsSimd/Extracted/Funs.lean` and reapply the mutation, rather than deleting the control. If a mutated proof now succeeds, investigate whether the mutation still tests the intended property; that result alone does not establish a lost dependency.
7. From the silver repository root, run `SILVER_REQUIRE_IFMA=1 cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors replay_vectors` on the IFMA host. Review the vector diff alongside the changes to the Rust, generated code, model and proofs.
8. From this folder, `AENEAS_DIR=/path/to/aeneas ./extract.sh --check` must report no drift.
9. Update `../README.md`: the sha256, git blob, commit and commit date of each changed file, and any counts that changed. If `lib.rs` changed, check again that `decompress_g2_chunk` reads the batch as the headline's left side says.

## Mapping Rust changes to Lean

| Rust file | Model | Refinement | Proofs that read the model |
|---|---|---|---|
| `lib.rs` (`Membership` and `G2_COMPRESSED_LEN` only) | `Model/G2x8.lean` (`Membership`), `Model/DecompressG2.lean` (`G2_COMPRESSED_LEN`) | `Refines/G2x8.lean` (`ofMembership`, `toMembership` and their uses), `Refines/DecompressG2.lean` (`G2_COMPRESSED_LEN`) | `Proofs/G2x8.lean` and `Proofs/DecompressG2.lean` (`Membership`); `Proofs/Decode.lean`, `Proofs/DecompressG2.lean` and `Proofs/Kernel.lean` (`G2_COMPRESSED_LEN`) |
| `constants.rs` | `LeanBlsSimd/Constants.lean`, which also proves each table equal to its derivation | `Refines/Constants.lean` | every file |
| `fp8.rs` | `LeanBlsSimd/Model/Fp8.lean`, over the intrinsics in `Model/Intrinsics.lean` | `Refines/Fp8.lean` | `Proofs/Limbs.lean` (`mul`), `Proofs/Vector.lean`, `Proofs/Carries.lean`, `Proofs/Fp8.lean` (the other operations), `Proofs/Pow.lean`, `Proofs/Convert.lean` |
| `fp2x8.rs` | `LeanBlsSimd/Model/Fp2x8.lean` | `Refines/Fp2x8.lean` | `Proofs/Fp2x8.lean`, which relates the computed square root to `Kernel.sqrt` in `Spec/Sqrt.lean` |
| `g2x8.rs` | `LeanBlsSimd/Model/G2x8.lean` | `Refines/G2x8.lean` | `Proofs/G2x8.lean`, against the field-level chain and Scott test in `Spec/Membership.lean` |
| `decompress_g2.rs` | `LeanBlsSimd/Model/DecompressG2.lean` | `Refines/DecompressG2.lean`, then `Refines/Kernel.lean` and `Refines/Complete.lean` with the headline | `Proofs/Decode.lean` (bytes and flags), `Proofs/DecompressG2.lean` (lanes and early returns), `Proofs/Kernel.lean` |

Abbreviated paths such as `Model/Intrinsics.lean` and `Proofs/Limbs.lean` are relative to `LeanBlsSimd/`. `Refines/Basic.lean` contains conversions between Aeneas's values and the model's values, plus lemmas for evaluating Aeneas's primitives. `Refines/Loop.lean` equates Aeneas's loops with folds: `loop_range` for a `for` over a range, `loop_countdown` for a `while` that counts down. Changes to `Membership` or `G2_COMPRESSED_LEN` in `lib.rs` follow the extraction and refinement process described above. Other changes to `lib.rs`, notably to `decompress_g2_chunk`, need a separate review of the caller interpretation in the parent README; neither the extraction nor the vector tests verify how it consumes the batch.

`extract.sh` specifies the function to extract and the functions to keep opaque. Aeneas leaves calls to untranslated items; Lean then needs definitions for them. Add function definitions to `Extracted/FunsExternal.lean` and type definitions to `Extracted/TypesExternal.lean`. A new intrinsic needs a definition in `Model/Intrinsics.lean` and an external that returns `ok` of that definition. Their agreement with the actual intrinsic is trusted, so check its semantics against the Intel SDM and Rust's `core::arch`, including arithmetic, lane order, mask bit order and shifts of 64 or more.

## Working in Lean

`Spec/CubicHasse.lean` proves the character-sum bound for E′, derives the Hasse bounds and concludes Scott completeness. `Refines/Complete.lean` supplies that proof to the conditional extracted correctness theorem. Changes to the field, curve, generator or subgroup constants must preserve this chain as well as the extraction refinements; a successful generator check alone does not establish completeness.

- `lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false <file>` checks one file with the project's elaboration options, using the built versions of its imports. After changing an imported file, run `lake build` first.
- Never edit `Extracted/Types.lean` or `Extracted/Funs.lean`; regenerate them. Importing Aeneas makes `name` a keyword.
- A refinement theorem has the form `gen args = ok (toX (model (ofX args)))`. It rewrites a generated call for any arguments; the round-trip lemmas in `Refines/Basic.lean` then cancel nested conversions. Prefer explicit rewrite lemmas and `simp` when comparing large terms. Trying to close a mismatched goal by unfolding definitions can obscure the difference or exhaust Lean's resource limits.
- `Fp2x8.sqrt_refines` simplifies one stage at a time and generalizes matching intermediate values before continuing. Later goals can then refer to these values without printing the entire exponentiation chain. It accepts either `square x` or `mul x x` for the two squares forming the norm in the generated `Fp2x8::sqrt`; this does not extend to squares inside `pow_p_minus_3_over_4`. `DecompressG2.decompress_refines` uses `if_congr` to check branch conditions separately, exposing mask mismatches before comparing branch contents. Changes that prevent a stage from matching may still produce larger errors.
- `Proofs/MulComm.lean` proves exact multiplication commutativity for arbitrary limbs, including truncation and wrapping. Only `Fp2x8.mul_refines` uses it as a local simp rule to accept swapped operands. `Fp8.mul_refines` does not use commutativity, and swapping multiplication operands inside the generated `Fp2x8::sqrt` still fails its refinement proof. Field equality alone would not justify this rewrite: refinement also compares the representation, even for inputs outside `Fp8Inv`.
- Keep each proof well inside the default of 200000 heartbeats, or set explicit headroom with a comment saying why. `#count_heartbeats` under-reports unless `set_option Elab.async false in` precedes it.
- When two sides hold the same large model term with arguments in different forms, unification can unfold the model function and evaluate it. `Fp8.mul_refines` makes `Lane.reduce_row` locally irreducible for this reason. `simp only`, `unfold` and `rw` still reach its body there, but a proof step that relies on unification, such as `rfl`, can exhaust heartbeats at `whnf` when it needs that unfolding.
- Use the compiled `differential` executable when evaluating many batches; reserve `#eval` for small checks.
- The model's `UInt64` arithmetic wraps modulo 2^64. For inputs satisfying `Fp8Inv`, `Proofs/Limbs.lean` proves that no addition in `Lane.mul` overflows. Changes to limb layout, row count or carry handling require rechecking those bounds.

Proof-writing pitfalls:

- Avoid `decide` on universal statements over `Fp2Field`. `Spec/PointCount.lean` declares a global noncomputable `Fintype Fp2Field` instance, so importers can obtain `Fintype.decidableForallFintype` instead of a missing-instance error. Evaluating that decision procedure in Lean's kernel would attempt to enumerate p² field elements. Use a mathematical proof instead.
- Avoid unfolding the spec's `Fp2.sqrt` or `Fp.inverse` in proofs: evaluating their large powers can produce a "deep recursion" error. Use `cases h : Fp2.sqrt a` to obtain an equation for the result, then apply `Kernel.sqrt_agrees` or `Kernel.sqrt_fails`. Rewrite `Fp2.inverse` with `Fp2.toField_inverse` before its definition unfolds.
- `decide +kernel` exhausted memory when evaluating `decompress` directly; Mathlib's `dblXYZ` also proved impractical to evaluate through `MvPolynomial`. Go through `decompress_lane` and the lane functions, or `Kernel.dblXYZ_eq_dblFormula`.
- `rfl`, `show` or `unfold` across a structure whose fields mention `Kernel.sqrt` can send the elaborator into the same powers. Separate definitions rewritten by their equations, such as `laneX` and `laneY`, avoid it.
- `generalize` on a large `Fp2x8` term can time out on structure eta. The model's `decompress` computes x and x³ + b′ in `xOf` and `rhsOf`, whose applications generalise cheaply; `decompress_lane` and `decompress_refines` rely on that.
- `split` followed by `rfl` on `decide (val64 x < p)` hits deep recursion in Lean's kernel; `by_cases` with `if_pos` and `if_neg` does not.
- `get_elem_tactic` can time out in large contexts; give index bounds explicitly.
- `(x.c0 : ZMod p)` keeps the type `Fp`. State helpers over `ZMod` binders and apply them with `exact`.

## Controls and axioms

- In a control, close the mutated proof with `ring1` or `module`, never `ring`. `ring` can leave a goal open without throwing, so `fail_if_success` may treat the tactic as successful and reject the control. `ring1` throws when it cannot close the goal. `fail_if_success` accepts any failure, so after writing or changing a control, remove the wrapper once and check that the error is the one the control names.
- The guard rejects dependencies on axioms other than `propext`, `Classical.choice` and `Quot.sound`. This includes the axioms introduced by `native_decide` and `bv_decide`. Extending `acceptedAxioms` in `LeanBlsSimd/Axioms.lean` changes the proof's trust assumptions; it requires a documented justification and a corresponding update to the parent README. Use `#print axioms <theorem>` to inspect one theorem or `controls/AxiomLog.lean` for the library's theorems.
- Aeneas's library prints five `declaration uses 'sorry'` warnings while it builds. A `sorry` adds the axiom `sorryAx`, so the guard also shows that the generated `decompress` and every theorem avoid them.

## Adding a batch

If your change needs a case the file lacks, add it to `Cases` in `../vectors.rs` with an `Expect`, and regenerate. Every batch drawn from the seeded generator depends on all draws before it, so add batches that use the generator at the end; a batch built only from fixed values can go anywhere.
