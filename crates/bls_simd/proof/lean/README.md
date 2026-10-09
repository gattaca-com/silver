# Fixing a failed `replay_vectors`

This is for whoever changed `crates/bls_simd/src` and now sees `replay_vectors` fail, human or model. [`../README.md`](../README.md) explains what the proof claims and how the vector test ties it to the Rust; this file is about getting back to green without weakening either.

## Read the failure first

For output mismatches, the message gives the total number of changed batches and lists the first 20, with the masks that changed and the lanes whose `points` changed, split into lanes `lib.rs` returns (`valid` lanes) and lanes it never reads. A point counts as valid here if its lane was valid in either the recorded or current output. If the failure instead concerns IFMA availability or reading the vector file, resolve that before investigating output changes.

- **A mask or a `valid` lane's point changed.** The recorded behaviour changed, but the caller's result may not have: `on_curve` is not read by `lib.rs`, and `undecided` routes a lane to blst. Determine whether acceptance, a returned point or only the route to that result changed. If the change is unintended, fix the Rust. The blst comparison tests in `src/tests.rs` can help diagnose acceptance or point errors; they do not necessarily exercise this exact recorded batch.
- **Only points on lanes `lib.rs` never reads changed.** Verdicts and returned points are as before, but the arithmetic on rejected or undecided lanes is different, so the Rust no longer computes what the model does. Typical causes are skipping work on lanes already rejected, or a different order of operations that leaves different values there. If that part of the change is not needed, reverting it is the cheapest fix. Otherwise the model must follow, as below, even though the theorem's claims probably still hold. The refinement proofs need the generated code and the model to agree on every lane.

Before deciding which applies, regenerate nothing. `write_vectors` checks the new kernel's acceptance and accepted points against blst before replacing the file; `recorded_matches_blst` checks the recorded results the same way. Both checks skip lanes marked undecided in the outputs they check. If regeneration succeeds, `replay_vectors` can pass with the new outputs even though the Lean side still disagrees with them. Rerun the Lean side to check that agreement.

## When the change in behaviour is intended

First follow the toolchain and cache setup in [the parent README](../README.md#building-and-checking-the-proof), and its setup of `AENEAS_DIR` under [regenerating the extraction](../README.md#regenerating-the-extraction). Run Cargo commands from the silver repository root, and Lake commands and `extract.sh` from this folder. Keep the failure output for review; regeneration is not evidence that the new behaviour is correct.

1. Regenerate the extraction with `AENEAS_DIR=/path/to/aeneas ./extract.sh`. It replaces `LeanBlsSimd/Extracted/Types.lean` and `Funs.lean`, and prints how they changed, ignoring Aeneas's `Source:` location lines. If the Rust now calls an item that Aeneas does not translate, such as a new intrinsic, add it to the externals (see below).
2. Regenerate the vectors on a host with AVX-512 IFMA:
   ```sh
   SILVER_REQUIRE_IFMA=1 cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
   ```
   `write_vectors` checks each edge batch's specified mask expectations before writing the file. If one fails, your change altered a case that batch exists to cover: make sure that is intended before changing its expectation in `../vectors.rs`.
3. `lake build differential && lake exe differential ../decompress_g2_vectors.txt`. This checks the generated code and the model against the new Rust outputs, on the recorded batches only. A mismatch prints the batch, its kind, the lane, the field and both values, and names the Lean side: `model` or `extraction`. A mismatch of the extraction side points at the extraction or the externals. A mismatch of the model alone shows that the model must follow the change.
4. `lake build`. Fix the refinement proofs in `LeanBlsSimd/Refines/` that break. Each states that a generated function returns `ok` of its model counterpart, so a broken one shows which function the change reached. A change that keeps behaviour, such as a restructured loop, needs only these proofs repaired.
5. If the change alters behaviour, update the model of each changed function (table below) to transcribe the new Rust, operation for operation. Preserve the per-lane treatment of `Fp8::mul` unless that modelling choice itself needs changing. Keep the corresponding layout and the Rust's names: reviewers check the model by reading the two side by side. Iterate with step 3 until the model passes, then fix the refinement proofs again and the proofs in `LeanBlsSimd/Proofs/` that break. Those show where the change matters to the claims. Do not weaken a theorem statement to make it go through. If a statement must change, the claim in `../README.md` changes with it, and that needs the same review the original had.
6. Run every control (command in `../README.md`). If a mutated proof now succeeds, investigate whether the mutation still tests the intended property; that result alone does not establish a lost dependency.
7. From the silver repository root, run `SILVER_REQUIRE_IFMA=1 cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors replay_vectors` on the IFMA host. Review the vector diff alongside the Rust, extraction, model and proof changes.
8. Update `../README.md`: the sha256, git blob, commit and commit date of each changed file, and any counts that changed.

## Where each Rust file lives

| Rust file | Model | Refinement | Proofs that read the model |
|---|---|---|---|
| `constants.rs` | `LeanBlsSimd/Constants.lean`, which also proves each table equal to its derivation | `Refines/Constants.lean` | every file |
| `fp8.rs` | `LeanBlsSimd/Model/Fp8.lean`, over the intrinsics in `Model/Intrinsics.lean` | `Refines/Fp8.lean` | `Proofs/Limbs.lean` (`mul`), `Proofs/Vector.lean`, `Proofs/Carries.lean`, `Proofs/Fp8.lean` (the other operations), `Proofs/Pow.lean`, `Proofs/Convert.lean` |
| `fp2x8.rs` | `LeanBlsSimd/Model/Fp2x8.lean` | `Refines/Fp2x8.lean` | `Proofs/Fp2x8.lean`, whose square root lands on `Kernel.sqrt` in `Spec/Sqrt.lean` |
| `g2x8.rs` | `LeanBlsSimd/Model/G2x8.lean` | `Refines/G2x8.lean` | `Proofs/G2x8.lean`, against the field-level chain and Scott test in `Spec/Membership.lean` |
| `decompress_g2.rs` | `LeanBlsSimd/Model/DecompressG2.lean` | `Refines/DecompressG2.lean`, then `Refines/Kernel.lean` with the headline | `Proofs/Decode.lean` (bytes and flags), `Proofs/DecompressG2.lean` (lanes and early returns), `Proofs/Kernel.lean` |

Abbreviated paths such as `Model/Intrinsics.lean` and `Proofs/Limbs.lean` are relative to `LeanBlsSimd/`. `Refines/Basic.lean` holds the conversions between Aeneas's values and the model's, and lemmas that evaluate Aeneas's primitives. `Refines/Loop.lean` equates Aeneas's loops with folds: `loop_range` for a `for` over a range, `loop_countdown` for a `while` that counts down. Changes to `lib.rs` need a separate review of the caller interpretation in the parent README; neither the extraction nor the vector tests cover that file.

`extract.sh` names the function the extraction starts from and the functions it keeps opaque. Aeneas writes calls to the items it does not translate, and Lean then reports their definitions missing. Write each in `Extracted/FunsExternal.lean`, or a type in `Extracted/TypesExternal.lean`, after the existing entries. A new intrinsic needs its definition in `Model/Intrinsics.lean` and an external that returns `ok` of it. Both files are trusted, not proved, so check the semantics against the Intel SDM and Rust's `core::arch`, including lane order, mask bit order and what happens at shift counts of 64 and above.

## Working in Lean

- `lake env lean <file>` checks one file, against the built versions of its imports. After changing a file others import, run `lake build` first.
- Never edit `Extracted/Types.lean` or `Extracted/Funs.lean`; regenerate them. Importing Aeneas makes `name` a keyword.
- A refinement theorem has the form `gen args = ok (toX (model (ofX args)))`, so it rewrites a generated call on any arguments. The roundtrip lemmas of `Refines/Basic.lean` then cancel the nested conversions. Close goals with `simp` rather than a high-transparency `rfl`, so that a mutated control fails fast.
- Keep each proof well inside the default of 200000 heartbeats, or set explicit headroom with a comment saying why, as `Fp8.mul_refines` does. `#count_heartbeats` under-reports unless `set_option Elab.async false in` precedes it.
- `#eval` runs the model on one batch in about 2.5 s; the compiled `differential` is faster for many.
- Overflow: the model's `UInt64` arithmetic wraps modulo 2^64 exactly as the hardware does, and `Proofs/Limbs.lean` proves that the wrap never fires in `mul` for inputs satisfying `Fp8Inv`. A change to the limb layout, the number of rows or the carry handling needs those headroom bounds proved again.

Traps met while building this proof:

- Never unfold the spec's `Fp2.sqrt` or `Fp.inverse`. Lean's kernel evaluates their large powers and stops with "deep recursion". Obtain `h : Fp2.sqrt a = .ok y` or `.error e` with `cases h : Fp2.sqrt a`, then use `Kernel.sqrt_agrees` or `Kernel.sqrt_fails`; rewrite `Fp2.inverse` with `Fp2.toField_inverse` before anything unfolds it.
- `decide +kernel` exhausted memory when evaluating `decompress` directly; Mathlib's `dblXYZ` also proved impractical to evaluate through `MvPolynomial`. Go through `decompress_lane` and the lane functions, or `Kernel.dblXYZ_eq_dblFormula`.
- `rfl`, `show` or `unfold` across a structure whose fields mention `Kernel.sqrt` can send the elaborator into the same powers. Separate definitions rewritten by their equations, such as `laneX` and `laneY`, avoid it.
- `generalize` on a large `Fp2x8` term can time out on structure eta. `decompress_eq := rfl` restates `decompress` on small arguments that generalise cheaply; `decompress_refines` relies on it.
- `split` followed by `rfl` on `decide (val64 x < p)` hits deep recursion in Lean's kernel; `by_cases` with `if_pos` and `if_neg` does not.
- `get_elem_tactic` can time out in large contexts; give index bounds explicitly.
- `(x.c0 : ZMod p)` keeps the type `Fp`. State helpers over `ZMod` binders and apply them with `exact`.

## Controls and axioms

- In a control, close the mutated proof with `ring1` or `module`, never `ring`. `ring` can leave a goal open without throwing, so `fail_if_success` may treat the tactic as successful and reject the control. `ring1` throws when it cannot close the goal. `fail_if_success` accepts any failure, so after writing or changing a control, remove the wrapper once and check that the error is the one the control names.
- The guard fails the build on any axiom beyond `propext`, `Classical.choice` and `Quot.sound`. `native_decide` and `bv_decide` each add one per use. Accepting one is a deliberate decision: list it by exact name in `acceptedAxioms` in `LeanBlsSimd/Axioms.lean`, with the reason beside it. `#print axioms <theorem>` shows one theorem's axioms; `controls/AxiomLog.lean` prints all of them.
- Aeneas's library prints five `declaration uses 'sorry'` warnings while it builds. A `sorry` adds the axiom `sorryAx`, so the guard also shows that the generated `decompress` and every theorem avoid them.

## Adding a batch

If your change needs a case the file lacks, add it to `Cases` in `../vectors.rs` with an `Expect`, and regenerate. Every batch drawn from the seeded generator depends on all draws before it, so add batches that use the generator at the end; a batch built only from fixed values can go anywhere.
