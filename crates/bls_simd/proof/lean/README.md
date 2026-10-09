# Fixing a failed `replay_vectors`

This is for whoever changed `crates/bls_simd/src` and now sees `replay_vectors` fail, human or model. `../README.md` explains what the proof claims and how the vector test ties it to the Rust; this file is about getting back to green without weakening either.

## Read the failure first

The message lists each changed batch, with the masks that changed and the lanes whose `points` changed, split into lanes `lib.rs` returns (`valid` lanes) and lanes it never reads. That split decides what kind of problem you have.

- **A mask or a `valid` lane's point changed.** The kernel now answers differently on a recorded input. Unless that was the purpose of your change, your change has a bug: fix the Rust and leave the proof alone. The blst comparison tests in `src/tests.rs` often fail on the same inputs and are quicker to debug, because they name the encoding.
- **Only points on lanes `lib.rs` never reads changed.** Verdicts and returned points are as before, but the arithmetic on rejected or undecided lanes is different, so the Rust no longer computes what the model transcribes. Typical causes are skipping work on lanes already rejected, or a different order of operations that leaves different values there. If that part of the change is not needed, reverting it is the cheapest fix. Otherwise the model must follow, as below, even though the theorem's claims probably still hold.

Before deciding which applies, regenerate nothing. `write_vectors` would rewrite the file to match the new kernel, `replay_vectors` would pass, and the Lean side would be left checking against a model that no longer matches anything.

## When the change in behaviour is intended

Work in this order. Each step tells you something the next one needs.

1. Find the model of each changed file (table below) and update it to transcribe the new Rust, operation for operation. Keep the one-to-one layout and the Rust's names: reviewers check the model by reading the two side by side.
2. Regenerate the vectors on a host with AVX-512 IFMA:
   ```sh
   SILVER_REQUIRE_IFMA=1 cargo test -p silver_bls_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
   ```
   `write_vectors` checks each edge batch against the masks it was built to produce. If one fails, your change altered a case that batch exists to cover: make sure that is intended before changing its expectation in `../vectors.rs`.
3. From this folder, `lake build differential && lake exe differential ../decompress_g2_vectors.txt`. This is the real check: it compares your updated model with the new Rust. A mismatch prints the batch, its kind, the lane, the field and both values. Iterate on the model until it passes.
4. `lake build`. The proofs that break show where the change matters to the claims. Fix them; do not weaken a theorem statement to make it go through. If a statement must change, the claim in `../README.md` changes with it, and that needs the same review the original had.
5. Run every control (command in `../README.md`). A control that stops failing means a proof no longer depends on what that control mutates.
6. Update `../README.md`: the sha256, git blob, commit and commit date of each changed file, and any counts that changed.

## Where each Rust file lives

| Rust file | Model | Proofs that read it |
|---|---|---|
| `constants.rs` | `LeanBlsSimd/Constants.lean`, which also proves each table equal to its derivation | every file |
| `fp8.rs` | `LeanBlsSimd/Model/Fp8.lean`, over the intrinsics in `Model/Intrinsics.lean` | `Proofs/Limbs.lean` (`mul`), `Proofs/Vector.lean`, `Proofs/Carries.lean`, `Proofs/Fp8.lean` (the other operations), `Proofs/Pow.lean`, `Proofs/Convert.lean` |
| `fp2x8.rs` | `LeanBlsSimd/Model/Fp2x8.lean` | `Proofs/Fp2x8.lean`, whose square root lands on `Kernel.sqrt` in `Spec/Sqrt.lean` |
| `g2x8.rs` | `LeanBlsSimd/Model/G2x8.lean` | `Proofs/G2x8.lean`, against the field-level chain and Scott test in `Spec/Membership.lean` |
| `decompress_g2.rs` | `LeanBlsSimd/Model/DecompressG2.lean` | `Proofs/Decode.lean` (bytes and flags), `Proofs/DecompressG2.lean` (lanes and early returns), `Proofs/Kernel.lean` |

A new intrinsic needs a definition in `Model/Intrinsics.lean`. That file is trusted, not proved, so check its semantics against the Intel SDM and Rust's `core::arch`, including lane order, mask bit order and what happens at shift counts of 64 and above.

## Working in Lean

- `lake env lean <file>` checks one file in seconds, against the built versions of its imports. After changing a file others import, run `lake build` first.
- `#eval` runs the model on one batch in about 2.5 s; the compiled `differential` is faster for many.
- Overflow: the model's `UInt64` arithmetic wraps modulo 2^64 exactly as the hardware does, and `Proofs/Limbs.lean` proves that the wrap never fires in `mul` for inputs satisfying `Fp8Inv`. A change to the limb layout, the number of rows or the carry handling needs those headroom bounds proved again.

Traps met while building this proof:

- Never unfold the spec's `Fp2.sqrt` or `Fp.inverse`. Lean's kernel evaluates their large powers and stops with "deep recursion". Obtain `h : Fp2.sqrt a = .ok y` or `.error e` with `cases h : Fp2.sqrt a`, then use `Kernel.sqrt_agrees` or `Kernel.sqrt_fails`; rewrite `Fp2.inverse` with `Fp2.toField_inverse` before anything unfolds it.
- `decide +kernel` cannot evaluate `decompress` (it runs out of memory) or Mathlib's `dblXYZ` (it goes through `MvPolynomial`). Go through `decompress_lane` and the lane functions, or `Kernel.dblXYZ_eq_dblFormula`.
- `rfl`, `show` or `unfold` across a structure whose fields mention `Kernel.sqrt` can send the elaborator into the same powers. Separate definitions rewritten by their equations, such as `laneX` and `laneY`, avoid it.
- `generalize` on a large `Fp2x8` term can time out on structure eta. `decompress_eq := rfl` restates `decompress` on small arguments that generalise cheaply.
- `split` followed by `rfl` on `decide (val64 x < p)` hits deep recursion in Lean's kernel; `by_cases` with `if_pos` and `if_neg` does not.
- `get_elem_tactic` can time out in large contexts; give index bounds explicitly.
- `(x.c0 : ZMod p)` keeps the type `Fp`. State helpers over `ZMod` binders and apply them with `exact`.

## Controls and axioms

- In a control, close the mutated proof with `ring1` or `module`, never `ring`. A failing `ring` falls back to `ring_nf` and can leave its goal open, which `fail_if_success` may accept for the wrong reason. `fail_if_success` accepts any failure, so after writing or changing a control, remove the wrapper once and check that the error is the one the control names.
- The guard fails the build on any axiom beyond `propext`, `Classical.choice` and `Quot.sound`. `native_decide` and `bv_decide` each add one per use. Accepting one is a deliberate decision: list it by exact name in `acceptedAxioms` in `LeanBlsSimd/Axioms.lean`, with the reason beside it. `#print axioms <theorem>` shows one theorem's axioms; `controls/AxiomLog.lean` prints all of them.

## Adding a batch

If your change needs a case the file lacks, add it to `Cases` in `../vectors.rs` with an `Expect`, and regenerate. Every batch drawn from the seeded generator depends on all draws before it, so add batches that use the generator at the end; a batch built only from fixed values can go anywhere.
