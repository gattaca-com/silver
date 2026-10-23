import controls.G1Fallback
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Refines.G1Wrapper

/-! Mutation controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` checks that a proof script
rejects a mutation; each plain `example` must pass.

Each mutated definition takes the changed part as a parameter. An `rfl` check identifies its
unmutated instance with the original, and the same proof script succeeds on that instance.
Separate concrete examples refute the mutated claims where described below. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! ## `Fp8::select`: the order of the operands

`select k a b` takes a lane from `b` where its bit of `k` is set, and from `a` otherwise. A
generated `select` with its operands swapped must not refine the model's. -/

def selectWith (swap : Bool) (k : U8) (a b : fp8.Fp8) : Result fp8.Fp8 :=
  if swap then fp8.Fp8.select k b a else fp8.Fp8.select k a b

example : selectWith false = fp8.Fp8.select := rfl

set_option hygiene false in
/-- The proof of `Fp8.select_refines`, over `selectWith`. -/
local macro "select_proof" : tactic => `(tactic| (
  intro k a b
  simp [selectWith, fp8.Fp8.select, Simd.blend_refines, Fp8.select, toFp8]))

example : ∀ (k : U8) (a b : fp8.Fp8),
    selectWith false k a b = ok (toFp8 (Fp8.select (ofU8 k) (ofFp8 a) (ofFp8 b))) := by
  select_proof

example : True := by
  fail_if_success
    have : ∀ (k : U8) (a b : fp8.Fp8),
        selectWith true k a b = ok (toFp8 (Fp8.select (ofU8 k) (ofFp8 a) (ofFp8 b))) := by
      select_proof
  trivial

end LeanBlsSimd
