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

/-! ## `Fp8::mul`: the row indices

The eighth `muladd_row` of `mul` adds `rhs[7]` at row 7. A generated `mul` that adds it at row 6
must not refine the model's. The same script proves that this mutant refines a model with the
same mutation, and that model differs from `Lane.mul` on a concrete input. So the mutated claim
is false, not only unproved. -/

def mulWith (k : Usize) (self rhs : fp8.Fp8) : Result fp8.Fp8 := do
  let mi ← fp8.zero
  let t := Array.repeat 17#usize mi
  let mi1 ← Array.index_usize rhs 0#usize
  let t1 ← fp8.muladd_row t self mi1 0#usize
  let mi2 ← Array.index_usize rhs 1#usize
  let t2 ← fp8.muladd_row t1 self mi2 1#usize
  let mi3 ← Array.index_usize rhs 2#usize
  let t3 ← fp8.muladd_row t2 self mi3 2#usize
  let mi4 ← Array.index_usize rhs 3#usize
  let t4 ← fp8.muladd_row t3 self mi4 3#usize
  let mi5 ← Array.index_usize rhs 4#usize
  let t5 ← fp8.muladd_row t4 self mi5 4#usize
  let mi6 ← Array.index_usize rhs 5#usize
  let t6 ← fp8.muladd_row t5 self mi6 5#usize
  let mi7 ← Array.index_usize rhs 6#usize
  let t7 ← fp8.muladd_row t6 self mi7 6#usize
  let mi8 ← Array.index_usize rhs 7#usize
  let t8 ← fp8.muladd_row t7 self mi8 k
  fp8.Fp8.reduce t8

example : mulWith 7#usize = fp8.Fp8.mul := rfl

def Lane.mulWith (k : Fin LIMBS) (self rhs : Limbs) : Limbs :=
  let p := splat_limbs (.ofList P)
  let pinv := splat (.ofNat P_INV52)
  let t : Acc := .replicate _ zero
  let t := muladd_row t self rhs[0] 0
  let t := muladd_row t self rhs[1] 1
  let t := muladd_row t self rhs[2] 2
  let t := muladd_row t self rhs[3] 3
  let t := muladd_row t self rhs[4] 4
  let t := muladd_row t self rhs[5] 5
  let t := muladd_row t self rhs[6] 6
  let t := muladd_row t self rhs[7] k
  let t := reduce_row t p pinv 0
  let t := reduce_row t p pinv 1
  let t := reduce_row t p pinv 2
  let t := reduce_row t p pinv 3
  let t := reduce_row t p pinv 4
  let t := reduce_row t p pinv 5
  let t := reduce_row t p pinv 6
  let t := reduce_row t p pinv 7

  let mask := splat (.ofNat MASK52)
  let r : Limbs := .replicate _ zero
  let r := r.set 0 t[LIMBS]
  (List.finRange (LIMBS - 1)).foldl (carryStep t mask) r

example : Lane.mulWith 7 = Lane.mul := rfl

set_option hygiene false in
/-- The proof of `Fp8.mul_refines`, over `mulWith`, and over `Lane.mulWith` where the claim
names it. -/
-- Keep the shared reduction rows folded while comparing the product row indices.
local macro "mul_proof" : tactic => `(tactic| (
  intro self rhs
  obtain ⟨A, rfl⟩ : ∃ A : Vector M512 LIMBS, self = toArray id A :=
    ⟨ofArray id self, (toArray_ofArray (fun _ => rfl) self _ _).symm⟩
  obtain ⟨B, rfl⟩ : ∃ B : Vector M512 LIMBS, rhs = toArray id B :=
    ⟨ofArray id rhs, (toArray_ofArray (fun _ => rfl) rhs _ _).symm⟩
  unfold mulWith
  simp only [Simd.zero_refines, bind_tc_ok]
  rw [repeat_eq_toArray_id Simd.zero (show (17#usize).val = 2 * LIMBS + 1 from rfl)]
  simp (disch := decide) only [index_usize_toArray, Lane.muladd_row_refines,
    bind_tc_ok, ofArray_toArray_id, laneOf_fromLanes]
  rw [Fp8.reduce_refines]
  simp only [toFp8, Fp8.mul, Fp8.limbs_ofLanes_ofFn, Fp8.lane_eq, limbs_ofFp8,
    ofArray_toArray_id, laneOf_fromLanes]
  refine congrArg (fun F => ok (toArray id (fromLanes F) rfl)) (funext fun l => ?_)
  simp only [Lane.reduce, Reduction.referenceRows, Lane.finRange_LIMBS, List.foldl_cons, List.foldl_nil,
    Lane.referenceRow_eq, Reduction.finish, Lane.carryStep_eq, Lane.mul, Lane.mulAcc, Lane.mulWith,
    Lane.splat_limbs_eq, Lane.splat_eq, Lane.zero, laneOf_replicate, Fin.getElem_fin,
    Simd.getElem_zero, getElem_laneOf, getElem_ofArray, id_eq, UScalar.ofNatCore_val_eq,
    fin_mk_zero, fin_mk_one, fin_mk_ofNat, MASK52, LIMB_BITS]
  rfl))

attribute [local irreducible] Lane.reduce_row Lane.muladd_row in
example : ∀ self rhs : fp8.Fp8,
    mulWith 7#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  mul_proof

attribute [local irreducible] Lane.reduce_row Lane.muladd_row in
example : True := by
  fail_if_success
    have : ∀ self rhs : fp8.Fp8,
        mulWith 6#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
      mul_proof
  trivial

attribute [local irreducible] Lane.reduce_row Lane.muladd_row in
theorem mulWith_six_refines : ∀ self rhs : fp8.Fp8,
    mulWith 6#usize self rhs = ok (toFp8 (Fp8.ofLanes (.ofFn fun l =>
      Lane.mulWith 6 ((ofFp8 self).lane l) ((ofFp8 rhs).lane l)))) := by
  mul_proof

theorem lane_mulWith_six_ne :
    Lane.mulWith 6 (.ofList R2_MOD_P) (.ofList R2_MOD_P) ≠
      Lane.mul (.ofList R2_MOD_P) (.ofList R2_MOD_P) := by
  decide +kernel

example : ¬ ∀ self rhs : fp8.Fp8,
    mulWith 6#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  intro h
  let x := toFp8 (Fp8.splat_limbs (.ofList R2_MOD_P))
  have e := congrArg ofFp8 (Result.ok.inj ((mulWith_six_refines x x).symm.trans (h x x)))
  simp only [ofFp8_toFp8] at e
  have e0 := congrArg (Fp8.lane · 0) e
  simp only [Fp8.mul, Fp8.lane_ofLanes, Vector.getElem_ofFn, x, ofFp8_toFp8,
    Fp8.lane_splat_limbs] at e0
  exact lane_mulWith_six_ne e0

end LeanBlsSimd
