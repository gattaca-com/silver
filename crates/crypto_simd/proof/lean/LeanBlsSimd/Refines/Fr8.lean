import LeanBlsSimd.Refines.Fr8Core
import LeanBlsSimd.Proofs.Fr8Product

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

private theorem raw_array (T : Vector M512 (2 * LIMBS + 1)) :
    Array.make 5#usize [T[5], T[6], T[7], T[8], T[9]] (by rfl) =
    toArray id (Vector.ofFn fun j : Fin LIMBS => T[LIMBS + j.val]) := by
  apply Subtype.ext
  apply List.ext_getElem
  · simp [Array.make, toArray, LIMBS]
  intro j hj hj'
  have hj5 : j < 5 := by simpa [Array.make] using hj
  interval_cases j <;> simp [Array.make, toArray, LIMBS] <;> rfl

private theorem raw_fromLanes (T : Fin 8 → Lane.Acc) :
    (Vector.ofFn fun j : Fin LIMBS => (fromLanes T)[LIMBS + j.val]) =
      fromLanes (fun l => Vector.ofFn fun j : Fin LIMBS => (T l)[LIMBS + j.val]) := by
  ext j hj l hl
  simp [fromLanes]

attribute [local irreducible] Lane.muladd_row Reduction.earlyRow Lane.mulAcc Lane.mulRaw in
theorem Fr8.mul_refines (self rhs : fr8.Fr8) :
    fr8.Fr8.mul self rhs = ok (toFr8 ((ofFr8 self).mulRaw (ofFr8 rhs))) := by
  obtain ⟨A, rfl⟩ : ∃ A : Vector M512 LIMBS, self = toArray id A :=
    ⟨ofArray id self, (toArray_ofArray (fun _ => rfl) self _ _).symm⟩
  obtain ⟨B, rfl⟩ : ∃ B : Vector M512 LIMBS, rhs = toArray id B :=
    ⟨ofArray id rhs, (toArray_ofArray (fun _ => rfl) rhs _ _).symm⟩
  unfold fr8.Fr8.mul
  simp only [Simd.splat_limbs_refines, P_refines, Simd.splat_refines, P_INV52_refines,
    Simd.zero_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (11#usize).val = 2 * LIMBS + 1 from rfl)]
  simp (disch := decide) only [index_usize_toArray, Lane.muladd_row_refines,
    Lane.reduce_row_refines, bind_tc_ok, ofArray_toArray_id, laneOf_fromLanes]
  simp (disch := decide) only [usize_add_ok, bind_tc_ok, UScalar.ofNatCore_val_eq,
    index_usize_toArray]
  simp only [id_eq, Nat.reduceAdd, laneOf_replicate, ofU64_toU64,
    Simd.laneOf_splat_limbs, ofArray_toArray_ofU64]
  rw [raw_array]
  rw [raw_fromLanes]
  simp only [toFr8, Fr8.mulRaw, Fr8.limbs_ofLanes_ofFn, Fr8.lane_eq, limbs_ofFr8,
    ofArray_toArray_id]
  refine congrArg (fun F => ok (toArray id (fromLanes F) rfl)) (funext fun l => ?_)
  apply Vector.ext
  intro j hj
  simp only [Vector.getElem_ofFn, Fin.getElem_fin, Simd.getElem_zero,
    Simd.getElem_splat, Lane.mulRaw]
  simpa only [Reduction.earlyRows, Lane.finRange_LIMBS, List.foldl_cons,
    List.foldl_nil, Lane.productAcc, Lane.zero, getElem_laneOf, Fin.getElem_fin,
    Fin.val_zero, Fin.val_one, Fin.val_ofNat] using
    Lane.earlyRows_productAcc (laneOf A l) (laneOf B l) (LIMBS + j) (by omega) (by omega)

end LeanBlsSimd.FrModel
