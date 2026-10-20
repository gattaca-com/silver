import LeanBlsSimd.Refines.Fr8Interleaving
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
  unfold fr8.Fr8.mul fr8.Fr8.product
  simp only [Simd.zero_refines, bind_tc_ok]
  unfold fr8.Fr8.reduce
  simp only [Simd.splat_limbs_refines, P_refines, Simd.splat_refines, P_INV52_refines,
    bind_tc_ok, LIMBS_refines]
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

def Fr8.productValue (a b : fr8.Fr8) : Array M512 11#usize :=
  toArray id (fromLanes fun l => Lane.productAcc ((ofFr8 a).lane l) ((ofFr8 b).lane l))

def Fr8.reduceValue (t : Array M512 11#usize) : fr8.Fr8 :=
  toArray id (fromLanes fun l => Vector.ofFn fun j : Fin LIMBS =>
    (Reduction.earlyRows (laneOf (ofArray id t) l) (Limbs.ofList P)
      (.ofNat P_INV52))[LIMBS + j.val])

attribute [local irreducible] Lane.muladd_row in
theorem Fr8.product_refines (a b : fr8.Fr8) :
    fr8.Fr8.product a b = ok (Fr8.productValue a b) := by
  obtain ⟨B, rfl⟩ : ∃ B : Vector M512 LIMBS, b = toArray id B :=
    ⟨ofArray id b, (toArray_ofArray (fun _ => rfl) b _ _).symm⟩
  unfold fr8.Fr8.product
  simp only [Simd.zero_refines, bind_tc_ok]
  rw [repeat_eq_toArray_id Simd.zero (show (11#usize).val = 2 * LIMBS + 1 from rfl)]
  simp (disch := decide) only [index_usize_toArray, Lane.muladd_row_refines,
    bind_tc_ok, ofArray_toArray_id, laneOf_fromLanes]
  simp only [Fr8.productValue, Lane.productAcc, Fr8.lane_eq, limbs_ofFr8,
    laneOf_replicate, Simd.getElem_zero, Lane.zero, getElem_laneOf, Fin.getElem_fin,
    ofArray_toArray_id, id_eq]
  rfl

attribute [local irreducible] Reduction.earlyRow in
theorem Fr8.reduce_refines (t : Array M512 11#usize) :
    fr8.Fr8.reduce t = ok (Fr8.reduceValue t) := by
  unfold fr8.Fr8.reduce
  simp only [Simd.splat_limbs_refines, P_refines, Simd.splat_refines, P_INV52_refines,
    bind_tc_ok, LIMBS_refines]
  simp (disch := decide) only [Lane.reduce_row_refines, bind_tc_ok,
    ofArray_toArray_id, laneOf_fromLanes, usize_add_ok, UScalar.ofNatCore_val_eq,
    index_usize_toArray]
  simp only [id_eq, Nat.reduceAdd]
  rw [raw_array, raw_fromLanes]
  simp only [Fr8.reduceValue, Reduction.earlyRows, Lane.finRange_LIMBS,
    List.foldl_cons, List.foldl_nil, ofU64_toU64, Simd.laneOf_splat_limbs,
    ofArray_toArray_ofU64, Fin.getElem_fin, Simd.getElem_splat]
  rfl

theorem Fr8.product_success (a b : fr8.Fr8) :
    ∃ p, fr8.Fr8.product a b = ok p := ⟨_, Fr8.product_refines a b⟩

attribute [local irreducible] Lane.productAcc in
theorem Fr8.product_bound (a b : fr8.Fr8) :
    ∃ p, fr8.Fr8.product a b = ok p ∧
      ∀ (k : Fin (2 * LIMBS + 1)) (l : Fin 8),
        (laneOf (ofArray id p (m := 2 * LIMBS + 1)) l)[k].toNat < 2 ^ 56 := by
  refine ⟨_, Fr8.product_refines a b, ?_⟩
  intro k l
  simpa only [Fr8.productValue, ofArray_toArray_id, laneOf_fromLanes] using
    Lane.productAcc_bound ((ofFr8 a).lane l) ((ofFr8 b).lane l) k

theorem Fr8.reduce_success (t : Array M512 11#usize) :
    ∃ r, fr8.Fr8.reduce t = ok r := ⟨_, Fr8.reduce_refines t⟩

theorem Fr8.mul_eq_reduce_product (a b : fr8.Fr8) :
    fr8.Fr8.mul a b = (do let p ← fr8.Fr8.product a b; fr8.Fr8.reduce p) := rfl

theorem Fr8.reduceValue_productValue (a b : fr8.Fr8) :
    Fr8.reduceValue (Fr8.productValue a b) = toFr8 ((ofFr8 a).mulRaw (ofFr8 b)) := by
  have h := Fr8.mul_refines a b
  simpa only [fr8.Fr8.mul, Fr8.product_refines, bind_tc_ok, Fr8.reduce_refines,
    Result.ok.injEq] using h

attribute [local irreducible] Lane.muladd_row Reduction.earlyRow in
theorem Fr8.reduce_while_multiplying_eq (t : Array M512 11#usize) (a b : fr8.Fr8) :
    fr8.Fr8.reduce_while_multiplying t a b = (do
      let r ← fr8.Fr8.reduce t
      let p ← fr8.Fr8.product a b
      ok (r, p)) := by
  let r : Array M512 5#usize := toArray id (Simd.splat_limbs (ofArray ofU64 fr8.R))
  let rinv := Simd.splat (ofU64 fr8.R_INV52)
  let next := Array.repeat 11#usize Simd.zero
  obtain ⟨t1, ht1⟩ : ∃ v, fr8.reduce_row t r rinv 0#usize = ok v :=
    ⟨_, Lane.reduce_row_refines t r rinv 0#usize (by decide)⟩
  obtain ⟨t2, ht2⟩ : ∃ v, fr8.reduce_row t1 r rinv 1#usize = ok v :=
    ⟨_, Lane.reduce_row_refines t1 r rinv 1#usize (by decide)⟩
  obtain ⟨t3, ht3⟩ : ∃ v, fr8.reduce_row t2 r rinv 2#usize = ok v :=
    ⟨_, Lane.reduce_row_refines t2 r rinv 2#usize (by decide)⟩
  obtain ⟨t4, ht4⟩ : ∃ v, fr8.reduce_row t3 r rinv 3#usize = ok v :=
    ⟨_, Lane.reduce_row_refines t3 r rinv 3#usize (by decide)⟩
  obtain ⟨t5, ht5⟩ : ∃ v, fr8.reduce_row t4 r rinv 4#usize = ok v :=
    ⟨_, Lane.reduce_row_refines t4 r rinv 4#usize (by decide)⟩
  obtain ⟨p1, hp1⟩ : ∃ v, fr8.muladd_row next a b.val[0] 0#usize = ok v :=
    ⟨_, Lane.muladd_row_refines next a b.val[0] 0#usize (by decide)⟩
  obtain ⟨p2, hp2⟩ : ∃ v, fr8.muladd_row p1 a b.val[1] 1#usize = ok v :=
    ⟨_, Lane.muladd_row_refines p1 a b.val[1] 1#usize (by decide)⟩
  obtain ⟨p3, hp3⟩ : ∃ v, fr8.muladd_row p2 a b.val[2] 2#usize = ok v :=
    ⟨_, Lane.muladd_row_refines p2 a b.val[2] 2#usize (by decide)⟩
  obtain ⟨p4, hp4⟩ : ∃ v, fr8.muladd_row p3 a b.val[3] 3#usize = ok v :=
    ⟨_, Lane.muladd_row_refines p3 a b.val[3] 3#usize (by decide)⟩
  obtain ⟨p5, hp5⟩ : ∃ v, fr8.muladd_row p4 a b.val[4] 4#usize = ok v :=
    ⟨_, Lane.muladd_row_refines p4 a b.val[4] 4#usize (by decide)⟩
  dsimp only [r, rinv, next] at ht1 ht2 ht3 ht4 ht5 hp1 hp2 hp3 hp4 hp5
  unfold fr8.Fr8.reduce_while_multiplying fr8.Fr8.reduce fr8.Fr8.product
  simp only [Simd.splat_limbs_refines, Simd.splat_refines, Simd.zero_refines, bind_tc_ok]
  simp (disch := decide) only [Lane.reduce_row_multiplying_refines,
    ht1, ht2, ht3, ht4, ht5, hp1, hp2, hp3, hp4, hp5,
    bind_tc_ok, Function.uncurry_apply_pair, index_usize_eq, LIMBS_refines,
    usize_add_ok, UScalar.ofNatCore_val_eq]

theorem Fr8.reduce_while_multiplying_refines (t : Array M512 11#usize) (a b : fr8.Fr8) :
    fr8.Fr8.reduce_while_multiplying t a b =
      ok (Fr8.reduceValue t, Fr8.productValue a b) := by
  simp only [Fr8.reduce_while_multiplying_eq, Fr8.reduce_refines,
    Fr8.product_refines, bind_tc_ok]

end LeanBlsSimd.FrModel
