import LeanBlsSimd.Msm8.Store

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

def referenceIndex (r : U32) : U32 := r &&& 2147483647#u32

def referenceSign (r : U32) (lane : ℕ) : U8 :=
  ⟨((r.bv.ushiftRight 31).setWidth 8).shiftLeft lane⟩

def referencesStep (refs : List U32) (group : ℕ)
    (state : Vector U32 8 × U8) (lane : Fin 8) : Vector U32 8 × U8 :=
  let r := refs[group * 8 + lane]!
  (state.1.set lane (referenceIndex r), state.2 ||| referenceSign r lane)

def referenceBatch (refs : List U32) (group : ℕ) : Vector U32 8 × U8 :=
  (List.finRange 8).foldl (referencesStep refs group) (Vector.replicate 8 0#u32, 0#u8)

private theorem references_body_refines (refs : Slice U32) (g : Usize)
    (hg : g.val * 8 + 8 ≤ refs.val.length) (v : Vector U32 8 × U8)
    (lane : Usize) (j : Fin 8) (hj : lane.val = j.val) :
    ∃ next, next.val = j.val + 1 ∧
      msm8.pairs.references_loop.body refs g (toArray id v.1) v.2 lane =
        ok (cont (toArray id (referencesStep refs.val g.val v j).1,
          (referencesStep refs.val g.val v j).2, next)) := by
  have hl : lane.val < 8 := by omega
  have hs : refs.val.length < 2 ^ UScalarTy.Usize.numBits := by
    have h := refs.property
    simp only [Usize.max, Usize.numBits, UScalarTy.numBits] at h ⊢
    have hp : 0 < (2 : ℕ) ^ System.Platform.numBits := by positivity
    omega
  let base : Usize := UScalar.ofNatCore (g.val * 8) (by omega)
  let k : Usize := UScalar.ofNatCore (g.val * 8 + lane.val) (by omega)
  let next : Usize := UScalar.ofNatCore (lane.val + 1)
    (by have := two_pow_32_le_usize; omega)
  have hkv : k.val = g.val * 8 + lane.val := UScalar.ofNatCore_val_eq _
  have hkl : k.val < refs.val.length := by omega
  have hbase : g * 8#usize = ok base := by
    rw [mul_ok _ _ (by change g.val * 8 < _; omega)]
    rfl
  have hk : base + lane = ok k := by
    rw [add_ok _ _ (by change g.val * 8 + lane.val < _; omega)]
    rfl
  have hn : lane + 1#usize = ok next := by
    rw [add_ok _ _ (by have := two_pow_32_le_usize; change lane.val + 1 < _; omega)]
    rfl
  have hidx : Slice.index_usize refs k = ok refs.val[k.val] := by
    simp [Slice.index_usize, hkl]
  have hsign (r : U32) : r >>> 31#i32 = ok (⟨r.bv.ushiftRight 31⟩ : U32) := rfl
  have hneg : msm8.pairs.NEGATED = ok 2147483648#u32 := by
    unfold msm8.pairs.NEGATED
    rfl
  refine ⟨next, by simp [next, hj], ?_⟩
  simp only [msm8.pairs.references_loop.body, limbs.LANES, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, hl, ↓reduceIte, hbase, bind_tc_ok, hk, hidx, hneg,
    lift, update_eq (n := 8#usize) _ lane _ hl, hsign,
    shiftLeft_ok (ty := .U8) _ lane (by exact hl), hn]
  have hget : refs.val[g.val * 8 + j.val]! = refs.val[k.val] := by
    simp [k, hj, show g.val * 8 + j.val < refs.val.length by omega]
  simp only [referencesStep, hget, referenceIndex, referenceSign]
  rw [show (~~~2147483648#u32) = 2147483647#u32 by decide]
  apply congrArg ok
  apply congrArg cont
  apply Prod.ext
  · simpa only [id_eq, hj] using (set_toArray (n := 8#usize) id v.1 rfl lane
      (refs.val[k.val] &&& 2147483647#u32) hl)
  · simp only [hj]
    rfl

theorem references_refines (refs : Slice U32) (g : Usize)
    (hg : g.val * 8 + 8 ≤ refs.val.length) :
    msm8.pairs.references refs g =
      ok (toArray id (referenceBatch refs.val g.val).1, (referenceBatch refs.val g.val).2) := by
  unfold msm8.pairs.references msm8.pairs.references_loop
  rw [show Array.repeat 8#usize 0#u32 = toArray id (Vector.replicate 8 0#u32) from
    (toArray_replicate id 0#u32 rfl).symm]
  exact loop_up_inv
    (fun (v, mask, lane) => msm8.pairs.references_loop.body refs g v mask lane)
    (fun v lane => (toArray id v.1, v.2, lane)) (referencesStep refs.val g.val)
    (fun v => (toArray id v.1, v.2)) (fun _ => True) (fun _ _ _ => trivial)
    (by intro v c hc _; simp [msm8.pairs.references_loop.body, limbs.LANES, UScalar.lt_equiv, hc])
    (fun v c j hj _ => references_body_refines refs g hg v c j hj)
    (Vector.replicate 8 0#u32, 0#u8) 0#usize (by decide) trivial

theorem referenceBatch_indices (refs : List U32) (g : ℕ) :
    (referenceBatch refs g).1 =
      Vector.ofFn (fun lane : Fin 8 => referenceIndex refs[g * 8 + lane]!) := by
  have hf (lanes : List (Fin 8)) (state : Vector U32 8 × U8) :
      (lanes.foldl (referencesStep refs g) state).1 =
        lanes.foldl (fun v lane => v.set lane (referenceIndex refs[g * 8 + lane]!)) state.1 := by
    induction lanes generalizing state with
    | nil => rfl
    | cons lane lanes ih => exact ih _
  rw [referenceBatch, hf, foldl_set_ofFn]

theorem referenceIndex_val (r : U32) : (referenceIndex r).val = r.val % 2 ^ 31 := by
  change r.bv.toNat &&& (2147483647#32).toNat = _
  change r.val &&& (2 ^ 31 - 1) = _
  exact Nat.and_two_pow_sub_one_eq_mod _ _

theorem referenceSign_bit (r : U32) (lane j : Fin 8) :
    (referenceSign r lane).bv.getLsbD j = (decide (j = lane) && r.bv.getLsbD 31) := by
  change (((r.bv.ushiftRight 31).setWidth 8).shiftLeft lane).getLsbD j = _
  simp only [BitVec.shiftLeft_eq, BitVec.ushiftRight_eq]
  rw [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth, BitVec.getLsbD_ushiftRight]
  by_cases h : j = lane
  · subst j
    simp
  · have hval : j.val ≠ lane.val := fun he => h (Fin.ext he)
    by_cases hlt : j.val < lane.val
    · simp [h, hlt]
    · have hbit : r.bv.getLsbD (31 + (j.val - lane.val)) = false :=
        BitVec.getLsbD_of_ge _ _ (by omega)
      simp [h, hlt, hbit]

theorem referenceBatch_sign (refs : List U32) (g : ℕ) (j : Fin 8) :
    (referenceBatch refs g).2.bv.getLsbD j = refs[g * 8 + j]!.bv.getLsbD 31 := by
  have hf (lanes : List (Fin 8)) (state : Vector U32 8 × U8) :
      (lanes.foldl (referencesStep refs g) state).2.bv.getLsbD j =
        (state.2.bv.getLsbD j || (decide (j ∈ lanes) && refs[g * 8 + j]!.bv.getLsbD 31)) := by
    induction lanes generalizing state with
    | nil => simp
    | cons lane lanes ih =>
      rw [List.foldl_cons, ih]
      change (((state.2 ||| referenceSign refs[g * 8 + lane]! lane).bv.getLsbD j) || _) = _
      change (((state.2.bv ||| (referenceSign refs[g * 8 + lane]! lane).bv).getLsbD j) || _) = _
      rw [BitVec.getLsbD_or, referenceSign_bit]
      by_cases h : j = lane
      · subst j
        cases refs[g * 8 + lane]!.bv.getLsbD 31 <;> simp
      · simp [h]
  rw [referenceBatch, hf]
  simp

end LeanBlsSimd.Msm8
