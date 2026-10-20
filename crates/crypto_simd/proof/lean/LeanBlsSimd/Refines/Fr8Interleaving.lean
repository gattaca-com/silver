import LeanBlsSimd.Refines.Fr8Core

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

theorem Lane.reduce_multiplying_high_refines (t : Array M512 11#usize) (p : Array M512 5#usize)
    (i : Usize) (hi : i.val < LIMBS) (q : M512) :
    fr8.reduce_row_multiplying_loop1 { start := 0#usize, «end» := fr8.LIMBS } t p i q =
      ok (toArray id (fromLanes fun l =>
        (List.finRange LIMBS).foldl
          (Reduction.highStep (laneOf (ofArray id p) l) q[l] ⟨i.val, hi⟩)
          (laneOf (ofArray id t) l))) := by
  unfold fr8.reduce_row_multiplying_loop1
  simp only [LIMBS_refines]
  let P : Vector M512 LIMBS := ofArray id p
  have hij : ∀ j : Fin LIMBS, i.val + j.val + 1 < 2 * LIMBS + 1 := by
    intro j; have := j.isLt; unfold LIMBS at *; omega
  let step := fun (T : Vector M512 (2 * LIMBS + 1)) (j : Fin LIMBS) =>
    T.set (i.val + j.val + 1) (_mm512_madd52hi_epu64 T[i.val + j.val + 1] P[j] q) (hij j)
  conv_lhs => rw [show t = toArray id (ofArray id t (n := 11#usize) (m := 2 * LIMBS + 1) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) t _ _).symm]
  trans ok (toArray id ((List.finRange LIMBS).foldl step (ofArray id t)))
  · refine loop_range_inv (n := LIMBS) _ 5#usize rfl (toArray id) step (toArray id)
      (fun _ _ => True) (fun _ _ _ => trivial) ?_ ?_ 0#usize (ofArray id t) (by decide) trivial
    · intro r m he hs _ hn
      simp_body fr8.reduce_row_multiplying_loop1.body hn
    · intro r r' m j he hs he' hs' _ hn
      have hi' : i.val < 5 := hi
      have hj' : r.start.val < 5 := by rw [hs]; exact j.isLt
      simp_body fr8.reduce_row_multiplying_loop1.body hn
      simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
        core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64, UScalar.ofNatCore_val_eq]
      refine congrArg (fun s => ok (cont (r', s))) ?_
      exact toArray_set_of_eq id m _ _ (i.val + j.val + 1) (hij j)
        (_mm512_madd52hi_epu64 m[i.val + j.val + 1] P[j] q) _ (by simp [hs]) (by simp [P, hs])
  · suffices H : (List.finRange LIMBS).foldl step (ofArray id t) =
        fromLanes (fun l => (List.finRange LIMBS).foldl
          (Reduction.highStep (laneOf P l) q[l] ⟨i.val, hi⟩) (laneOf (ofArray id t) l)) by
      rw [H]
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    refine List.foldl_hom (fun T => laneOf T l) ?_
    intro T j
    simp only [step, laneOf_set]
    simp [Reduction.highStep]

private theorem reduce_multiplying_low_eq :
    fr8.reduce_row_multiplying_loop0 = fr8.reduce_row_loop0 := rfl

private theorem high_fold_zero (t : Lane.Acc) (p : Limbs) (q : UInt64) (i : Fin LIMBS) :
    (List.finRange LIMBS).foldl (Reduction.highStep p q i) t =
      ((List.finRange LIMBS).drop 1).foldl (Reduction.highStep p q i)
        (t.set (i.val + 1) (t[i.val + 1] + madd52hi 0 p[0] q)) := by
  conv_lhs => rw [show List.finRange LIMBS = 0 :: (List.finRange LIMBS).drop 1 from by decide]
  simp only [List.foldl_cons, Reduction.highStep, Fin.val_zero, Nat.add_zero,
    madd52hi, UInt64.zero_add]
  rfl

attribute [local irreducible] Reduction.lowStep Reduction.highStep Lane.muladd_row in
theorem Lane.reduce_row_multiplying_refines
    (t : Array M512 11#usize) (p : Array M512 5#usize) (pinv : M512)
    (i : Usize) (hi : i.val < LIMBS) (next : Array M512 11#usize)
    (a : Array M512 5#usize) (b : M512) :
    fr8.reduce_row_multiplying t p pinv i next a b = (do
      let t' ← fr8.reduce_row t p pinv i
      let next' ← fr8.muladd_row next a b i
      ok (t', next')) := by
  obtain ⟨T, rfl⟩ : ∃ T : Vector M512 (2 * LIMBS + 1), t = toArray id T :=
    ⟨ofArray id t, (toArray_ofArray (fun _ => rfl) t _ _).symm⟩
  obtain ⟨P, rfl⟩ : ∃ P : Vector M512 LIMBS, p = toArray id P :=
    ⟨ofArray id p, (toArray_ofArray (fun _ => rfl) p _ _).symm⟩
  have hi' : i.val < 5 := hi
  rw [Lane.reduce_row_refines _ _ _ _ hi]
  unfold fr8.reduce_row_multiplying
  simp (disch := (simp; omega)) only [Simd.zero_refines, bind_tc_ok, index_usize_toArray,
    core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64,
    core.core_arch.x86.avx512f._mm512_add_epi64, LeanBlsSimd.Simd.carry_of_cleared_refines,
    usize_add_ok, update_eq, set_toArray_id, UScalar.ofNatCore_val_eq,
    Lane.muladd_row_refines _ _ _ _ hi, reduce_multiplying_low_eq]
  rw [Lane.reduce_low_refines _ _ _ hi]
  simp only [bind_tc_ok]
  rw [Lane.reduce_multiplying_high_refines _ _ _ hi]
  simp only [bind_tc_ok, ofArray_toArray_id, laneOf_set, laneOf_fromLanes]
  simp [Reduction.earlyRow, high_fold_zero]

end LeanBlsSimd.FrModel
