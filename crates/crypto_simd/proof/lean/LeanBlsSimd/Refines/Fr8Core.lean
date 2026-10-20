import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Proofs.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

theorem LIMBS_refines : fr8.LIMBS = 5#usize := by rw [fr8.LIMBS]

theorem MASK52_refines : fr8.MASK52 = ok (toU64 (.ofNat MASK52)) := by
  rw [fr8.MASK52, fr8.LIMB_BITS]; rfl

theorem P_refines : fr8.R = toArray toU64 (Limbs.ofList P) := by rw [fr8.R]; rfl

theorem P_INV52_refines : fr8.R_INV52 = toU64 (.ofNat P_INV52) := by
  rw [fr8.R_INV52]; rfl

def ofFr8 (a : fr8.Fr8) : Fr8 := ⟨ofArray id a⟩

def toFr8 (x : Fr8) : fr8.Fr8 := toArray id x.limbs

@[simp] theorem limbs_ofFr8 (a : fr8.Fr8) : (ofFr8 a).limbs = ofArray id a := rfl

@[simp] theorem ofFr8_toFr8 (x : Fr8) : ofFr8 (toFr8 x) = x := by
  simp [ofFr8, toFr8, ofArray_toArray]

@[simp] theorem toFr8_ofFr8 (a : fr8.Fr8) : toFr8 (ofFr8 a) = a := by
  simp [ofFr8, toFr8, toArray_ofArray]

theorem Fr8.limbs_ofLanes_ofFn (lanes : Fin 8 → Limbs) :
    (Fr8.ofLanes (.ofFn lanes)).limbs = fromLanes lanes := by
  ext j hj l hl
  simp [Fr8.ofLanes, fromLanes]

theorem Simd.splat_refines (x : U64) : fr8.splat x = ok (Simd.splat (ofU64 x)) := rfl

theorem Simd.zero_refines : fr8.zero = ok Simd.zero := rfl

theorem Simd.borrowed_refines (borrow : M512) :
    fr8.borrowed borrow = ok (toU8 (Simd.borrowed borrow)) := rfl

theorem Simd.splat_limbs_refines (limbs : Array U64 5#usize) :
    fr8.splat_limbs limbs = ok (toArray id (Simd.splat_limbs (ofArray ofU64 limbs))) := by
  unfold fr8.splat_limbs fr8.splat_limbs_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 5#usize rfl (toArray id)
    (fun v j => v.set j (Simd.splat (ofArray ofU64 limbs)[j])) (toArray id)
    (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.splat_limbs_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.splat_limbs_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, Simd.splat_refines, update_eq _ _ _ hj]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Simd.splat_limbs, foldl_set_ofFn]

theorem Simd.sub_limbs_refines (a b : Array M512 5#usize) :
    fr8.sub_limbs a b =
      ok (Prod.map (toArray id) id (Simd.sub_limbs (ofArray id a) (ofArray id b))) := by
  unfold fr8.sub_limbs fr8.sub_limbs_loop
  simp only [MASK52_refines, Simd.splat_refines, Simd.zero_refines, bind_tc_ok, LIMBS_refines,
    ofU64_toU64]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 5#usize rfl (Prod.map (toArray id) id)
    (fun (d, borrow) j =>
      let s := _mm512_add_epi64 (_mm512_sub_epi64 (ofArray id a)[j] (ofArray id b)[j]) borrow
      (d.set j (_mm512_and_si512 s (Simd.splat (.ofNat MASK52))), _mm512_srai_epi64 63 s))
    (Prod.map (toArray id) id) (Vector.replicate LIMBS Simd.zero, Simd.zero) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fr8.sub_limbs_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    obtain ⟨d, borrow⟩ := m
    simp_body fr8.sub_limbs_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_sub_epi64, core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_srai_epi64, core.core_arch.x86.avx512f._mm512_and_si512,
      Prod.map, id]
    refine congrArg (fun s => ok (cont (r', s))) (Prod.ext ?_ ?_)
    · apply Subtype.ext
      simp [hs, List.map_set, Vector.toList_set]
    · simp [hs]

theorem Simd.select_borrowed_refines (borrow : M512) (b a : Array M512 5#usize) :
    fr8.select_borrowed borrow b a = ok (toArray id (Simd.blend (Simd.borrowed borrow) (ofArray id a) (ofArray id b))) := by
  unfold fr8.select_borrowed fr8.select_borrowed_loop
  simp only [Simd.borrowed_refines, bind_tc_ok, Simd.zero_refines, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 5#usize rfl (toArray id)
    (fun v j => v.set j (_mm512_mask_blend_epi64 (Simd.borrowed borrow) (ofArray id a)[j] (ofArray id b)[j]))
    (toArray id) (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.select_borrowed_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.select_borrowed_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok,
      core.core_arch.x86.avx512f._mm512_mask_blend_epi64, ofU8_toU8, update_eq _ _ _ hj]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Simd.blend, foldl_set_ofFn]

theorem Lane.muladd_row_refines (t : Array M512 11#usize) (a : Array M512 5#usize) (b_i : M512)
    (i : Usize) (hi : i.val < LIMBS) :
    fr8.muladd_row t a b_i i = ok (toArray id (fromLanes fun l =>
      Lane.muladd_row (laneOf (ofArray id t) l) (laneOf (ofArray id a) l) b_i[l] ⟨i.val, hi⟩)) := by
  unfold fr8.muladd_row fr8.muladd_row_loop
  simp only [LIMBS_refines]
  let A : Vector M512 LIMBS := ofArray id a
  have hij : ∀ j : Fin LIMBS, i.val + j.val + 1 < 2 * LIMBS + 1 := by
    intro j; have := j.isLt; unfold LIMBS at *; omega
  let step := fun (T : Vector M512 (2 * LIMBS + 1)) (j : Fin LIMBS) =>
    let T := T.set (i.val + j.val) (_mm512_madd52lo_epu64 T[i.val + j.val] A[j] b_i)
      (by have := hij j; omega)
    T.set (i.val + j.val + 1) (_mm512_madd52hi_epu64 T[i.val + j.val + 1] A[j] b_i) (hij j)
  conv_lhs => rw [show t = toArray id (ofArray id t (n := 11#usize) (m := 2 * LIMBS + 1) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) t _ _).symm]
  refine loop_range (n := LIMBS) _ 5#usize rfl (toArray id) step (toArray id) (ofArray id t) _
    ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.muladd_row_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hi8 : i.val < 5 := hi
    have hj8 : r.start.val < 5 := by rw [hs]; exact j.isLt
    simp_body fr8.muladd_row_loop.body hn
    simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
      core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64,
      core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64, UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    have e1 : i.val + j.val < 2 * LIMBS + 1 := by have := hij j; omega
    let X := _mm512_madd52lo_epu64 m[i.val + j.val] A[j] b_i
    rw [toArray_set_of_eq id m _ _ (i.val + j.val) e1 X _ (by simp [hs]) (by simp [X, A, hs])]
    exact toArray_set_of_eq id _ _ _ (i.val + j.val + 1) (hij j)
      (_mm512_madd52hi_epu64 (m.set (i.val + j.val) X e1)[i.val + j.val + 1] A[j] b_i) _
      (by simp [hs]) (by simp [A, hs])
  · suffices H : (List.finRange LIMBS).foldl step (ofArray id t) = fromLanes fun l =>
        Lane.muladd_row (laneOf (ofArray id t) l) (laneOf A l) b_i[l] ⟨i.val, hi⟩ by
      rw [H]
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    unfold Lane.muladd_row
    refine List.foldl_hom (fun T => laneOf T l) ?_
    intro T j
    simp only [step, laneOf_set, getElem_laneOf]
    simp [A]


theorem Lane.reduce_low_refines (t : Array M512 11#usize) (p : Array M512 5#usize)
    (i : Usize) (hi : i.val < LIMBS) (q : M512) :
    fr8.reduce_row_loop0 { start := 1#usize, «end» := fr8.LIMBS } t p i q =
      ok (toArray id (fromLanes fun l =>
        ((List.finRange LIMBS).drop 1).foldl
          (Reduction.lowStep (laneOf (ofArray id p) l) q[l] ⟨i.val, hi⟩)
          (laneOf (ofArray id t) l))) := by
  unfold fr8.reduce_row_loop0
  simp only [LIMBS_refines]
  let P : Vector M512 LIMBS := ofArray id p
  have hij : ∀ j : Fin LIMBS, i.val + j.val < 2 * LIMBS + 1 := by
    intro j; have := j.isLt; unfold LIMBS at *; omega
  let step := fun (T : Vector M512 (2 * LIMBS + 1)) (j : Fin LIMBS) =>
    T.set (i.val + j.val) (_mm512_madd52lo_epu64 T[i.val + j.val] P[j] q) (hij j)
  conv_lhs => rw [show t = toArray id (ofArray id t (n := 11#usize) (m := 2 * LIMBS + 1) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) t _ _).symm]
  trans ok (toArray id (((List.finRange LIMBS).drop 1).foldl step (ofArray id t)))
  · refine loop_range_inv (n := LIMBS) _ 5#usize rfl (toArray id) step (toArray id)
      (fun _ _ => True) (fun _ _ _ => trivial) ?_ ?_ 1#usize (ofArray id t) (by decide) trivial
    · intro r m he hs _ hn
      simp_body fr8.reduce_row_loop0.body hn
    · intro r r' m j he hs he' hs' _ hn
      have hi' : i.val < 5 := hi
      have hj' : r.start.val < 5 := by rw [hs]; exact j.isLt
      simp_body fr8.reduce_row_loop0.body hn
      simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
        core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64, UScalar.ofNatCore_val_eq]
      refine congrArg (fun s => ok (cont (r', s))) ?_
      exact toArray_set_of_eq id m _ _ (i.val + j.val) (hij j)
        (_mm512_madd52lo_epu64 m[i.val + j.val] P[j] q) _ (by simp [hs]) (by simp [P, hs])
  · suffices H : ((List.finRange LIMBS).drop 1).foldl step (ofArray id t) =
        fromLanes (fun l => ((List.finRange LIMBS).drop 1).foldl
          (Reduction.lowStep (laneOf P l) q[l] ⟨i.val, hi⟩) (laneOf (ofArray id t) l)) by
      rw [H]
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    refine List.foldl_hom (fun T => laneOf T l) ?_
    intro T j
    simp only [step, laneOf_set]
    simp [Reduction.lowStep]

theorem Lane.reduce_high_refines (t : Array M512 11#usize) (p : Array M512 5#usize)
    (i : Usize) (hi : i.val < LIMBS) (q : M512) :
    fr8.reduce_row_loop1 { start := 1#usize, «end» := fr8.LIMBS } t p i q =
      ok (toArray id (fromLanes fun l =>
        ((List.finRange LIMBS).drop 1).foldl
          (Reduction.highStep (laneOf (ofArray id p) l) q[l] ⟨i.val, hi⟩)
          (laneOf (ofArray id t) l))) := by
  unfold fr8.reduce_row_loop1
  simp only [LIMBS_refines]
  let P : Vector M512 LIMBS := ofArray id p
  have hij : ∀ j : Fin LIMBS, i.val + j.val + 1 < 2 * LIMBS + 1 := by
    intro j; have := j.isLt; unfold LIMBS at *; omega
  let step := fun (T : Vector M512 (2 * LIMBS + 1)) (j : Fin LIMBS) =>
    T.set (i.val + j.val + 1) (_mm512_madd52hi_epu64 T[i.val + j.val + 1] P[j] q) (hij j)
  conv_lhs => rw [show t = toArray id (ofArray id t (n := 11#usize) (m := 2 * LIMBS + 1) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) t _ _).symm]
  trans ok (toArray id (((List.finRange LIMBS).drop 1).foldl step (ofArray id t)))
  · refine loop_range_inv (n := LIMBS) _ 5#usize rfl (toArray id) step (toArray id)
      (fun _ _ => True) (fun _ _ _ => trivial) ?_ ?_ 1#usize (ofArray id t) (by decide) trivial
    · intro r m he hs _ hn
      simp_body fr8.reduce_row_loop1.body hn
    · intro r r' m j he hs he' hs' _ hn
      have hi' : i.val < 5 := hi
      have hj' : r.start.val < 5 := by rw [hs]; exact j.isLt
      simp_body fr8.reduce_row_loop1.body hn
      simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
        core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64, UScalar.ofNatCore_val_eq]
      refine congrArg (fun s => ok (cont (r', s))) ?_
      exact toArray_set_of_eq id m _ _ (i.val + j.val + 1) (hij j)
        (_mm512_madd52hi_epu64 m[i.val + j.val + 1] P[j] q) _ (by simp [hs]) (by simp [P, hs])
  · suffices H : ((List.finRange LIMBS).drop 1).foldl step (ofArray id t) =
        fromLanes (fun l => ((List.finRange LIMBS).drop 1).foldl
          (Reduction.highStep (laneOf P l) q[l] ⟨i.val, hi⟩) (laneOf (ofArray id t) l)) by
      rw [H]
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    refine List.foldl_hom (fun T => laneOf T l) ?_
    intro T j
    simp only [step, laneOf_set]
    simp [Reduction.highStep]

attribute [local irreducible] Reduction.lowStep Reduction.highStep in
theorem Lane.reduce_row_refines (t : Array M512 11#usize) (p : Array M512 5#usize)
    (pinv : M512) (i : Usize) (hi : i.val < LIMBS) :
    fr8.reduce_row t p pinv i = ok (toArray id (fromLanes fun l =>
      Reduction.earlyRow (laneOf (ofArray id t) l) (laneOf (ofArray id p) l)
        pinv[l] ⟨i.val, hi⟩)) := by
  obtain ⟨T, rfl⟩ : ∃ T : Vector M512 (2 * LIMBS + 1), t = toArray id T :=
    ⟨ofArray id t, (toArray_ofArray (fun _ => rfl) t _ _).symm⟩
  obtain ⟨P, rfl⟩ : ∃ P : Vector M512 LIMBS, p = toArray id P :=
    ⟨ofArray id p, (toArray_ofArray (fun _ => rfl) p _ _).symm⟩
  have hi' : i.val < 5 := hi
  unfold fr8.reduce_row
  simp (disch := (simp; omega)) only [Simd.zero_refines, bind_tc_ok, index_usize_toArray,
    core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64,
    core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64,
    core.core_arch.x86.avx512f._mm512_add_epi64, LeanBlsSimd.Simd.carry_of_cleared_refines,
    usize_add_ok, update_eq, set_toArray_id, UScalar.ofNatCore_val_eq]
  rw [Lane.reduce_low_refines _ _ _ hi]
  simp (disch := (simp; omega)) only [bind_tc_ok, index_usize_toArray, set_toArray_id,
    UScalar.ofNatCore_val_eq]
  rw [Lane.reduce_high_refines _ _ _ hi]
  simp only [ofArray_toArray_id, laneOf_set, laneOf_fromLanes]
  simp [Reduction.earlyRow]

theorem Lane.splat_eq (x : UInt64) : Lane.splat x = x := UInt64.toUInt64_toInt64 x

theorem Lane.splat_limbs_eq (x : Limbs) : Lane.splat_limbs x = x := by
  ext j hj
  simp [Lane.splat_limbs, Lane.splat_eq]

theorem Fr8.canonical_refines (self : fr8.Fr8) :
    fr8.Fr8.canonical self = ok (toFr8 (ofFr8 self).canonical) := by
  simp [fr8.Fr8.canonical, P_refines, Simd.splat_limbs_refines, Simd.sub_limbs_refines,
    Fr8.canonical, Function.uncurry_def, Simd.select_borrowed_refines, toFr8]

end LeanBlsSimd.FrModel
