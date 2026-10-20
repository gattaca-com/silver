import LeanBlsSimd.Refines.Fr8Core
import LeanBlsSimd.Model.SignedLimbs

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

private theorem bind_return {α : Type} (x : Result α) : (x >>= ok) = x := by
  cases x <;> rfl

def Fr8.normalise (a : Fr8) : Fr8 :=
  Fr8.ofLanes (.ofFn fun lane => SignedLimbs.normalise (a.lane lane))

theorem Fr8.normalise_refines (a : fr8.Fr8) :
    fr8.Fr8.normalise a = ok (toFr8 (ofFr8 a).normalise) := by
  unfold fr8.Fr8.normalise fr8.Fr8.normalise_loop
  simp only [MASK52_refines, Simd.splat_refines, bind_tc_ok, LIMBS_refines,
    ofU64_toU64]
  have hsub : 5#usize - 1#usize = ok 4#usize := by
    change UScalar.sub _ _ = _
    simp [UScalar.sub]
    apply UScalar.eq_of_val_eq
    exact usize_ofNat_val 4 (by decide)
  rw [hsub]
  simp only [bind_tc_ok, bind_return]
  let step := fun (v : Vector M512 LIMBS) (j : Fin (LIMBS - 1)) =>
    let v := v.set (j.val + 1)
      (_mm512_add_epi64 v[j.val + 1] (_mm512_srai_epi64 52 v[j.val]))
    v.set j.val (_mm512_and_si512 v[j.val] (Simd.splat (.ofNat MASK52)))
  conv_lhs => rw [show a = toArray id (ofArray id a) from (toArray_ofArray (fun _ => rfl) a _ _).symm]
  refine loop_range (n := LIMBS - 1) _ 4#usize rfl (toArray (n := 5#usize) id) step
    (toArray (n := 5#usize) id) (ofArray id a) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.Fr8.normalise_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < 4 := by rw [hs]; exact j.isLt
    simp_body fr8.Fr8.normalise_loop.body hn
    simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
      core.core_arch.x86.avx512f._mm512_srai_epi64,
      core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_and_si512, UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [step, hs, List.map_set, Vector.toList_set]
  · change toArray id _ = toArray id (Fr8.normalise (ofFr8 a)).limbs
    apply congrArg (toArray (n := 5#usize) id)
    change _ = (Fr8.ofLanes (.ofFn fun lane =>
      SignedLimbs.normalise ((ofFr8 a).lane lane))).limbs
    rw [Fr8.limbs_ofLanes_ofFn, eq_comm, fromLanes_eq_iff]
    intro l
    unfold SignedLimbs.normalise
    refine List.foldl_hom (fun v => laneOf v l) ?_
    intro v j
    simp [step, SignedLimbs.carryStep, laneOf_set, getElem_laneOf, srai, MASK52,
      Simd.splat, _mm512_set1_epi64, _mm512_add_epi64, _mm512_srai_epi64,
      _mm512_and_si512]
    rfl

def Fr8.addRaw (a b : Fr8) : Fr8 :=
  ⟨.ofFn fun j => _mm512_add_epi64 a.limbs[j] b.limbs[j]⟩

def Fr8.subRaw (a b offset : Fr8) : Fr8 :=
  ⟨.ofFn fun j => _mm512_sub_epi64
    (_mm512_add_epi64 a.limbs[j] offset.limbs[j]) b.limbs[j]⟩

theorem Fr8.add_raw_refines (a b : fr8.Fr8) :
    fr8.Fr8.add_raw a b = ok (toFr8 ((ofFr8 a).addRaw (ofFr8 b))) := by
  unfold fr8.Fr8.add_raw fr8.Fr8.add_raw_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_return]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 5#usize rfl
    (fun v => (a, b, toArray (n := 5#usize) id v))
    (fun v j => v.set j (_mm512_add_epi64 (ofArray id a)[j] (ofArray id b)[j]))
    (toArray (n := 5#usize) id) (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.Fr8.add_raw_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.Fr8.add_raw_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_add_epi64]
    refine congrArg (fun s => ok (cont (r', a, b, s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Fr8.addRaw, toFr8, ofFr8, foldl_set_ofFn]

theorem Fr8.sub_raw_refines (a b offset : fr8.Fr8) :
    fr8.Fr8.sub_raw a b offset =
      ok (toFr8 ((ofFr8 a).subRaw (ofFr8 b) (ofFr8 offset))) := by
  unfold fr8.Fr8.sub_raw fr8.Fr8.sub_raw_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_return]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 5#usize rfl
    (fun v => (a, b, offset, toArray (n := 5#usize) id v))
    (fun v j => v.set j (_mm512_sub_epi64
      (_mm512_add_epi64 (ofArray id a)[j] (ofArray id offset)[j]) (ofArray id b)[j]))
    (toArray (n := 5#usize) id) (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.Fr8.sub_raw_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.Fr8.sub_raw_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_sub_epi64]
    refine congrArg (fun s => ok (cont (r', a, b, offset, s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Fr8.subRaw, toFr8, ofFr8, foldl_set_ofFn]

end LeanBlsSimd.FrModel
