import LeanBlsSimd.Refines.Constants
import LeanBlsSimd.Refines.Loop
import LeanBlsSimd.Proofs.Pow

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

/-!
# `fp8.rs`

`ofFp8` reads a generated `Fp8` as the model's, limb by limb. Both sides use the same `M512`, so
SIMD values need no conversion. `muladd_row` and `reduce_row` refine the model's per-lane
functions, joined by `fromLanes`.

`Fp8.mul_refines` chains the sixteen rows and the carry loop, each in the `fromLanes` form, so
lane `l` of the generated `mul` is `Lane.mul` on lane `l` of its inputs. It needs no precondition:
the model wraps modulo 2^64 as the intrinsics do, and no index depends on the inputs.

The window loop of `pow_p_minus_3_over_4` counts down from 94 in the Rust and folds over
`(List.range 94).reverse` in the model; `loop_countdown` bridges the two. Its table lookups stay in
bounds because every window is below 16 (`windows_lt`).
-/

namespace LeanBlsSimd

def ofFp8 (a : fp8.Fp8) : Fp8 := ⟨ofArray id a⟩

def toFp8 (x : Fp8) : fp8.Fp8 := toArray id x.limbs

@[simp] theorem limbs_ofFp8 (a : fp8.Fp8) : (ofFp8 a).limbs = ofArray id a := rfl

@[simp] theorem ofFp8_toFp8 (x : Fp8) : ofFp8 (toFp8 x) = x := by
  simp [ofFp8, toFp8, ofArray_toArray]

@[simp] theorem toFp8_ofFp8 (a : fp8.Fp8) : toFp8 (ofFp8 a) = a := by
  simp [ofFp8, toFp8, toArray_ofArray]

def fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) : Vector M512 n :=
  .ofFn fun j => .ofFn fun l => (lanes l)[j]

@[simp] theorem laneOf_fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (l : Fin 8) :
    laneOf (fromLanes lanes) l = lanes l := by
  ext j hj
  simp [fromLanes]

@[simp] theorem fromLanes_laneOf {n : ℕ} (v : Vector M512 n) : fromLanes (laneOf v) = v := by
  ext j hj l hl
  simp [fromLanes]

@[simp] theorem getElem_fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (k : ℕ) (hk : k < n)
    (l : ℕ) (hl : l < 8) : (fromLanes lanes)[k][l] = (lanes ⟨l, hl⟩)[k] := by
  simp [fromLanes]

theorem fromLanes_eq_iff {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (v : Vector M512 n) :
    fromLanes lanes = v ↔ ∀ l, lanes l = laneOf v l := by
  constructor
  · rintro rfl l; simp
  · intro h; rw [← fromLanes_laneOf v]; congr 1; funext l; exact h l

theorem Fp8.limbs_ofLanes_ofFn (lanes : Fin 8 → Limbs) :
    (Fp8.ofLanes (.ofFn lanes)).limbs = fromLanes lanes := by
  ext j hj l hl
  simp [Fp8.ofLanes, fromLanes]

theorem laneOf_replicate {n : ℕ} (x : M512) (l : Fin 8) :
    laneOf (Vector.replicate n x) l = Vector.replicate n x[l] := by
  ext j hj
  simp

@[simp] theorem getElem_madd52hi_epu64 (a b c : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_madd52hi_epu64 a b c)[l] = madd52hi a[l] b[l] c[l] := by
  simp [_mm512_madd52hi_epu64]

theorem repeat_eq_toArray_id {α : Type} {n : Usize} {m : ℕ} (x : α) (h : n.val = m) :
    Array.repeat n x = toArray id (Vector.replicate m x) h := by
  simp [toArray_replicate]

theorem Simd.splat_refines (x : U64) : fp8.splat x = ok (Simd.splat (ofU64 x)) := rfl

theorem Simd.zero_refines : fp8.zero = ok Simd.zero := rfl

theorem Simd.lanes_refines (v : M512) : fp8.lanes v = ok (toArray toU64 (Simd.lanes v)) := rfl

theorem Simd.borrowed_refines (borrow : M512) :
    fp8.borrowed borrow = ok (toU8 (Simd.borrowed borrow)) := rfl

theorem Simd.splat_limbs_refines (limbs : Array U64 8#usize) :
    fp8.splat_limbs limbs = ok (toArray id (Simd.splat_limbs (ofArray ofU64 limbs))) := by
  unfold fp8.splat_limbs fp8.splat_limbs_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id)
    (fun v j => v.set j (Simd.splat (ofArray ofU64 limbs)[j])) (toArray id)
    (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.splat_limbs_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.splat_limbs_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, Simd.splat_refines, update_eq _ _ _ hj]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Simd.splat_limbs, foldl_set_ofFn]

theorem Simd.sub_limbs_refines (a b : Array M512 8#usize) :
    fp8.sub_limbs a b =
      ok (Prod.map (toArray id) id (Simd.sub_limbs (ofArray id a) (ofArray id b))) := by
  unfold fp8.sub_limbs fp8.sub_limbs_loop
  simp only [MASK52_refines, Simd.splat_refines, Simd.zero_refines, bind_tc_ok, LIMBS_refines,
    ofU64_toU64]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (Prod.map (toArray id) id)
    (fun (d, borrow) j =>
      let s := _mm512_add_epi64 (_mm512_sub_epi64 (ofArray id a)[j] (ofArray id b)[j]) borrow
      (d.set j (_mm512_and_si512 s (Simd.splat (.ofNat MASK52))), _mm512_srai_epi64 63 s))
    (Prod.map (toArray id) id) (Vector.replicate LIMBS Simd.zero, Simd.zero) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fp8.sub_limbs_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    obtain ⟨d, borrow⟩ := m
    simp_body fp8.sub_limbs_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_sub_epi64, core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_srai_epi64, core.core_arch.x86.avx512f._mm512_and_si512,
      Prod.map, id]
    refine congrArg (fun s => ok (cont (r', s))) (Prod.ext ?_ ?_)
    · apply Subtype.ext
      simp [hs, List.map_set, Vector.toList_set]
    · simp [hs]

theorem Simd.add_limbs_refines (a b : Array M512 8#usize) :
    fp8.add_limbs a b = ok (toArray id (Simd.add_limbs (ofArray id a) (ofArray id b))) := by
  unfold fp8.add_limbs fp8.add_limbs_loop
  simp only [MASK52_refines, Simd.splat_refines, Simd.zero_refines, bind_tc_ok, LIMBS_refines,
    ofU64_toU64]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (Prod.map (toArray id) id)
    (fun (s, carry) j =>
      let t := _mm512_add_epi64 (_mm512_add_epi64 (ofArray id a)[j] (ofArray id b)[j]) carry
      (s.set j (_mm512_and_si512 t (Simd.splat (.ofNat MASK52))), _mm512_srli_epi64 52 t))
    (fun x => toArray id x.1) (Vector.replicate LIMBS Simd.zero, Simd.zero) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fp8.add_limbs_loop.body hn
    rfl
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    obtain ⟨s, carry⟩ := m
    simp_body fp8.add_limbs_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_add_epi64, core.core_arch.x86.avx512f._mm512_srli_epi64,
      core.core_arch.x86.avx512f._mm512_and_si512, Prod.map, id]
    refine congrArg (fun s => ok (cont (r', s))) (Prod.ext ?_ ?_)
    · apply Subtype.ext
      simp [hs, List.map_set, Vector.toList_set]
    · simp [hs]

theorem Simd.blend_refines (k : U8) (a b : Array M512 8#usize) :
    fp8.blend k a b = ok (toArray id (Simd.blend (ofU8 k) (ofArray id a) (ofArray id b))) := by
  unfold fp8.blend fp8.blend_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id)
    (fun v j => v.set j (_mm512_mask_blend_epi64 (ofU8 k) (ofArray id a)[j] (ofArray id b)[j]))
    (toArray id) (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.blend_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.blend_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok,
      core.core_arch.x86.avx512f._mm512_mask_blend_epi64, update_eq _ _ _ hj]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [Simd.blend, foldl_set_ofFn]

theorem Simd.two_p_refines : fp8.two_p = ok (toArray id Simd.two_p) := by
  simp [fp8.two_p, P_refines, Simd.splat_limbs_refines, Simd.add_limbs_refines, Simd.two_p]

theorem Lane.muladd_row_refines (t : Array M512 17#usize) (a : Array M512 8#usize) (b_i : M512)
    (i : Usize) (hi : i.val < LIMBS) :
    fp8.muladd_row t a b_i i = ok (toArray id (fromLanes fun l =>
      Lane.muladd_row (laneOf (ofArray id t) l) (laneOf (ofArray id a) l) b_i[l] ⟨i.val, hi⟩)) := by
  unfold fp8.muladd_row fp8.muladd_row_loop
  simp only [LIMBS_refines]
  let A : Vector M512 LIMBS := ofArray id a
  have hij : ∀ j : Fin LIMBS, i.val + j.val + 1 < 2 * LIMBS + 1 := by
    intro j; have := j.isLt; unfold LIMBS at *; omega
  let step := fun (T : Vector M512 (2 * LIMBS + 1)) (j : Fin LIMBS) =>
    let T := T.set (i.val + j.val) (_mm512_madd52lo_epu64 T[i.val + j.val] A[j] b_i)
      (by have := hij j; omega)
    T.set (i.val + j.val + 1) (_mm512_madd52hi_epu64 T[i.val + j.val + 1] A[j] b_i) (hij j)
  conv_lhs => rw [show t = toArray id (ofArray id t (n := 17#usize) (m := 2 * LIMBS + 1) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) t _ _).symm]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id) step (toArray id) (ofArray id t) _
    ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.muladd_row_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hi8 : i.val < 8 := hi
    have hj8 : r.start.val < 8 := by rw [hs]; exact j.isLt
    simp_body fp8.muladd_row_loop.body hn
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

theorem Lane.reduce_row_refines (t : Array M512 17#usize) (p : Array M512 8#usize) (pinv : M512)
    (i : Usize) (hi : i.val < LIMBS) :
    fp8.reduce_row t p pinv i = ok (toArray id (fromLanes fun l =>
      Lane.reduce_row (laneOf (ofArray id t) l) (laneOf (ofArray id p) l) pinv[l] ⟨i.val, hi⟩)) := by
  have hi8 : i.val < 8 := hi
  unfold fp8.reduce_row
  simp only [Simd.zero_refines, bind_tc_ok, index_usize_eq t i (by simp; omega),
    core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64]
  rw [Lane.muladd_row_refines _ _ _ _ hi]
  simp (disch := (simp; omega)) only [usize_add_ok, index_usize_eq, update_eq, bind_tc_ok,
    core.core_arch.x86.avx512f._mm512_srli_epi64, core.core_arch.x86.avx512f._mm512_add_epi64,
    UScalar.ofNatCore_val_eq]
  have hi1 : i.val + 1 < 2 * LIMBS + 1 := by unfold LIMBS; omega
  refine congrArg ok ((toArray_set_of_eq (m := 2 * LIMBS + 1) id _ _ _ (i.val + 1) hi1 _ _
    (by simp) rfl).trans ?_)
  refine congrArg (fun v : Vector M512 (2 * LIMBS + 1) => (toArray id v rfl : Array M512 17#usize)) ?_
  symm
  rw [fromLanes_eq_iff]
  intro l
  rw [laneOf_set]
  simp only [laneOf_fromLanes]
  simp [Lane.reduce_row, Lane.zero]

theorem Lane.splat_eq (x : UInt64) : Lane.splat x = x := UInt64.toUInt64_toInt64 x

theorem Lane.splat_limbs_eq (x : Limbs) : Lane.splat_limbs x = x := by
  ext j hj
  simp [Lane.splat_limbs, Lane.splat_eq]

theorem Fp8.splat_limbs_refines (limbs : Array U64 8#usize) :
    fp8.Fp8.splat_limbs limbs = ok (toFp8 (Fp8.splat_limbs (ofArray ofU64 limbs))) := by
  simp [fp8.Fp8.splat_limbs, Simd.splat_limbs_refines, Fp8.splat_limbs, toFp8]

theorem Fp8.zero_refines : fp8.Fp8.zero = ok (toFp8 Fp8.zero) := by
  simp [fp8.Fp8.zero, Simd.zero_refines, Fp8.zero, toFp8, repeat_eq_toArray_id Simd.zero
    (show (8#usize).val = LIMBS from rfl)]

theorem Fp8.one_refines : fp8.Fp8.one = ok (toFp8 Fp8.one) := by
  simp [fp8.Fp8.one, R_MOD_P_refines, Fp8.splat_limbs_refines, Fp8.one]

theorem Fp8.load_refines (values : Array (Array U64 8#usize) 8#usize) :
    fp8.Fp8.load values = ok (toFp8 (Fp8.load (ofArray (ofArray ofU64) values))) := by
  unfold fp8.Fp8.load fp8.Fp8.load_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_ok_eq]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id)
    (fun v j => v.set j (Fp8.load (ofArray (ofArray ofU64) values)).limbs[j]) (toArray id)
    (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.Fp8.load_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.load_loop.body hn
    simp only [index_usize_eq values 7#usize (by decide), index_usize_eq values 6#usize (by decide),
      index_usize_eq values 5#usize (by decide), index_usize_eq values 4#usize (by decide),
      index_usize_eq values 3#usize (by decide), index_usize_eq values 2#usize (by decide),
      index_usize_eq values 1#usize (by decide), index_usize_eq values 0#usize (by decide),
      index_usize_eq _ _ hj, bind_tc_ok, lift, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_set_epi64, ofBitVec_hcast_I64]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set, Fp8.load]
  · simp [Fp8.load, foldl_set_ofFn, toFp8]

theorem Fp8.store_inner_refines (out : Vector Limbs 8) (j : Usize) (hj : j.val < LIMBS)
    (l : Vector UInt64 8) :
    fp8.Fp8.store_loop0_loop0 { start := 0#usize, «end» := fp8.LANES } (toArray (toArray toU64) out) j
        (toArray toU64 l) =
      ok (toArray (toArray toU64) ((List.finRange 8).foldl
        (fun out (lane : Fin 8) => out.set lane (out[lane].set j.val l[lane])) out)) := by
  unfold fp8.Fp8.store_loop0_loop0
  rw [LANES_refines]
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray toU64))
    (fun out (lane : Fin 8) => out.set lane (out[lane].set j.val l[lane])) (toArray (toArray toU64))
    out _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fp8.Fp8.store_loop0_loop0.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact lane.isLt
    have hj' : j.val < (8#usize).val := hj
    simp_body fp8.Fp8.store_loop0_loop0.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, Array.index_mut_usize, update_eq _ _ _ hj']
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, hj, List.map_set, Vector.toList_set]

theorem Fp8.store_refines (self : fp8.Fp8) :
    fp8.Fp8.store self = ok (toArray (toArray toU64) (ofFp8 self).store) := by
  unfold fp8.Fp8.store fp8.Fp8.store_loop0
  simp only [LIMBS_refines]
  rw [show Array.repeat 8#usize (Array.repeat 8#usize 0#u64) =
    toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate LIMBS 0)) from
    by simp [toArray_replicate]; rfl]
  refine loop_range (n := LIMBS) _ 8#usize rfl (fun out => (self, toArray (toArray toU64) out))
    (fun out (j : Fin LIMBS) =>
      (List.finRange 8).foldl (fun out (lane : Fin 8) =>
        out.set lane (out[lane].set j (Simd.lanes (ofFp8 self).limbs[j])[lane])) out)
    (toArray (toArray toU64)) (Vector.replicate 8 (Vector.replicate LIMBS 0)) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fp8.Fp8.store_loop0.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.store_loop0.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, Simd.lanes_refines]
    rw [Fp8.store_inner_refines _ _ (by rw [hs]; exact j.isLt)]
    simp [hs]

theorem Fp8.canonical_refines (self : fp8.Fp8) :
    fp8.Fp8.canonical self = ok (toFp8 (ofFp8 self).canonical) := by
  simp [fp8.Fp8.canonical, P_refines, Simd.splat_limbs_refines, Simd.sub_limbs_refines,
    Fp8.canonical, Function.uncurry_def, Simd.borrowed_refines, Simd.blend_refines, toFp8]

theorem Fp8.add_refines (self rhs : fp8.Fp8) :
    fp8.Fp8.add self rhs = ok (toFp8 ((ofFp8 self).add (ofFp8 rhs))) := by
  simp [fp8.Fp8.add, Simd.add_limbs_refines, Simd.two_p_refines, Simd.sub_limbs_refines,
    Fp8.add, Function.uncurry_def, Simd.borrowed_refines, Simd.blend_refines, toFp8]

theorem Fp8.sub_refines (self rhs : fp8.Fp8) :
    fp8.Fp8.sub self rhs = ok (toFp8 ((ofFp8 self).sub (ofFp8 rhs))) := by
  simp [fp8.Fp8.sub, Simd.add_limbs_refines, Simd.two_p_refines, Simd.sub_limbs_refines,
    Fp8.sub, Function.uncurry_def, Simd.borrowed_refines, Simd.blend_refines, toFp8]

theorem Fp8.neg_refines (self : fp8.Fp8) :
    fp8.Fp8.neg self = ok (toFp8 (ofFp8 self).neg) := by
  simp [fp8.Fp8.neg, Fp8.zero_refines, Fp8.sub_refines, Fp8.neg]

theorem Fp8.double_refines (self : fp8.Fp8) :
    fp8.Fp8.double self = ok (toFp8 (ofFp8 self).double) := by
  simp [fp8.Fp8.double, Fp8.add_refines, Fp8.double]

theorem Fp8.select_refines (k : U8) (a b : fp8.Fp8) :
    fp8.Fp8.select k a b = ok (toFp8 (Fp8.select (ofU8 k) (ofFp8 a) (ofFp8 b))) := by
  simp [fp8.Fp8.select, Simd.blend_refines, Fp8.select, toFp8]

theorem Fp8.eq_mask_refines (self rhs : fp8.Fp8) :
    fp8.Fp8.eq_mask self rhs = ok (toU8 ((ofFp8 self).eq_mask (ofFp8 rhs))) := by
  simp only [fp8.Fp8.eq_mask, fp8.Fp8.eq_mask_loop, Fp8.canonical_refines, bind_tc_ok,
    LIMBS_refines]
  refine loop_range (n := LIMBS) _ 8#usize rfl
    (fun k => (toFp8 (ofFp8 self).canonical, toFp8 (ofFp8 rhs).canonical, toU8 k))
    (fun k j => k &&& _mm512_cmpeq_epi64_mask (ofFp8 self).canonical.limbs[j]
      (ofFp8 rhs).canonical.limbs[j]) toU8 0xff _ ?_ ?_ (by simp only [Fp8.eq_mask])
  · intro r m he hs hn
    simp_body fp8.Fp8.eq_mask_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.eq_mask_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, lift,
      core.core_arch.x86.avx512f._mm512_cmpeq_epi64_mask]
    simp [toFp8, hs]

theorem Fp8.is_zero_mask_refines (self : fp8.Fp8) :
    fp8.Fp8.is_zero_mask self = ok (toU8 (ofFp8 self).is_zero_mask) := by
  simp only [fp8.Fp8.is_zero_mask, fp8.Fp8.is_zero_mask_loop, Fp8.canonical_refines, bind_tc_ok,
    LIMBS_refines]
  refine loop_range (n := LIMBS) _ 8#usize rfl (fun k => (toFp8 (ofFp8 self).canonical, toU8 k))
    (fun k j => k &&& _mm512_cmpeq_epi64_mask (ofFp8 self).canonical.limbs[j] Simd.zero) toU8
    0xff _ ?_ ?_ (by simp only [Fp8.is_zero_mask])
  · intro r m he hs hn
    simp_body fp8.Fp8.is_zero_mask_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.is_zero_mask_loop.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, lift, Simd.zero_refines,
      core.core_arch.x86.avx512f._mm512_cmpeq_epi64_mask]
    simp [toFp8, hs]

theorem unpack52_refines (x : Array U64 6#usize) :
    fp8.unpack52 x = ok (toArray toU64 (unpack52 (ofArray ofU64 x))) := by
  unfold fp8.unpack52 fp8.unpack52_loop
  simp only [LIMBS_refines]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray toU64)
    (fun v j => v.set j (unpack52 (ofArray ofU64 x))[j]) (toArray toU64) (Vector.replicate LIMBS 0)
    _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.unpack52_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    obtain rfl : j = ⟨r.start.val, hj⟩ := Fin.ext hs.symm
    simp_body fp8.unpack52_loop.body hn
    simp only [update_eq _ _ _ hj]
    rcases usize_lt_8 r.start hj with h | h | h | h | h | h | h | h <;>
    · simp only [h]
      simp [lift, LIMB_BITS_refines, mul_ok, div_ok, rem_ok, shiftRight_ok, shiftLeft_ok,
        usize_add_ok, sub_ok, index_usize_eq, MASK52_refines]
      refine toArray_set_of_eq _ _ _ _ _ _ _ _ rfl ?_
      rw [eq_toU64_iff]
      simp [unpack52, LIMB_BITS, MASK52]
  · simp only [foldl_set_ofFn]
    rfl

theorem pack64_refines (x : Array U64 8#usize) :
    fp8.pack64 x = ok (toArray toU64 (pack64 (ofArray ofU64 x))) := by
  unfold fp8.pack64 fp8.pack64_loop
  simp only [LIMBS_refines]
  let X : Limbs := ofArray ofU64 x
  let step := packStep X
  let enc := fun (s : Vector UInt64 6 × BitVec 128 × ℕ × ℕ) =>
    ((toArray toU64 s.1 : Array U64 6#usize), (⟨s.2.1⟩ : U128), (⟨BitVec.ofNat 32 s.2.2.1⟩ : U32),
      (⟨BitVec.ofNat System.Platform.numBits s.2.2.2⟩ : Usize))
  let inv := fun (j : ℕ) (s : Vector UInt64 6 × BitVec 128 × ℕ × ℕ) =>
    s.2.2.1 = 52 * j % 64 ∧ s.2.2.2 = 52 * j / 64
  have hinv : ∀ s (j : Fin LIMBS), inv j s → inv (j + 1) (step s j) := by
    intro ⟨out, acc, bits, word⟩ j ⟨hb, hw⟩
    simp only at hb hw
    subst hb hw
    fin_cases j <;> simp [step, packStep, inv, LIMB_BITS]
  rw [show (Array.repeat 6#usize 0#u64, 0#u128, 0#u32, 0#usize) =
    enc (Vector.replicate 6 0, 0, 0, 0) from rfl]
  rw [loop_range_inv (n := LIMBS) _ 8#usize rfl enc step
    (fun s => ((toArray toU64 s.1 : Array U64 6#usize), (⟨s.2.1⟩ : U128),
      (⟨BitVec.ofNat System.Platform.numBits s.2.2.2⟩ : Usize)))
    inv hinv
    _ _ 0#usize _ (by simp) (by simp [inv])]
  · have hF := foldl_finRange_inv step inv hinv (Vector.replicate 6 0, 0, 0, 0) (by simp [inv])
    change _ = ok (toArray toU64 (match List.foldl step (Vector.replicate 6 0, 0, 0, 0)
      (List.finRange LIMBS) with
      | (out, acc, _, word) =>
        if h : word < 6 then out.set word (.ofBitVec (acc.setWidth 64)) h else out))
    simp only [show (0#usize).val = 0 from rfl, List.drop_zero]
    generalize List.foldl step (Vector.replicate 6 0, 0, 0, 0) (List.finRange LIMBS) = F at hF ⊢
    obtain ⟨out, acc, bits, word⟩ := F
    simp only [inv, LIMBS] at hF
    obtain ⟨rfl, rfl⟩ := hF
    simp_body Function.uncurry_apply_pair Function.uncurry_apply_pair
    simp
  · intro r s he hs _ hn
    simp_body fp8.pack64_loop.body hn
    rfl
  · intro r r' s j he hs he' hs' hi hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    obtain rfl : j = ⟨r.start.val, hj⟩ := Fin.ext hs.symm
    obtain ⟨out, acc, bits, word⟩ := s
    obtain ⟨hb, hw⟩ := hi
    simp only at hb hw
    subst hb hw
    simp_body fp8.pack64_loop.body hn
    rcases usize_lt_8 r.start hj with h | h | h | h | h | h | h | h <;>
    · simp only [h, enc, step, packStep, UScalar.ofNatCore_val_eq, LIMB_BITS, Fin.getElem_fin, X,
        getElem_ofArray]
      simp (disch := decide) only [lift, bind_tc_ok, LIMB_BITS_refines, index_usize_eq,
        shiftLeft_ok, add_ok, sub_ok, UScalar.ofNatCore_val_eq, u32_ofNat_val, Nat.reduceAdd,
        Nat.reduceMul, Nat.reduceMod, Nat.reduceDiv, Nat.reduceSub, ge_iff_le, UScalar.le_equiv,
        Nat.reduceLeDiff, ite_true, ite_false, shiftRight_64_i32,
        update_ofNat, usize_ofNat_add_ok]
      refine congrArg (fun s => ok (cont (r', s))) (Prod.ext ?_ (Prod.ext ?_ (Prod.ext ?_ ?_)))
      · first
        | (rw [vector_set!_eq _ _ (by decide)]
           exact toArray_set_of_eq _ _ _ _ _ _ _ _ (usize_ofNat_val _ (by decide)) rfl)
        | rfl
      · rfl
      · rfl
      · first
        | (dsimp only
           apply UScalar.eq_of_val_eq
           rw [UScalar.ofNatCore_val_eq, usize_ofNat_val _ (by decide)])
        | rfl

theorem Fp8.mul_loop_refines (t : Array M512 17#usize) (mask : M512) (r : Array M512 8#usize)
    (stop : Usize) (hstop : stop.val = LIMBS - 1) :
    fp8.Fp8.mul_loop { start := 0#usize, «end» := stop } t mask r =
      ok (toArray id (fromLanes (n := LIMBS) fun l =>
        (List.finRange (LIMBS - 1)).foldl
          (Lane.carryStep (laneOf (ofArray id t (m := 2 * LIMBS + 1)) l) mask[l])
          (laneOf (ofArray id r (m := LIMBS)) l))) := by
  unfold fp8.Fp8.mul_loop
  let T : Vector M512 (2 * LIMBS + 1) := ofArray id t
  have hj1 : ∀ j : Fin (LIMBS - 1), j.val + 1 < LIMBS := by
    intro j; have := j.isLt; omega
  let step := fun (R : Vector M512 LIMBS) (j : Fin (LIMBS - 1)) =>
    let R := R.set (j.val + 1)
      (_mm512_add_epi64 T[LIMBS + j.val + 1] (_mm512_srli_epi64 52 R[j.val])) (hj1 j)
    R.set j.val (_mm512_and_si512 R[j.val] mask) (by have := hj1 j; omega)
  conv_lhs => rw [show r = toArray id (ofArray id r (n := 8#usize) (m := LIMBS) rfl) rfl
    from (toArray_ofArray (fun _ => rfl) r _ _).symm]
  refine loop_range (n := LIMBS - 1) _ stop hstop (toArray id) step (toArray id) (ofArray id r) _
    ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.Fp8.mul_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj7 : r.start.val < 7 := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.mul_loop.body hn
    simp only [LIMBS_refines]
    simp (disch := (simp; omega)) only [usize_add_ok, bind_tc_ok, index_usize_eq, update_eq,
      core.core_arch.x86.avx512f._mm512_add_epi64, core.core_arch.x86.avx512f._mm512_srli_epi64,
      core.core_arch.x86.avx512f._mm512_and_si512, UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    let X := _mm512_add_epi64 T[LIMBS + j.val + 1] (_mm512_srli_epi64 52 m[j.val])
    rw [toArray_set_of_eq id m _ _ (j.val + 1) (hj1 j) X _ (by simp [hs])
      (by simp [X, T, hs, LIMBS]; rfl)]
    exact toArray_set_of_eq id _ _ _ j.val (by have := hj1 j; omega)
      (_mm512_and_si512 (m.set (j.val + 1) X (hj1 j))[j.val] mask) _ hs (by simp [hs])
  · refine congrArg (fun v : Vector M512 LIMBS => (toArray id v rfl : Array M512 8#usize)) ?_
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    refine List.foldl_hom (fun R => laneOf R l) ?_
    intro R j
    simp only [step, laneOf_set]
    simp [T, Lane.carryStep]

-- Both sides hold the same `Lane.reduce_row` applications once simplified. Unfolding them while
-- unifying the sides would evaluate the rows instead.
attribute [local irreducible] Lane.reduce_row in
theorem Fp8.mul_refines (self rhs : fp8.Fp8) :
    fp8.Fp8.mul self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  unfold fp8.Fp8.mul
  simp only [Simd.splat_limbs_refines, P_refines, Simd.splat_refines, P_INV52_refines,
    Simd.zero_refines, MASK52_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (17#usize).val = 2 * LIMBS + 1 from rfl),
    repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  simp (disch := decide) only [index_usize_eq rhs, Lane.muladd_row_refines,
    Lane.reduce_row_refines, bind_tc_ok, ofArray_toArray_id, laneOf_fromLanes]
  simp (disch := decide) only [index_usize_toArray, bind_tc_ok, update_eq, set_toArray, sub_ok,
    show (8#usize).val = LIMBS from rfl]
  rw [Fp8.mul_loop_refines _ _ _ _ rfl]
  simp only [toFp8, Fp8.mul, Fp8.limbs_ofLanes_ofFn, Fp8.lane_eq, limbs_ofFp8, bind_tc_ok,
    ofArray_toArray_id, laneOf_fromLanes, laneOf_set]
  refine congrArg (fun F => ok (toArray id (fromLanes F) rfl)) (funext fun l => ?_)
  simp only [Lane.mul, Lane.mulAcc, Lane.splat_limbs_eq, Lane.splat_eq, Lane.zero, laneOf_replicate,
    Fin.getElem_fin, Simd.getElem_zero, Simd.getElem_splat, getElem_laneOf, getElem_ofArray, id_eq,
    UScalar.ofNatCore_val_eq, ofU64_toU64, getElem_fromLanes, Simd.laneOf_splat_limbs,
    ofArray_toArray_ofU64, fin_mk_zero, fin_mk_one, fin_mk_ofNat]

theorem Fp8.square_refines (self : fp8.Fp8) :
    fp8.Fp8.square self = ok (toFp8 (ofFp8 self).square) := by
  simp [fp8.Fp8.square, Fp8.mul_refines, Fp8.square]

theorem Fp8.half_refines (self : fp8.Fp8) :
    fp8.Fp8.half self = ok (toFp8 (ofFp8 self).half) := by
  simp [fp8.Fp8.half, HALF_MONT_refines, Fp8.splat_limbs_refines, Fp8.mul_refines, Fp8.half]

theorem Fp8.from_plain_refines (values : Array (Array U64 8#usize) 8#usize) :
    fp8.Fp8.from_plain values = ok (toFp8 (Fp8.from_plain (ofArray (ofArray ofU64) values))) := by
  simp [fp8.Fp8.from_plain, Fp8.load_refines, R2_MOD_P_refines, Fp8.splat_limbs_refines,
    Fp8.mul_refines, Fp8.from_plain]

theorem Fp8.to_plain_refines (self : fp8.Fp8) :
    fp8.Fp8.to_plain self = ok (toArray (toArray toU64) (ofFp8 self).to_plain) := by
  simp [fp8.Fp8.to_plain, ONE_PLAIN_refines, Fp8.splat_limbs_refines, Fp8.mul_refines,
    Fp8.canonical_refines, Fp8.store_refines, Fp8.to_plain]

theorem Fp8.to_blst_limbs_loop_refines (t : Array (Array U64 8#usize) 8#usize) :
    fp8.Fp8.to_blst_limbs_loop { start := 0#usize, «end» := fp8.LANES } t
        (Array.repeat 8#usize (Array.repeat 6#usize 0#u64)) =
      ok (toArray (toArray toU64) (.ofFn fun lane : Fin 8 =>
        pack64 (ofArray (ofArray ofU64) t (m := 8))[lane])) := by
  unfold fp8.Fp8.to_blst_limbs_loop
  rw [LANES_refines, show Array.repeat 8#usize (Array.repeat 6#usize 0#u64) =
    toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate 6 0)) from
    by simp [toArray_replicate]; rfl]
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray toU64))
    (fun out lane => out.set lane (pack64 (ofArray (ofArray ofU64) t (m := 8))[lane]))
    (toArray (toArray toU64)) (Vector.replicate 8 (Vector.replicate 6 0)) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fp8.Fp8.to_blst_limbs_loop.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact lane.isLt
    simp_body fp8.Fp8.to_blst_limbs_loop.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, pack64_refines, update_eq _ _ _ hl]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [foldl_set_ofFn]

theorem Fp8.to_blst_limbs_refines (self : fp8.Fp8) :
    fp8.Fp8.to_blst_limbs self = ok (toArray (toArray toU64) (ofFp8 self).to_blst_limbs) := by
  simp [fp8.Fp8.to_blst_limbs, TWO_POW_384_MOD_P_refines, Fp8.splat_limbs_refines,
    Fp8.mul_refines, Fp8.canonical_refines, Fp8.store_refines, Fp8.to_blst_limbs_loop_refines,
    Fp8.to_blst_limbs]

theorem Fp8.is_larger_root_mask_refines (self : fp8.Fp8) :
    fp8.Fp8.is_larger_root_mask self = ok (toU8 (ofFp8 self).is_larger_root_mask) := by
  simp [fp8.Fp8.is_larger_root_mask, Fp8.to_plain_refines, Fp8.load_refines,
    HALF_P_MINUS_1_refines, Simd.splat_limbs_refines, Simd.sub_limbs_refines, Function.uncurry_def,
    Simd.borrowed_refines, Fp8.is_larger_root_mask, toFp8]

theorem Fp8.pow_table_refines (self : fp8.Fp8) (T : Vector Fp8 16) :
    fp8.Fp8.pow_p_minus_3_over_4_loop0 { start := 2#usize, «end» := 16#usize } self
        (toArray toFp8 T) =
      ok (toArray toFp8 (((List.finRange 16).drop 2).foldl
        (fun table (k : Fin 16) => table.set k (table[k.val - 1].mul (ofFp8 self))) T)) := by
  unfold fp8.Fp8.pow_p_minus_3_over_4_loop0
  rw [loop_range_inv (n := 16) _ 16#usize rfl (toArray toFp8)
    (fun table (k : Fin 16) => table.set k (table[k.val - 1].mul (ofFp8 self))) (toArray toFp8)
    (fun j _ => 2 ≤ j) (fun _ _ h => by omega) ?_ ?_ 2#usize T (by decide)
    (show 2 ≤ (2#usize).val by decide)]
  · rfl
  · intro r m he hs hinv hn
    simp_body fp8.Fp8.pow_p_minus_3_over_4_loop0.body hn
  · intro r r' m j he hs he' hs' hinv hn
    have hj : r.start.val < 16 := by rw [hs]; exact j.isLt
    simp_body fp8.Fp8.pow_p_minus_3_over_4_loop0.body hn
    rw [sub_ok _ _ (by simp; omega)]
    simp only [bind_tc_ok]
    rw [index_usize_toArray _ _ _ _ (by simp; omega)]
    simp only [bind_tc_ok, Fp8.mul_refines, ofFp8_toFp8, UScalar.ofNatCore_val_eq]
    rw [update_eq _ _ _ hj]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    exact toArray_set_of_eq _ _ _ _ _ j.isLt _ _ hs (by simp [hs])

theorem Fp8.pow_windows_refines (T : Vector Fp8 16) (r : Fp8) (w : Usize) (n : ℕ)
    (hwn : w.val = n) (hn : n ≤ 95) :
    fp8.Fp8.pow_p_minus_3_over_4_loop1 (toArray toFp8 T) (toFp8 r) w =
      ok (toFp8 ((List.range n).reverse.foldl (Fp8.windowStep T) r)) := by
  unfold fp8.Fp8.pow_p_minus_3_over_4_loop1
  refine loop_countdown _ (fun m c => (toFp8 m, c)) (Fp8.windowStep T) toFp8 n ?_ ?_ w r hwn
  · intro m c hc
    simp [fp8.Fp8.pow_p_minus_3_over_4_loop1.body, hc]
  · intro m c c' hc hcn
    simp only [fp8.Fp8.pow_p_minus_3_over_4_loop1.body]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have hc'v : c'.val < 95 := by omega
    have e : (UScalar.ofNatCore (c.val - (1#usize).val) (by have := c.hBounds; omega) : Usize) =
        c' :=
      UScalar.eq_of_val_eq (by simp; omega)
    simp only [e, bind_tc_ok, Fp8.square_refines, ofFp8_toFp8,
      P_MINUS_3_OVER_4_WINDOWS_index c' hc'v, lift]
    have hd := windows_lt c'.val (List.mem_range.mpr hc'v)
    simp only [Fp8.windowStep, cast_Usize_ofNatCore, usize_ofNatCore_bne_zero, decide_eq_true_eq]
    split_ifs with hd0
    · rw [index_usize_toArray _ _ _ _ (by rw [UScalar.ofNatCore_val_eq]; exact hd)]
      simp only [bind_tc_ok, UScalar.ofNatCore_val_eq, Fp8.mul_refines, ofFp8_toFp8,
        getElem!_pos T P_MINUS_3_OVER_4_WINDOWS[c'.val]! hd]
    · rfl

theorem Fp8.pow_p_minus_3_over_4_refines (self : fp8.Fp8) :
    fp8.Fp8.pow_p_minus_3_over_4 self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
  unfold fp8.Fp8.pow_p_minus_3_over_4
  simp only [Fp8.one_refines, bind_tc_ok]
  rw [← toArray_replicate toFp8 Fp8.one (show (16#usize).val = 16 from rfl),
    update_eq _ _ _ (by decide),
    toArray_set_of_eq toFp8 _ _ 1#usize 1 (by decide) (ofFp8 self) self rfl (by simp)]
  simp only [bind_tc_ok, Fp8.pow_table_refines]
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := windows_lt 94 (by simp)
  simp only [bind_tc_ok, P_MINUS_3_OVER_4_WINDOWS_index 94#usize (by decide), lift,
    cast_Usize_ofNatCore]
  rw [index_usize_toArray _ _ _ _ (by rw [UScalar.ofNatCore_val_eq]; exact h94)]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [Fp8.pow_windows_refines _ _ _ _ rfl (by decide),
    ← getElem!_pos _ P_MINUS_3_OVER_4_WINDOWS[94]! h94]
  simp only [Fp8.pow_p_minus_3_over_4, UScalar.ofNatCore_val_eq]

theorem Fp8.sqrt_candidate_refines (self : fp8.Fp8) :
    fp8.Fp8.sqrt_candidate self = ok (toFp8 (ofFp8 self).sqrt_candidate) := by
  simp [fp8.Fp8.sqrt_candidate, Fp8.pow_p_minus_3_over_4_refines, Fp8.mul_refines,
    Fp8.sqrt_candidate]

end LeanBlsSimd
