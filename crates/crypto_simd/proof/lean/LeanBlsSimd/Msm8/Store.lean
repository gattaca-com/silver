import LeanBlsSimd.Refines.G1x8
import LeanBlsSimd.Refines.Transpose

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open silver_crypto_simd silver_crypto_simd.bls
namespace LeanBlsSimd

theorem row_vector_refines (row : Array U64 8#usize) :
    msm8.store.row_vector row = ok (ofArray ofU64 row) := by
  simp only [msm8.store.row_vector,
    index_usize_eq row 7#usize (by decide), index_usize_eq row 6#usize (by decide),
    index_usize_eq row 5#usize (by decide), index_usize_eq row 4#usize (by decide),
    index_usize_eq row 3#usize (by decide), index_usize_eq row 2#usize (by decide),
    index_usize_eq row 1#usize (by decide), index_usize_eq row 0#usize (by decide),
    bind_tc_ok, lift, core.core_arch.x86.avx512f._mm512_set_epi64,
    ofBitVec_hcast_I64]
  congr 1
  ext i hi
  interval_cases i <;> simp [_mm512_set_epi64, getElem_ofArray]


theorem loop_up_inv {S B M : Type} {n : ℕ}
    (body : S → Result (ControlFlow S B)) (enc : M → Usize → S)
    (step : M → Fin n → M) (finish : M → B) (inv : M → Prop)
    (hinv : ∀ m j, inv m → inv (step m j))
    (hdone : ∀ m c, c.val = n → inv m → body (enc m c) = ok (done (finish m)))
    (hcont : ∀ m (c : Usize) (j : Fin n), c.val = j.val → inv m →
      ∃ c', c'.val = j.val + 1 ∧ body (enc m c) = ok (cont (enc (step m j) c')))
    (m : M) (c : Usize) (hc : c.val ≤ n) (hm : inv m) :
    loop body (enc m c) = ok (finish (((List.finRange n).drop c.val).foldl step m)) := by
  induction hk : n - c.val generalizing c m with
  | zero =>
    have hs : c.val = n := by omega
    rw [loop.eq_1, hdone m c hs hm]
    simp [hs]
  | succ k ih =>
    have hlt : c.val < n := by omega
    obtain ⟨c', hc', hb⟩ := hcont m c ⟨c.val, hlt⟩ rfl hm
    simp only at hc'
    rw [loop.eq_1, hb]
    simp only
    rw [ih (step m ⟨c.val, hlt⟩) c' (by omega) (hinv m _ hm) (by omega)]
    rw [List.drop_eq_getElem_cons (l := List.finRange n) (i := c.val) (by simp [hlt])]
    simp [hc']

theorem vec_index_eq {α : Type} (v : alloc.vec.Vec α) (i : Usize)
    (hi : i.val < v.val.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i =
      ok v.val[i.val] := by
  simp [alloc.vec.Vec.index, Slice.index_usize, hi]

def pointRows (s : msm8.store.PointStore) : List Limbs := s.rows.val.map (ofArray ofU64)

def indexedRows (rows : List Limbs) (indices : Vector ℕ 8) (coordinate : ℕ) : Vector M512 8 :=
  Vector.ofFn fun lane => rows[2 * indices[lane] + coordinate]!

def pointIndices (indices : Array U32 8#usize) : Vector ℕ 8 := ofArray UScalar.val indices

def indicesInBounds (s : msm8.store.PointStore) (indices : Array U32 8#usize) : Prop :=
  ∀ lane : Fin 8, 2 * (pointIndices indices)[lane] + 1 < s.rows.val.length


theorem load_x_body (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (hb : indicesInBounds s indices) (hs : s.rows.val.length < 2 ^ UScalarTy.Usize.numBits)
    (xs : Vector M512 8) (lane : Usize) (j : Fin 8) (hj : lane.val = j.val) :
    ∃ next, next.val = j.val + 1 ∧
      msm8.store.PointStore.load_x_loop.body s indices (toArray id xs) lane =
      ok (cont (toArray id (xs.set j (indexedRows (pointRows s) (pointIndices indices) 0)[j]), next)) := by
  have hl : lane.val < (8#usize).val := by simp [hj]
  let ix := indices.val[lane.val]'(by simpa [indices.property] using hl)
  have hix : (pointIndices indices)[j.val] = ix.val := by simp [pointIndices, ix, ← hj]
  have hbound := hb j
  change 2 * (pointIndices indices)[j.val] + 1 < _ at hbound
  rw [hix] at hbound
  have hmul : (2#usize).val * (UScalar.cast .Usize ix).val < 2 ^ UScalarTy.Usize.numBits := by
    simp only [cast_Usize_val]; simp at *; omega
  have hadd : lane.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    change lane.val + 1 < _
    omega
  let at1 : Usize := UScalar.ofNatCore (2 * ix.val) (by simpa using hmul)
  let next : Usize := UScalar.ofNatCore (lane.val + 1) (by simpa using hadd)
  refine ⟨next, by simp [next, hj], ?_⟩
  have hmul' : (2#usize * UScalar.cast .Usize ix : Result Usize) = ok at1 := by
    rw [mul_ok _ _ hmul]
    congr 1
    apply UScalar.eq_of_val_eq
    simp [at1]
  have hadd' : (lane + 1#usize : Result Usize) = ok next := by
    rw [add_ok _ _ hadd]; rfl
  have hat : at1.val = 2 * ix.val := by simp [at1]
  simp only [msm8.store.PointStore.load_x_loop.body, limbs.LANES,
    UScalar.lt_equiv, hl, if_true, index_usize_eq indices lane hl, bind_tc_ok, lift]
  change (do
    let at2 ← (2#usize * UScalar.cast .Usize ix : Result Usize)
    let row ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice (Array U64 8#usize)) s.rows at2
    let mi ← msm8.store.row_vector row
    let a ← Array.update (toArray (n := 8#usize) id xs) lane mi
    let c ← lane + 1#usize
    ok (cont (a, c))) = _
  rw [hmul']
  simp only [bind_tc_ok, vec_index_eq s.rows at1 (by omega), row_vector_refines,
    update_eq _ lane _ hl, hadd']
  congr 2
  have hr : ofArray ofU64 s.rows.val[at1.val] =
      (indexedRows (pointRows s) (pointIndices indices) 0)[j] := by
    simp [indexedRows, pointRows, hix, hat, show 2 * ix.val < s.rows.val.length by omega]
    rfl
  rw [hr]
  congr 1
  exact toArray_set_of_eq (n := 8#usize) id xs rfl lane j.val j.isLt _ _ hj rfl


theorem vec_length_bound {α : Type} (rows : alloc.vec.Vec α) :
    rows.val.length < 2 ^ UScalarTy.Usize.numBits := by
  have h := rows.property
  simp only [Usize.max_def, Usize.numBits_def] at h
  have := two_pow_32_le_usize
  change rows.val.length ≤ 2 ^ UScalarTy.Usize.numBits - 1 at h
  omega

theorem load_x_refines (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (hb : indicesInBounds s indices) :
    msm8.store.PointStore.load_x s indices =
      ok (toArray id (transpose8 (indexedRows (pointRows s) (pointIndices indices) 0))) := by
  let target := indexedRows (pointRows s) (pointIndices indices) 0
  have hloop : msm8.store.PointStore.load_x_loop s indices
      (toArray id (Vector.replicate 8 Simd.zero)) 0#usize = ok (toArray id target) := by
    unfold msm8.store.PointStore.load_x_loop
    rw [loop_up_inv (n := 8) (fun p => msm8.store.PointStore.load_x_loop.body s indices p.1 p.2) (fun (xs : Vector M512 8) (c : Usize) => (toArray (n := 8#usize) id xs, c))
      (fun xs j => xs.set j target[j]) (toArray (n := 8#usize) id)
      (fun _ => True) (fun _ _ _ => trivial)
      (fun xs c hc _ => by
        simp [msm8.store.PointStore.load_x_loop.body, limbs.LANES, UScalar.lt_equiv, hc])
      (fun xs c j hc _ => load_x_body s indices hb (vec_length_bound s.rows) xs c j hc)
      (Vector.replicate 8 Simd.zero) 0#usize (by simp) trivial]
    simp [target, indexedRows, foldl_set_ofFn]
  simp only [msm8.store.PointStore.load_x, core.core_arch.x86.avx512f._mm512_setzero_si512,
    bind_tc_ok, ← show Simd.zero = _mm512_setzero_si512 from rfl]
  have hz : Array.repeat 8#usize Simd.zero = toArray id (Vector.replicate 8 Simd.zero) := by
    simpa only [id_eq] using (toArray_replicate (n := 8#usize) id Simd.zero rfl).symm
  rw [hz, hloop]
  simp only [bind_tc_ok, transpose8_refines, ofArray_toArray_id]
  rfl

theorem load_points_body (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (hb : indicesInBounds s indices) (hs : s.rows.val.length < 2 ^ UScalarTy.Usize.numBits)
    (xs ys : Vector M512 8) (lane : Usize) (j : Fin 8) (hj : lane.val = j.val) :
    ∃ next, next.val = j.val + 1 ∧
      msm8.store.PointStore.load_points_loop.body s indices (toArray id xs) (toArray id ys) lane =
      ok (cont (toArray id (xs.set j (indexedRows (pointRows s) (pointIndices indices) 0)[j]),
        toArray id (ys.set j (indexedRows (pointRows s) (pointIndices indices) 1)[j]), next)) := by
  have hl : lane.val < (8#usize).val := by simp [hj]
  let ix := indices.val[lane.val]'(by simpa [indices.property] using hl)
  have hix : (pointIndices indices)[j.val] = ix.val := by simp [pointIndices, ix, ← hj]
  have hbound := hb j
  change 2 * (pointIndices indices)[j.val] + 1 < _ at hbound
  rw [hix] at hbound
  have hmul : (2#usize).val * (UScalar.cast .Usize ix).val < 2 ^ UScalarTy.Usize.numBits := by
    simp only [cast_Usize_val]; simp at *; omega
  have hadd : lane.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    change lane.val + 1 < _
    omega
  let at1 : Usize := UScalar.ofNatCore (2 * ix.val) (by simpa using hmul)
  let next : Usize := UScalar.ofNatCore (lane.val + 1) (by simpa using hadd)
  refine ⟨next, by simp [next, hj], ?_⟩
  have hmul' : (2#usize * UScalar.cast .Usize ix : Result Usize) = ok at1 := by
    rw [mul_ok _ _ hmul]
    congr 1
    apply UScalar.eq_of_val_eq
    simp [at1]
  have hadd' : (lane + 1#usize : Result Usize) = ok next := by
    rw [add_ok _ _ hadd]; rfl
  have hat : at1.val = 2 * ix.val := by simp [at1]
  have hyadd : at1.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    simp only [hat]; change 2 * ix.val + 1 < _; omega
  let yat : Usize := UScalar.ofNatCore (2 * ix.val + 1) (by omega)
  have hyat : yat.val = 2 * ix.val + 1 := by simp [yat]
  have hyadd' : (at1 + 1#usize : Result Usize) = ok yat := by
    rw [add_ok _ _ hyadd]
    congr 1
  simp only [msm8.store.PointStore.load_points_loop.body, limbs.LANES,
    UScalar.lt_equiv, hl, if_true, index_usize_eq indices lane hl, bind_tc_ok, lift]
  change (do
    let at2 ← (2#usize * UScalar.cast .Usize ix : Result Usize)
    let row ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice (Array U64 8#usize)) s.rows at2
    let mi ← msm8.store.row_vector row
    let a ← Array.update (toArray (n := 8#usize) id xs) lane mi
    let at3 ← at2 + 1#usize
    let rowy ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice (Array U64 8#usize)) s.rows at3
    let miy ← msm8.store.row_vector rowy
    let ay ← Array.update (toArray (n := 8#usize) id ys) lane miy
    let c ← lane + 1#usize
    ok (cont (a, ay, c))) = _
  rw [hmul']
  simp only [bind_tc_ok, vec_index_eq s.rows at1 (by omega), row_vector_refines,
    update_eq _ lane _ hl, hyadd',
    vec_index_eq s.rows yat (by omega), hadd']
  have hxrow : ofArray ofU64 s.rows.val[at1.val] =
      (indexedRows (pointRows s) (pointIndices indices) 0)[j] := by
    simp [indexedRows, pointRows, hix, hat, show 2 * ix.val < s.rows.val.length by omega]
    rfl
  have hyrow : ofArray ofU64 s.rows.val[yat.val] =
      (indexedRows (pointRows s) (pointIndices indices) 1)[j] := by
    simp [indexedRows, pointRows, hix, hyat, hbound]
    rfl
  apply congrArg (fun p => ok (cont p))
  apply Prod.ext
  · exact toArray_set_of_eq (n := 8#usize) id xs rfl lane j.val j.isLt _ _ hj hxrow
  · apply Prod.ext
    · exact toArray_set_of_eq (n := 8#usize) id ys rfl lane j.val j.isLt _ _ hj hyrow
    · rfl


theorem foldl_pair {A B I : Type} (l : List I) (f : A → I → A) (g : B → I → B)
    (a : A) (b : B) :
    l.foldl (fun p i => (f p.1 i, g p.2 i)) (a, b) = (l.foldl f a, l.foldl g b) := by
  induction l generalizing a b with
  | nil => rfl
  | cons i l ih => exact ih (f a i) (g b i)

theorem load_points_refines (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (hb : indicesInBounds s indices) :
    msm8.store.PointStore.load_points s indices =
      ok (toArray id (transpose8 (indexedRows (pointRows s) (pointIndices indices) 0)),
        toArray id (transpose8 (indexedRows (pointRows s) (pointIndices indices) 1))) := by
  let tx := indexedRows (pointRows s) (pointIndices indices) 0
  let ty := indexedRows (pointRows s) (pointIndices indices) 1
  let zero := Vector.replicate 8 Simd.zero
  have hloop : msm8.store.PointStore.load_points_loop s indices
      (toArray id zero) (toArray id zero) 0#usize = ok (toArray id tx, toArray id ty) := by
    unfold msm8.store.PointStore.load_points_loop
    rw [loop_up_inv (n := 8)
      (fun p => msm8.store.PointStore.load_points_loop.body s indices p.1 p.2.1 p.2.2)
      (fun (p : Vector M512 8 × Vector M512 8) (c : Usize) =>
        (toArray (n := 8#usize) id p.1, toArray (n := 8#usize) id p.2, c))
      (fun p j => (p.1.set j tx[j], p.2.set j ty[j]))
      (fun p => (toArray (n := 8#usize) id p.1, toArray (n := 8#usize) id p.2))
      (fun _ => True) (fun _ _ _ => trivial)
      (fun p c hc _ => by
        simp [msm8.store.PointStore.load_points_loop.body, limbs.LANES, UScalar.lt_equiv, hc])
      (fun p c j hc _ => load_points_body s indices hb (vec_length_bound s.rows) p.1 p.2 c j hc)
      (zero, zero) 0#usize (by simp) trivial]
    change ok (toArray (n := 8#usize) id ((List.finRange 8).foldl
      (fun p j => (p.1.set j tx[j], p.2.set j ty[j])) (zero, zero)).1,
      toArray (n := 8#usize) id ((List.finRange 8).foldl
      (fun p j => (p.1.set j tx[j], p.2.set j ty[j])) (zero, zero)).2) = _
    rw [foldl_pair (List.finRange 8) (fun (v : Vector M512 8) (j : Fin 8) => v.set j tx[j])
      (fun (v : Vector M512 8) (j : Fin 8) => v.set j ty[j]) zero zero]
    simp only [tx, ty, indexedRows, foldl_set_ofFn]
    simp
  have hz : Array.repeat 8#usize Simd.zero = toArray id zero := by
    simpa only [id_eq] using (toArray_replicate (n := 8#usize) id Simd.zero rfl).symm
  simp only [msm8.store.PointStore.load_points, core.core_arch.x86.avx512f._mm512_setzero_si512,
    bind_tc_ok, ← show Simd.zero = _mm512_setzero_si512 from rfl]
  rw [hz, hloop]
  simp only [bind_tc_ok, transpose8_refines]
  rfl


def loadedCoordinate (s : msm8.store.PointStore) (indices : Array U32 8#usize) (c : ℕ) : Fp8 :=
  ⟨transpose8 (indexedRows (pointRows s) (pointIndices indices) c)⟩

theorem load_signed_refines (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (negated : U8) (hb : indicesInBounds s indices) :
    msm8.store.PointStore.load_signed s indices negated =
      ok (toFp8 (loadedCoordinate s indices 0),
        toFp8 (Fp8.select (ofU8 negated) (loadedCoordinate s indices 1)
          (loadedCoordinate s indices 1).neg)) := by
  simp only [msm8.store.PointStore.load_signed, load_points_refines s indices hb, bind_tc_ok,
    Fp8.neg_refines, Fp8.select_refines, ofFp8_toFp8]
  rfl


theorem vec_index_mut_eq {α : Type} (v : alloc.vec.Vec α) (i : Usize)
    (hi : i.val < v.val.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i =
      ok (v.val[i.val], fun x => (⟨v.val.set i.val x, by simpa using v.property⟩ : alloc.vec.Vec α)) := by
  simp [alloc.vec.Vec.index_mut, Slice.index_mut_usize, Slice.index_usize, hi]
  rfl

def storeLane (s : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) : msm8.store.PointStore :=
  { s with rows := ⟨(s.rows.val.set (2 * indices[j]) (toArray toU64 xs[j])).set
      (2 * indices[j] + 1) (toArray toU64 ys[j]), by simpa using s.rows.property⟩ }

@[simp] theorem storeLane_length (s : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) :
    (storeLane s indices xs ys j).rows.val.length = s.rows.val.length := by
  simp [storeLane]

theorem store_points_body (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (hb : indicesInBounds s indices) (hs : s.rows.val.length < 2 ^ UScalarTy.Usize.numBits)
    (xs ys : Vector M512 8) (lane : Usize) (j : Fin 8) (hj : lane.val = j.val) :
    ∃ next, next.val = j.val + 1 ∧
      msm8.store.PointStore.store_points_loop.body indices (toArray id xs) (toArray id ys) s lane =
      ok (cont (storeLane s (pointIndices indices) xs ys j, next)) := by
  have hl : lane.val < (8#usize).val := by simp [hj]
  let ix := indices.val[lane.val]'(by simpa [indices.property] using hl)
  have hix : (pointIndices indices)[j.val] = ix.val := by simp [pointIndices, ix, ← hj]
  have hbound := hb j
  change 2 * (pointIndices indices)[j.val] + 1 < _ at hbound
  rw [hix] at hbound
  have hmul : (2#usize).val * (UScalar.cast .Usize ix).val < 2 ^ UScalarTy.Usize.numBits := by
    simp only [cast_Usize_val]; simp at *; omega
  have hadd : lane.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    change lane.val + 1 < _
    omega
  let at1 : Usize := UScalar.ofNatCore (2 * ix.val) (by simpa using hmul)
  let next : Usize := UScalar.ofNatCore (lane.val + 1) (by simpa using hadd)
  refine ⟨next, by simp [next, hj], ?_⟩
  have hmul' : (2#usize * UScalar.cast .Usize ix : Result Usize) = ok at1 := by
    rw [mul_ok _ _ hmul]
    congr 1
    apply UScalar.eq_of_val_eq
    simp [at1]
  have hadd' : (lane + 1#usize : Result Usize) = ok next := by
    rw [add_ok _ _ hadd]; rfl
  have hat : at1.val = 2 * ix.val := by simp [at1]
  have hyadd : at1.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    simp only [hat]; change 2 * ix.val + 1 < _; omega
  let yat : Usize := UScalar.ofNatCore (2 * ix.val + 1) (by omega)
  have hyat : yat.val = 2 * ix.val + 1 := by simp [yat]
  have hyadd' : (at1 + 1#usize : Result Usize) = ok yat := by
    rw [add_ok _ _ hyadd]
    congr 1
  simp only [msm8.store.PointStore.store_points_loop.body, limbs.LANES,
    UScalar.lt_equiv, hl, if_true, index_usize_eq indices lane hl, bind_tc_ok, lift]
  change (do
    let at2 ← (2#usize * UScalar.cast .Usize ix : Result Usize)
    let mx ← Array.index_usize (toArray (n := 8#usize) id xs) lane
    let x ← fp8.lanes mx
    let (_, backx) ← alloc.vec.Vec.index_mut
      (core.slice.index.SliceIndexUsizeSlice (Array U64 8#usize)) s.rows at2
    let my ← Array.index_usize (toArray (n := 8#usize) id ys) lane
    let y ← fp8.lanes my
    let rowx := backx x
    let at3 ← at2 + 1#usize
    let (_, backy) ← alloc.vec.Vec.index_mut
      (core.slice.index.SliceIndexUsizeSlice (Array U64 8#usize)) rowx at3
    let c ← lane + 1#usize
    ok (cont ({ s with rows := backy y }, c))) = _
  rw [hmul']
  simp only [bind_tc_ok, index_usize_toArray (n := 8#usize) id xs rfl lane hl,
    index_usize_toArray (n := 8#usize) id ys rfl lane hl, Simd.lanes_refines, Simd.lanes,
    vec_index_mut_eq s.rows at1 (by omega), hyadd', hadd']
  simp only [Bind.bind, Aeneas.Std.bind]
  simp [alloc.vec.Vec.index_mut, Slice.index_mut_usize, Slice.index_usize,
    hyat, storeLane, hat, ← hix, hj]
  have hb' : 2 * (pointIndices indices)[j.val] + 1 < s.rows.val.length := by
    simpa only [hix] using hbound
  simp [hb', Bind.bind, Aeneas.Std.bind]
  apply Subtype.ext
  simp only [Slice.set, Slice.setAtNat, hyat, ← hix]


theorem store_points_fold (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : fp8.Fp8) (hb : indicesInBounds s indices) :
    msm8.store.PointStore.store_points s indices x y =
      ok ((List.finRange 8).foldl (fun s j => storeLane s (pointIndices indices)
        (transpose8 (ofArray id x)) (transpose8 (ofArray id y)) j) s) := by
  simp only [msm8.store.PointStore.store_points, transpose8_refines, bind_tc_ok]
  unfold msm8.store.PointStore.store_points_loop
  rw [loop_up_inv (n := 8)
    (fun p => msm8.store.PointStore.store_points_loop.body indices
      (toArray id (transpose8 (ofArray id x))) (toArray id (transpose8 (ofArray id y))) p.1 p.2)
    (fun (s : msm8.store.PointStore) (c : Usize) => (s, c))
    (fun s j => storeLane s (pointIndices indices)
      (transpose8 (ofArray id x)) (transpose8 (ofArray id y)) j)
    id (fun s => indicesInBounds s indices)
    (fun s j h => by simpa only [indicesInBounds, storeLane_length] using h)
    (fun s c hc _ => by
      simp [msm8.store.PointStore.store_points_loop.body, limbs.LANES, UScalar.lt_equiv, hc])
    (fun s c j hc h => store_points_body s indices h (vec_length_bound s.rows)
      (transpose8 (ofArray id x)) (transpose8 (ofArray id y)) c j hc)
    s 0#usize (by simp) hb]
  rfl

def storeRows (rows : List Limbs) (indices : Vector ℕ 8) (xs ys : Vector M512 8) : List Limbs :=
  (List.finRange 8).foldl (fun rows j => (rows.set (2 * indices[j]) xs[j]).set
    (2 * indices[j] + 1) ys[j]) rows

@[simp] theorem pointRows_storeLane (s : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) :
    pointRows (storeLane s indices xs ys j) =
      ((pointRows s).set (2 * indices[j]) xs[j]).set (2 * indices[j] + 1) ys[j] := by
  simp [pointRows, storeLane, List.map_set, LIMBS]

theorem storeLane_fold_rows (s : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (lanes : List (Fin 8)) :
    pointRows (lanes.foldl (fun s j => storeLane s indices xs ys j) s) =
      lanes.foldl (fun rows j => (rows.set (2 * indices[j]) xs[j]).set
        (2 * indices[j] + 1) ys[j]) (pointRows s) := by
  induction lanes generalizing s with
  | nil => rfl
  | cons j lanes ih =>
    simp only [List.foldl_cons, ih, pointRows_storeLane]

theorem storeLane_fold_len (s : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (lanes : List (Fin 8)) :
    (lanes.foldl (fun s j => storeLane s indices xs ys j) s).len = s.len := by
  induction lanes generalizing s with
  | nil => rfl
  | cons j lanes ih => exact ih (storeLane s indices xs ys j)

theorem store_points_refines (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : fp8.Fp8) (hb : indicesInBounds s indices) :
    ∃ out, msm8.store.PointStore.store_points s indices x y = ok out ∧
      pointRows out = storeRows (pointRows s) (pointIndices indices)
        (transpose8 (ofArray id x)) (transpose8 (ofArray id y)) ∧ out.len = s.len := by
  refine ⟨_, store_points_fold s indices x y hb, ?_, ?_⟩
  · exact storeLane_fold_rows s _ _ _ _
  · exact storeLane_fold_len s _ _ _ _


theorem repeated_write_last_wins (rows : List Limbs) (i : ℕ) (oldx oldy x y : Limbs) :
    ((((rows.set (2 * i) oldx).set (2 * i + 1) oldy).set (2 * i) x).set (2 * i + 1) y) =
      (rows.set (2 * i) x).set (2 * i + 1) y := by
  apply List.ext_getElem
  · simp
  · intro k hk hk'
    by_cases hx : 2 * i = k
    · subst k
      simp
    · by_cases hy : 2 * i + 1 = k
      · subst k
        simp
      · simp [hx, hy]

end LeanBlsSimd
