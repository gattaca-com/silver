import LeanBlsSimd.Msm8.References
import LeanBlsSimd.Msm8.Affine
import LeanBlsSimd.Msm8.Inversion

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open Aeneas Aeneas.Std Result ControlFlow Error
noncomputable section
namespace LeanBlsSimd.BatchedRefines
open silver_crypto_simd.bls
open G1x8.Offsets
theorem pair_map_loop {β : Type}
    (body : Usize × Array fp8.Fp8 2#usize → Result (ControlFlow (Usize × Array fp8.Fp8 2#usize) β))
    (finish : Vector Fp8 2 → β) (f : Fin 2 → Fp8) (m : Vector Fp8 2)
    (hdone : ∀ m (s : Usize), s.val = 2 → body (s, toArray toFp8 m) = ok (done (finish m)))
    (hstep : ∀ m (s : Usize) (j : Fin 2), s.val = j.val →
      ∃ next, next.val = j.val + 1 ∧ body (s, toArray toFp8 m) =
        ok (cont (next, toArray toFp8 (m.set j (f j))))) :
    loop body (0#usize, toArray toFp8 m) = ok (finish (Vector.ofFn f)) := by
  rw [loop_up_inv (n := 2) body (fun m s => (s, toArray toFp8 m))
    (fun m j => m.set j (f j)) finish (fun _ => True) (fun _ _ _ => trivial)
    (fun m s hs _ => hdone m s hs) (fun m s j hs _ => hstep m s j hs)
    m 0#usize (by decide) trivial]
  simp only [show (0#usize).val = 0 from rfl, List.drop_zero, foldl_set_ofFn]

def slope (o : G1x8.Offsets) (ya yb inv : Fp8) : Fp8 :=
  ((yb.sub_raw ya o.two_p).normalise).mul inv

theorem slope_loop_refines (inv ya yb initial : Vector Fp8 2) (o : G1x8.Offsets) :
    msm8.pairs.BatchedAdds.finish_pair_loop1 (toArray toFp8 inv) (toOffsets o)
      (toArray toFp8 ya) (toArray toFp8 yb) 0#usize (toArray toFp8 initial) =
    ok (toOffsets o, toArray toFp8 (Vector.ofFn fun j => slope o ya[j] yb[j] inv[j])) := by
  unfold msm8.pairs.BatchedAdds.finish_pair_loop1
  apply pair_map_loop _ (fun m => (toOffsets o, toArray toFp8 m)) _ initial
  · intro m s hs
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [msm8.pairs.BatchedAdds.finish_pair_loop1.body, msm8.pairs.PAIR, hn]
  · intro m s j hs
    have hlt : s.val < 2 := by omega
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [msm8.pairs.BatchedAdds.finish_pair_loop1.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true,
      index_usize_toArray (n := 2#usize) toFp8 yb rfl s hlt, index_usize_toArray (n := 2#usize) toFp8 ya rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 inv rfl s hlt, bind_tc_ok, Fp8.sub_raw_refines,
      Fp8.normalise_refines, Fp8.mul_refines, ofFp8_toFp8, toOffsets]
    rw [update_eq (toArray (n := 2#usize) toFp8 m) s _ hlt]
    simp only [bind_tc_ok]
    rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
    rw [set_toArray toFp8 m rfl s _ hlt]
    simp [next, slope, hs]

theorem square_loop_refines (slopes initial : Vector Fp8 2) :
    msm8.pairs.BatchedAdds.finish_pair_loop2 0#usize (toArray toFp8 slopes) (toArray toFp8 initial) =
    ok (toArray toFp8 (Vector.ofFn fun j => slopes[j].square)) := by
  unfold msm8.pairs.BatchedAdds.finish_pair_loop2
  apply pair_map_loop _ (toArray toFp8) _ initial
  · intro m s hs
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [msm8.pairs.BatchedAdds.finish_pair_loop2.body, msm8.pairs.PAIR, hn]
  · intro m s j hs
    have hlt : s.val < 2 := by omega
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [msm8.pairs.BatchedAdds.finish_pair_loop2.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true,
      index_usize_toArray (n := 2#usize) toFp8 slopes rfl s hlt,
      bind_tc_ok, Fp8.square_refines, ofFp8_toFp8]
    rw [update_eq (toArray (n := 2#usize) toFp8 m) s _ hlt]
    simp only [bind_tc_ok]
    rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
    rw [set_toArray toFp8 m rfl s _ hlt]
    simp [next, hs]

def xCoordinate (o : G1x8.Offsets) (xa xb squared : Fp8) : Fp8 :=
  o.reduced_from_8p ((squared.sub_raw xa o.two_p).sub_raw xb o.two_p)

theorem x_loop_refines (xa xb squared initial : Vector Fp8 2) (o : G1x8.Offsets) :
    msm8.pairs.BatchedAdds.finish_pair_loop3 (toOffsets o) (toArray toFp8 xa)
      (toArray toFp8 xb) 0#usize (toArray toFp8 squared) (toArray toFp8 initial) =
    ok (toOffsets o, toArray toFp8 (Vector.ofFn fun j => xCoordinate o xa[j] xb[j] squared[j])) := by
  unfold msm8.pairs.BatchedAdds.finish_pair_loop3
  apply pair_map_loop _ (fun m => (toOffsets o, toArray toFp8 m)) _ initial
  · intro m s hs
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [msm8.pairs.BatchedAdds.finish_pair_loop3.body, msm8.pairs.PAIR, hn]
  · intro m s j hs
    have hlt : s.val < 2 := by omega
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [msm8.pairs.BatchedAdds.finish_pair_loop3.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true,
      index_usize_toArray (n := 2#usize) toFp8 squared rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 xa rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 xb rfl s hlt,
      bind_tc_ok, Fp8.sub_raw_refines, G1x8.Offsets.reduced_from_8p_refines,
      ofFp8_toFp8, toOffsets]
    rw [update_eq (toArray (n := 2#usize) toFp8 m) s _ hlt]
    simp only [bind_tc_ok]
    rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
    rw [set_toArray toFp8 m rfl s _ hlt]
    simp [next, xCoordinate, hs, ofOffsets]

def yProduct (o : G1x8.Offsets) (xa slope x3 : Fp8) : Fp8 :=
  slope.mul ((xa.sub_raw x3 o.two_p).normalise)

theorem product_loop_refines (xa slopes x3 initial : Vector Fp8 2) (o : G1x8.Offsets) :
    msm8.pairs.BatchedAdds.finish_pair_loop4 (toOffsets o) (toArray toFp8 xa)
      0#usize (toArray toFp8 slopes) (toArray toFp8 x3) (toArray toFp8 initial) =
    ok (toOffsets o, toArray toFp8 (Vector.ofFn fun j => yProduct o xa[j] slopes[j] x3[j])) := by
  unfold msm8.pairs.BatchedAdds.finish_pair_loop4
  apply pair_map_loop _ (fun m => (toOffsets o, toArray toFp8 m)) _ initial
  · intro m s hs
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [msm8.pairs.BatchedAdds.finish_pair_loop4.body, msm8.pairs.PAIR, hn]
  · intro m s j hs
    have hlt : s.val < 2 := by omega
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [msm8.pairs.BatchedAdds.finish_pair_loop4.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true,
      index_usize_toArray (n := 2#usize) toFp8 slopes rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 xa rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 x3 rfl s hlt,
      bind_tc_ok, Fp8.sub_raw_refines, Fp8.normalise_refines, Fp8.mul_refines,
      ofFp8_toFp8, toOffsets]
    rw [update_eq (toArray (n := 2#usize) toFp8 m) s _ hlt]
    simp only [bind_tc_ok]
    rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
    rw [set_toArray toFp8 m rfl s _ hlt]
    simp [next, yProduct, hs]

def writeCoordinates (store : msm8.store.PointStore) (indices : Array U32 8#usize) (x y : Fp8) :
    msm8.store.PointStore :=
  (List.finRange 8).foldl (fun store j => storeLane store (pointIndices indices)
    (transpose8 (ofArray id (toFp8 x))) (transpose8 (ofArray id (toFp8 y))) j) store

theorem writeCoordinates_length (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) : (writeCoordinates store indices x y).rows.val.length = store.rows.val.length := by
  unfold writeCoordinates
  generalize List.finRange 8 = lanes
  induction lanes generalizing store with
  | nil => rfl
  | cons j lanes ih => simp only [List.foldl_cons, ih, storeLane_length]

def yCoordinate (o : G1x8.Offsets) (ya product : Fp8) : Fp8 :=
  o.reduced_from_4p (product.sub_raw ya o.two_p)

theorem write_loop_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (hg : g.val + 2 < 2 ^ 32) (o : G1x8.Offsets) (ya x3 product : Vector Fp8 2)
    (refs : Fin 2 → Array U32 8#usize × U8)
    (hrefs : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.out) group = ok (refs j))
    (hbound : ∀ j, indicesInBounds store (refs j).1) :
    msm8.pairs.BatchedAdds.finish_pair_loop5 self store g (toOffsets o) (toArray toFp8 ya)
      0#usize (toArray toFp8 x3) (toArray toFp8 product) =
      ok ((List.finRange 2).foldl (fun store j =>
        writeCoordinates store (refs j).1 x3[j] (yCoordinate o ya[j] product[j])) store) := by
  unfold msm8.pairs.BatchedAdds.finish_pair_loop5
  rw [loop_up_inv (n := 2) _ (fun store s => (store, s))
    (fun store j => writeCoordinates store (refs j).1 x3[j] (yCoordinate o ya[j] product[j]))
    id (fun current => current.rows.val.length = store.rows.val.length)
    (fun current j h => (writeCoordinates_length current _ _ _).trans h) ?_ ?_
    store 0#usize (by decide) rfl]
  · rfl
  · intro current s hs _
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [msm8.pairs.BatchedAdds.finish_pair_loop5.body, msm8.pairs.PAIR, hn]
  · intro current s j hs hlength
    have hlt : s.val < 2 := by omega
    let group : Usize := UScalar.ofNatCore (g.val + s.val)
      (lt_of_lt_of_le (by omega : g.val + s.val < 2 ^ 32) two_pow_32_le_usize)
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    have hr := hrefs j group (by simp [group, hs])
    have hb : indicesInBounds current (refs j).1 := by
      simpa only [indicesInBounds, hlength] using hbound j
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [msm8.pairs.BatchedAdds.finish_pair_loop5.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true,
      index_usize_toArray (n := 2#usize) toFp8 product rfl s hlt,
      index_usize_toArray (n := 2#usize) toFp8 ya rfl s hlt,
      bind_tc_ok, Fp8.sub_raw_refines, G1x8.Offsets.reduced_from_4p_refines,
      ofFp8_toFp8, toOffsets]
    rw [usize_add_ok g s (by omega)]
    simp only [bind_tc_ok]
    rw [hr]
    simp only [bind_tc_ok]
    rw [index_usize_toArray (n := 2#usize) toFp8 x3 rfl s hlt]
    simp only [bind_tc_ok]
    cases hpair : refs j with
    | mk indices negated =>
      simp only [hpair] at hb ⊢
      simp only [ofOffsets, ofFp8_toFp8]
      change (do
        let store1 ← current.store_points indices (toFp8 x3[s.val])
          (toFp8 (yCoordinate o ya[s.val] product[s.val]))
        let s2 ← s + 1#usize
        ok (cont (store1, s2))) = _
      rw [store_points_fold _ _ _ _ hb]
      simp only [bind_tc_ok]
      rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
      simp [next, hs, writeCoordinates, yCoordinate]

abbrev Quad := Fp8 × Fp8 × Fp8 × Fp8

def quadArray (f : Quad → Fp8) (m : Vector Quad 2) : Array fp8.Fp8 2#usize :=
  toArray (fun q => toFp8 (f q)) m

theorem quadArray_ofFn (f : Quad → Fp8) (m : Fin 2 → Quad) :
    quadArray f (Vector.ofFn m) = toArray toFp8 (Vector.ofFn fun j => f (m j)) := by
  apply Subtype.ext
  simp [quadArray, toArray, Vector.toList, Vector.ofFn]

theorem load_pair_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (hg : g.val + 2 < 2 ^ 32) (xa ya xb yb : Vector Fp8 2)
    (ra rb : Fin 2 → Array U32 8#usize × U8)
    (hrefa : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.a) group = ok (ra j))
    (hrefb : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.b) group = ok (rb j))
    (hloada : ∀ j, store.load_signed (ra j).1 (ra j).2 = ok (toFp8 xa[j], toFp8 ya[j]))
    (hloadb : ∀ j, store.load_signed (rb j).1 (rb j).2 = ok (toFp8 xb[j], toFp8 yb[j])) :
    msm8.pairs.BatchedAdds.finish_pair_loop0 self store g
      (Array.repeat 2#usize (toFp8 Fp8.zero)) (Array.repeat 2#usize (toFp8 Fp8.zero))
      (Array.repeat 2#usize (toFp8 Fp8.zero)) (Array.repeat 2#usize (toFp8 Fp8.zero)) 0#usize =
    ok (self, toArray toFp8 xa, toArray toFp8 ya, toArray toFp8 xb, toArray toFp8 yb) := by
  let f : Fin 2 → Quad := fun j => (xa[j], ya[j], xb[j], yb[j])
  let enc := fun (m : Vector Quad 2) (s : Usize) =>
    (quadArray (fun q => q.1) m, quadArray (fun q => q.2.1) m,
      quadArray (fun q => q.2.2.1) m, quadArray (fun q => q.2.2.2) m, s)
  let finish := fun m : Vector Quad 2 =>
    (self, quadArray (fun q => q.1) m, quadArray (fun q => q.2.1) m,
      quadArray (fun q => q.2.2.1) m, quadArray (fun q => q.2.2.2) m)
  have hfinish : finish (Vector.ofFn f) =
      (self, toArray toFp8 xa, toArray toFp8 ya, toArray toFp8 xb, toArray toFp8 yb) := by
    simp only [finish, quadArray_ofFn, f]
    simp
  apply Eq.trans ?_ (congrArg Result.ok hfinish)
  rw [← foldl_set_ofFn f (Vector.replicate 2 (Fp8.zero, Fp8.zero, Fp8.zero, Fp8.zero))]
  refine loop_up_inv (n := 2)
    (fun (xa, ya, xb, yb, s) => msm8.pairs.BatchedAdds.finish_pair_loop0.body self store g xa ya xb yb s)
    enc (fun m j => m.set j (f j)) finish (fun _ => True) (fun _ _ _ => trivial) ?_ ?_
    (Vector.replicate 2 (Fp8.zero, Fp8.zero, Fp8.zero, Fp8.zero)) 0#usize (by decide) trivial
  · intro m s hs _
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp [enc, finish, msm8.pairs.BatchedAdds.finish_pair_loop0.body, msm8.pairs.PAIR, hn]
  · intro m s j hs _
    have hlt : s.val < 2 := by omega
    let group : Usize := UScalar.ofNatCore (g.val + s.val)
      (lt_of_lt_of_le (by omega : g.val + s.val < 2 ^ 32) two_pow_32_le_usize)
    let next : Usize := UScalar.ofNatCore (s.val + 1)
      (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    have hra := hrefa j group (by simp [group, hs])
    have hrb := hrefb j group (by simp [group, hs])
    refine ⟨next, by simp [next, hs], ?_⟩
    simp only [enc, msm8.pairs.BatchedAdds.finish_pair_loop0.body, msm8.pairs.PAIR,
      show s < 2#usize from hlt, if_true]
    rw [usize_add_ok g s (by omega)]
    dsimp [group] at hra hrb
    simp only [bind_tc_ok, hra, hrb]
    cases hpa : ra j with
    | mk ia na =>
      cases hpb : rb j with
      | mk ib nb =>
        have hla := hloada j
        have hlb := hloadb j
        simp only [hpa, hpb] at hla hlb ⊢
        change (do
          let (x, y) ← store.load_signed ia na
          let aa ← Array.update (quadArray (fun q => q.1) m) s x
          let ab ← Array.update (quadArray (fun q => q.2.1) m) s y
          let (x', y') ← store.load_signed ib nb
          let ac ← Array.update (quadArray (fun q => q.2.2.1) m) s x'
          let ad ← Array.update (quadArray (fun q => q.2.2.2) m) s y'
          let s' ← s + 1#usize
          ok (cont (aa, ab, ac, ad, s'))) = _
        rw [hla, hlb]
        simp only [bind_tc_ok]
        simp only [update_eq _ s _ (show s.val < (2#usize).val from hlt), bind_tc_ok]
        rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
        simp only [bind_tc_ok]
        congr 2
        simp [quadArray, f, next, hs]
        refine ⟨?_, ?_, ?_, ?_⟩
        all_goals apply Subtype.ext; simp [toArray, List.map_set, Vector.toList_set, hs]

theorem vector_ofFn_fin {α : Type} {n : ℕ} (f : Fin n → α) (j : Fin n) :
    (Vector.ofFn f)[j] = f j := by simp

theorem finish_pair_schedule (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (hg : g.val + 2 < 2 ^ 32) (xa ya xb yb inv : Vector Fp8 2)
    (ra rb rout : Fin 2 → Array U32 8#usize × U8)
    (hrefa : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.a) group = ok (ra j))
    (hrefb : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.b) group = ok (rb j))
    (hrefo : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.out) group = ok (rout j))
    (hloada : ∀ j, store.load_signed (ra j).1 (ra j).2 = ok (toFp8 xa[j], toFp8 ya[j]))
    (hloadb : ∀ j, store.load_signed (rb j).1 (rb j).2 = ok (toFp8 xb[j], toFp8 yb[j]))
    (hbound : ∀ j, indicesInBounds store (rout j).1) :
    self.finish_pair store g (toArray toFp8 inv) =
      let o := G1x8.Offsets.new
      let slopes := Vector.ofFn fun j : Fin 2 => slope o ya[j] yb[j] inv[j]
      let squared := Vector.ofFn fun j : Fin 2 => slopes[j].square
      let x3 := Vector.ofFn fun j : Fin 2 => xCoordinate o xa[j] xb[j] squared[j]
      let products := Vector.ofFn fun j : Fin 2 => yProduct o xa[j] slopes[j] x3[j]
      ok ((List.finRange 2).foldl (fun store j =>
        writeCoordinates store (rout j).1 x3[j] (yCoordinate o ya[j] products[j])) store) := by
  unfold msm8.pairs.BatchedAdds.finish_pair
  rw [G1x8.Offsets.new_refines, Fp8.zero_refines]
  simp only [bind_tc_ok]
  rw [load_pair_refines self store g hg xa ya xb yb ra rb hrefa hrefb hloada hloadb]
  simp only [bind_tc_ok]
  rw [← toArray_replicate toFp8 Fp8.zero (show (2#usize).val = 2 from rfl)]
  change (do
    let (o1, slope1) ← msm8.pairs.BatchedAdds.finish_pair_loop1 (toArray toFp8 inv)
      (toOffsets G1x8.Offsets.new) (toArray toFp8 ya) (toArray toFp8 yb) 0#usize
      (toArray toFp8 (Vector.replicate 2 Fp8.zero))
    let squared1 ← msm8.pairs.BatchedAdds.finish_pair_loop2 0#usize slope1
      (toArray toFp8 (Vector.replicate 2 Fp8.zero))
    let (o2, x31) ← msm8.pairs.BatchedAdds.finish_pair_loop3 o1 (toArray toFp8 xa)
      (toArray toFp8 xb) 0#usize squared1 (toArray toFp8 (Vector.replicate 2 Fp8.zero))
    let (o3, product1) ← msm8.pairs.BatchedAdds.finish_pair_loop4 o2 (toArray toFp8 xa)
      0#usize slope1 x31 (toArray toFp8 (Vector.replicate 2 Fp8.zero))
    self.finish_pair_loop5 store g o3 (toArray toFp8 ya) 0#usize x31 product1) = _
  simp only [slope_loop_refines, square_loop_refines, x_loop_refines, product_loop_refines, bind_tc_ok]
  rw [write_loop_refines self store g hg _ _ _ _ rout hrefo hbound]

section
attribute [local irreducible] writeCoordinates Msm8.affineAdd slope xCoordinate yProduct yCoordinate
  Fp8.mul Fp8.sub_raw Fp8.normalise Fp8.square G1x8.Offsets.reduced_from_8p
  G1x8.Offsets.reduced_from_4p

theorem finish_pair_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (hg : g.val + 2 < 2 ^ 32) (xa ya xb yb inv : Vector Fp8 2)
    (ra rb rout : Fin 2 → Array U32 8#usize × U8)
    (hrefa : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.a) group = ok (ra j))
    (hrefb : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.b) group = ok (rb j))
    (hrefo : ∀ (j : Fin 2) (group : Usize), group.val = g.val + j.val →
      msm8.pairs.references (alloc.vec.Vec.deref self.out) group = ok (rout j))
    (hloada : ∀ j, store.load_signed (ra j).1 (ra j).2 = ok (toFp8 xa[j], toFp8 ya[j]))
    (hloadb : ∀ j, store.load_signed (rb j).1 (rb j).2 = ok (toFp8 xb[j], toFp8 yb[j]))
    (hbound : ∀ j, indicesInBounds store (rout j).1) :
    self.finish_pair store g (toArray toFp8 inv) =
      ok ((List.finRange 2).foldl (fun store j =>
        let result := Msm8.affineAdd xa[j] ya[j] xb[j] yb[j] inv[j]
        writeCoordinates store (rout j).1 result.1 result.2) store) := by
  rw [finish_pair_schedule self store g hg xa ya xb yb inv ra rb rout hrefa hrefb hrefo hloada hloadb hbound]
  apply congrArg Result.ok
  apply congrArg (fun step : msm8.store.PointStore → Fin 2 → msm8.store.PointStore =>
    (List.finRange 2).foldl step store)
  funext current j
  simp only [vector_ofFn_fin]
  simp only [slope, xCoordinate, yProduct, yCoordinate, Msm8.affineAdd]

end

def referencesAt (refs : List U32) (group : ℕ) : Array U32 8#usize × U8 :=
  (toArray id (Msm8.referenceBatch refs group).1, (Msm8.referenceBatch refs group).2)

def signedCoordinates (store : msm8.store.PointStore) (refs : Array U32 8#usize × U8) : Fp8 × Fp8 :=
  (loadedCoordinate store refs.1 0,
    Fp8.select (ofU8 refs.2) (loadedCoordinate store refs.1 1) (loadedCoordinate store refs.1 1).neg)

def finishPair (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (group : ℕ) (inv : Vector Fp8 2) : msm8.store.PointStore :=
  (List.finRange 2).foldl (fun current j =>
    let a := signedCoordinates store (referencesAt self.a.val (group + j.val))
    let b := signedCoordinates store (referencesAt self.b.val (group + j.val))
    let result := Msm8.affineAdd a.1 a.2 b.1 b.2 inv[j]
    writeCoordinates current (referencesAt self.out.val (group + j.val)).1 result.1 result.2) store

theorem finish_pair_concrete (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (inv : Vector Fp8 2) (hg : g.val + 2 < 2 ^ 32)
    (ha : (g.val + 2) * 8 ≤ self.a.val.length) (hb : (g.val + 2) * 8 ≤ self.b.val.length)
    (ho : (g.val + 2) * 8 ≤ self.out.val.length)
    (hba : ∀ j : Fin 2, indicesInBounds store (referencesAt self.a.val (g.val + j.val)).1)
    (hbb : ∀ j : Fin 2, indicesInBounds store (referencesAt self.b.val (g.val + j.val)).1)
    (hbo : ∀ j : Fin 2, indicesInBounds store (referencesAt self.out.val (g.val + j.val)).1) :
    self.finish_pair store g (toArray toFp8 inv) = ok (finishPair self store g.val inv) := by
  let ra := fun j : Fin 2 => referencesAt self.a.val (g.val + j.val)
  let rb := fun j : Fin 2 => referencesAt self.b.val (g.val + j.val)
  let rout := fun j : Fin 2 => referencesAt self.out.val (g.val + j.val)
  let xa := Vector.ofFn fun j : Fin 2 => (signedCoordinates store (ra j)).1
  let ya := Vector.ofFn fun j : Fin 2 => (signedCoordinates store (ra j)).2
  let xb := Vector.ofFn fun j : Fin 2 => (signedCoordinates store (rb j)).1
  let yb := Vector.ofFn fun j : Fin 2 => (signedCoordinates store (rb j)).2
  have refs (v : alloc.vec.Vec U32) (hv : (g.val + 2) * 8 ≤ v.val.length)
      (j : Fin 2) (group : Usize) (hgroup : group.val = g.val + j.val) :
      msm8.pairs.references v.deref group = ok (referencesAt v.val (g.val + j.val)) := by
    rw [Msm8.references_refines _ _ (by change group.val * 8 + 8 ≤ v.val.length; omega)]
    simp only [referencesAt, hgroup, alloc.vec.Vec.deref]
  have result := finish_pair_refines self store g hg xa ya xb yb inv ra rb rout
    (refs self.a ha) (refs self.b hb) (refs self.out ho)
    (fun j => by simpa [xa, ya, signedCoordinates] using load_signed_refines store (ra j).1 (ra j).2 (hba j))
    (fun j => by simpa [xb, yb, signedCoordinates] using load_signed_refines store (rb j).1 (rb j).2 (hbb j)) hbo
  simpa [finishPair, xa, ya, xb, yb, ra, rb, rout] using result


open silver_crypto_simd.bls
theorem extend_chain_zero (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (products : Array fp8.Fp8 4#usize)
    (ia ib : Array U32 8#usize) (na nb : U8) (xa xb : Fp8)
    (hra : msm8.pairs.references self.a.deref g = ok (ia, na))
    (hrb : msm8.pairs.references self.b.deref g = ok (ib, nb))
    (hla : store.load_x ia = ok (toFp8 xa)) (hlb : store.load_x ib = ok (toFp8 xb))
    (hzero : (xb.sub xa).is_zero_mask ≠ 0) :
    self.extend_chain store g products = ok (false, self, products) := by
  have hm : toU8 (xb.sub xa).is_zero_mask ≠ 0#u8 := by
    intro h
    exact hzero ((toU8_inj _ 0).mp h)
  simp only [msm8.pairs.BatchedAdds.extend_chain, hra, hrb, bind_tc_ok]
  change (do
    let a ← store.load_x ia
    let b ← store.load_x ib
    let dx ← fp8.Fp8.sub b a
    let mask ← fp8.Fp8.is_zero_mask dx
    if mask != 0#u8 then ok (false, self, products) else _) = _
  rw [hla, hlb]
  simp only [bind_tc_ok, Fp8.sub_refines, Fp8.is_zero_mask_refines, ofFp8_toFp8, bne_iff_ne]
  rw [if_pos hm]

theorem equal_x_zero_mask (xa xb : Fp8) (lane : Fin 8)
    (ha : Fp8Inv (xa.lane lane)) (hb : Fp8Inv (xb.lane lane))
    (heq : decode (xa.lane lane) = decode (xb.lane lane)) :
    (xb.sub xa).is_zero_mask ≠ 0 := by
  have h := Fp8.testBit_is_zero_mask (Fp8.lane_sub hb ha).1
  rw [Fp8.decode_lane_sub hb ha, heq, sub_self] at h
  intro hz
  simp [hz] at h

theorem extend_chain_equal_x (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (products : Array fp8.Fp8 4#usize)
    (ha : g.val * 8 + 8 ≤ self.a.val.length) (hb : g.val * 8 + 8 ≤ self.b.val.length)
    (hba : indicesInBounds store (referencesAt self.a.val g.val).1)
    (hbb : indicesInBounds store (referencesAt self.b.val g.val).1)
    (lane : Fin 8)
    (hxa : Fp8Inv ((loadedCoordinate store (referencesAt self.a.val g.val).1 0).lane lane))
    (hxb : Fp8Inv ((loadedCoordinate store (referencesAt self.b.val g.val).1 0).lane lane))
    (heq : decode ((loadedCoordinate store (referencesAt self.a.val g.val).1 0).lane lane) =
      decode ((loadedCoordinate store (referencesAt self.b.val g.val).1 0).lane lane)) :
    self.extend_chain store g products = ok (false, self, products) := by
  exact extend_chain_zero self store g products _ _ _ _ _ _
    (Msm8.references_refines _ _ ha) (Msm8.references_refines _ _ hb)
    (load_x_refines store _ hba) (load_x_refines store _ hbb)
    (equal_x_zero_mask _ _ lane hxa hxb heq)

def chainIndex (g : Usize) : Usize :=
  UScalar.ofNatCore (g.val % 4)
    (lt_of_lt_of_le (by omega : g.val % 4 < 2 ^ 32) two_pow_32_le_usize)

theorem rem_four (g : Usize) : g % 4#usize = ok (chainIndex g) := by
  change UScalar.rem g 4#usize = _
  simp only [UScalar.rem, show ((4#usize).val != 0) = true from rfl, if_true]
  apply congrArg Result.ok
  apply UScalar.eq_of_val_eq
  exact BitVec.toNat_umod (x := g.bv) (y := (4#usize).bv)

def setFp8Entry (v : alloc.vec.Vec fp8.Fp8) (i : ℕ) (x : Fp8) : alloc.vec.Vec fp8.Fp8 :=
  ⟨v.val.set i (toFp8 x), by simpa using v.property⟩

theorem extend_chain_nonzero (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (products : Vector Fp8 4)
    (ia ib : Array U32 8#usize) (na nb : U8) (xa xb : Fp8)
    (hra : msm8.pairs.references self.a.deref g = ok (ia, na))
    (hrb : msm8.pairs.references self.b.deref g = ok (ib, nb))
    (hla : store.load_x ia = ok (toFp8 xa)) (hlb : store.load_x ib = ok (toFp8 xb))
    (hdx : g.val < self.dx.val.length) (hpref : g.val < self.prefix.val.length)
    (hzero : (xb.sub xa).is_zero_mask = 0) :
    let k : Fin 4 := ⟨g.val % 4, by omega⟩
    let dx := xb.sub xa
    let product := products[k].mul dx
    self.extend_chain store g (toArray toFp8 products) =
      ok (true, { self with
        dx := setFp8Entry self.dx g.val dx
        «prefix» := setFp8Entry self.prefix g.val product },
        toArray toFp8 (products.set k product)) := by
  have hk : (chainIndex g).val < (4#usize).val := by change g.val % 4 < 4; omega
  simp only [msm8.pairs.BatchedAdds.extend_chain, hra, hrb, bind_tc_ok]
  change (do
    let a ← store.load_x ia
    let b ← store.load_x ib
    let dx ← fp8.Fp8.sub b a
    let mask ← fp8.Fp8.is_zero_mask dx
    if mask != 0#u8 then ok (false, self, toArray (n := 4#usize) toFp8 products) else _) = _
  rw [hla, hlb]
  simp only [bind_tc_ok, Fp8.sub_refines, Fp8.is_zero_mask_refines, ofFp8_toFp8, hzero]
  simp only [show (toU8 (0 : UInt8) != 0#u8) = false from rfl, Bool.false_eq_true, if_false]
  rw [msm8.pairs.CHAINS, rem_four]
  simp only [bind_tc_ok, index_usize_toArray (n := 4#usize) toFp8 products rfl (chainIndex g) hk,
    Fp8.mul_refines, ofFp8_toFp8]
  rw [update_eq _ (chainIndex g) _ hk]
  simp only [bind_tc_ok]
  rw [vec_index_mut_eq self.dx g hdx]
  rw [set_toArray toFp8 products rfl (chainIndex g) _ hk]
  change (do
    let f2 ← Array.index_usize (toArray (n := 4#usize) toFp8
      (products.set (chainIndex g).val ((products[(chainIndex g).val]'hk).mul (xb.sub xa)) hk)) (chainIndex g)
    let (_, back) ← alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice fp8.Fp8) self.prefix g
    ok (true, { self with
      dx := setFp8Entry self.dx g.val (xb.sub xa)
      «prefix» := back f2 }, toArray (n := 4#usize) toFp8
      (products.set (chainIndex g).val ((products[(chainIndex g).val]'hk).mul (xb.sub xa)) hk))) = _
  rw [index_usize_toArray (n := 4#usize) toFp8
    (products.set (chainIndex g).val ((products[(chainIndex g).val]'hk).mul (xb.sub xa)) hk)
    rfl (chainIndex g) hk]
  rw [vec_index_mut_eq self.prefix g hpref]
  simp only [bind_tc_ok, Vector.getElem_set_self]
  rfl


def unwindValue (self : msm8.pairs.BatchedAdds) (group : ℕ) (inverses : Vector Fp8 4) : Fp8 :=
  let k : Fin 4 := ⟨group % 4, by omega⟩
  if group < 4 then inverses[k] else inverses[k].mul (ofFp8 self.prefix.val[group - 4]!)

def unwindStep (self : msm8.pairs.BatchedAdds) (g : ℕ)
    (state : Vector Fp8 4 × Vector Fp8 2) (j : Fin 2) : Vector Fp8 4 × Vector Fp8 2 :=
  let group := g + j.val
  let k : Fin 4 := ⟨group % 4, by omega⟩
  (state.1.set k (state.1[k].mul (ofFp8 self.dx.val[group]!)),
    state.2.set j (unwindValue self group state.1))

theorem unwind_pick (self : msm8.pairs.BatchedAdds) (group : Usize) (inv : Vector Fp8 4)
    (hb : group.val - 4 < self.prefix.val.length) :
    (if group < 4#usize then do
      let f ← Array.index_usize (toArray (n := 4#usize) toFp8 inv) (chainIndex group)
      ok (self, f)
    else do
      let f ← Array.index_usize (toArray (n := 4#usize) toFp8 inv) (chainIndex group)
      let i ← group - 4#usize
      let p ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fp8.Fp8) self.prefix i
      let value ← fp8.Fp8.mul f p
      ok (self, value)) = ok (self, toFp8 (unwindValue self group.val inv)) := by
  have hk : (chainIndex group).val < (4#usize).val := by change group.val % 4 < 4; omega
  by_cases h : group.val < 4
  · have hh : group < 4#usize := h
    simp only [hh, if_true, index_usize_toArray (n := 4#usize) toFp8 inv rfl (chainIndex group) hk,
      bind_tc_ok, unwindValue, h]
    rfl
  · have hh : ¬group < 4#usize := h
    simp only [hh, if_false, index_usize_toArray (n := 4#usize) toFp8 inv rfl (chainIndex group) hk,
      bind_tc_ok, unwindValue, h]
    rw [sub_ok group 4#usize (by change 4 ≤ group.val; omega)]
    simp only [bind_tc_ok]
    rw [vec_index_eq _ _ (by simpa using hb)]
    simp only [bind_tc_ok, Fp8.mul_refines, ofFp8_toFp8]
    simp only [getElem!_pos self.prefix.val (group.val - 4) hb]
    rfl

theorem unwind_body_refines (self : msm8.pairs.BatchedAdds) (g : Usize)
    (hg : g.val + 2 < 2 ^ 32) (hdx : g.val + 2 ≤ self.dx.val.length)
    (hpref : g.val + 2 ≤ self.prefix.val.length)
    (state : Vector Fp8 4 × Vector Fp8 2) (s : Usize) (j : Fin 2) (hs : s.val = j.val) :
    ∃ next : Usize, next.val = j.val + 1 ∧
      msm8.pairs.BatchedAdds.unwind_chains_loop.body g self
        (toArray toFp8 state.1) (toArray toFp8 state.2) s =
      ok (cont (self, toArray toFp8 (unwindStep self g.val state j).1,
        toArray toFp8 (unwindStep self g.val state j).2, next)) := by
  have hlt : s.val < 2 := by omega
  let group : Usize := UScalar.ofNatCore (g.val + s.val)
    (lt_of_lt_of_le (by omega : g.val + s.val < 2 ^ 32) two_pow_32_le_usize)
  let next : Usize := UScalar.ofNatCore (s.val + 1)
    (lt_of_lt_of_le (by omega : s.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  have hgroup : g + s = ok group := by rw [usize_add_ok _ _ (by omega)]
  have hk : (chainIndex group).val < (4#usize).val := by change group.val % 4 < 4; omega
  have hdxg : group.val < self.dx.val.length := by simp only [group, UScalar.ofNatCore_val_eq]; omega
  have hpick := unwind_pick self group state.1 (by simp only [group, UScalar.ofNatCore_val_eq]; omega)
  refine ⟨next, by simp [next, hs], ?_⟩
  simp only [msm8.pairs.BatchedAdds.unwind_chains_loop.body, msm8.pairs.PAIR,
    show s < 2#usize from hlt, if_true, hgroup, bind_tc_ok]
  rw [msm8.pairs.CHAINS, rem_four]
  simp only [bind_tc_ok]
  rw [hpick]
  simp only [bind_tc_ok]
  change (do
    let a ← Array.update (toArray (n := 2#usize) toFp8 state.2) s (toFp8 (unwindValue self group.val state.1))
    let f1 ← Array.index_usize (toArray (n := 4#usize) toFp8 state.1) (chainIndex group)
    let f2 ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fp8.Fp8) self.dx group
    let f3 ← fp8.Fp8.mul f1 f2
    let a1 ← Array.update (toArray (n := 4#usize) toFp8 state.1) (chainIndex group) f3
    let s1 ← s + 1#usize
    ok (cont (self, a1, a, s1))) = _
  rw [update_eq (n := 2#usize) _ s _ hlt]
  simp only [bind_tc_ok, index_usize_toArray (n := 4#usize) toFp8 state.1 rfl (chainIndex group) hk,
    vec_index_eq self.dx group hdxg, Fp8.mul_refines, ofFp8_toFp8]
  rw [update_eq _ (chainIndex group) _ hk]
  simp only [bind_tc_ok]
  rw [usize_add_ok s 1#usize (by change s.val + 1 < 2 ^ 32; omega)]
  simp only [bind_tc_ok]
  rw [set_toArray toFp8 state.2 rfl s _ hlt, set_toArray toFp8 state.1 rfl (chainIndex group) _ hk]
  simp only [unwindStep, group, chainIndex, next, UScalar.ofNatCore_val_eq, hs]
  simp only [getElem!_pos self.dx.val (g.val + j.val) (show g.val + j.val < self.dx.val.length by omega)]
  rfl

def unwindChains (self : msm8.pairs.BatchedAdds) (g : ℕ) (inverses : Vector Fp8 4) :
    Vector Fp8 2 × Vector Fp8 4 :=
  let result := (List.finRange 2).foldl (unwindStep self g) (inverses, Vector.replicate 2 Fp8.zero)
  (result.2, result.1)

theorem unwind_chains_refines (self : msm8.pairs.BatchedAdds) (g : Usize)
    (inverses : Vector Fp8 4) (hg : g.val + 2 < 2 ^ 32)
    (hdx : g.val + 2 ≤ self.dx.val.length) (hpref : g.val + 2 ≤ self.prefix.val.length) :
    self.unwind_chains g (toArray toFp8 inverses) =
      ok (toArray toFp8 (unwindChains self g.val inverses).1,
        toArray toFp8 (unwindChains self g.val inverses).2) := by
  simp only [msm8.pairs.BatchedAdds.unwind_chains, Fp8.zero_refines, bind_tc_ok]
  rw [← toArray_replicate toFp8 Fp8.zero (show (2#usize).val = 2 from rfl)]
  unfold msm8.pairs.BatchedAdds.unwind_chains_loop
  refine loop_up_inv (n := 2)
    (fun (self1, inv, output, s) => msm8.pairs.BatchedAdds.unwind_chains_loop.body g self1 inv output s)
    (fun (state : Vector Fp8 4 × Vector Fp8 2) s => (self, toArray toFp8 state.1, toArray toFp8 state.2, s))
    (unwindStep self g.val) (fun state => (toArray toFp8 state.2, toArray toFp8 state.1))
    (fun _ => True) (fun _ _ _ => trivial) ?_ ?_
    (inverses, Vector.replicate 2 Fp8.zero) 0#usize (by decide) trivial
  · intro state s hs _
    have hn : ¬s < 2#usize := by change ¬s.val < 2; omega
    simp only [msm8.pairs.BatchedAdds.unwind_chains_loop.body, msm8.pairs.PAIR, hn, if_false]
  · intro state s j hs _
    exact unwind_body_refines self g hg hdx hpref state s j hs

def difference (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (group : ℕ) : Fp8 :=
  (loadedCoordinate store (referencesAt self.b.val group).1 0).sub
    (loadedCoordinate store (referencesAt self.a.val group).1 0)

def preparedUpdate (self : msm8.pairs.BatchedAdds) (group : ℕ) (products : Vector Fp8 4) (dx : Fp8) :
    msm8.pairs.BatchedAdds × Vector Fp8 4 :=
  let k : Fin 4 := ⟨group % 4, by omega⟩
  let product := products[k].mul dx
  ({ self with dx := setFp8Entry self.dx group dx
               «prefix» := setFp8Entry self.prefix group product }, products.set k product)

def prepareStep (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (group : ℕ)
    (products : Vector Fp8 4) : Bool × msm8.pairs.BatchedAdds × Vector Fp8 4 :=
  let dx := difference self store group
  if dx.is_zero_mask = 0 then
    let updated := preparedUpdate self group products dx
    (true, updated.1, updated.2)
  else (false, self, products)

theorem extend_chain_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (products : Vector Fp8 4)
    (ha : g.val * 8 + 8 ≤ self.a.val.length) (hb : g.val * 8 + 8 ≤ self.b.val.length)
    (hba : indicesInBounds store (referencesAt self.a.val g.val).1)
    (hbb : indicesInBounds store (referencesAt self.b.val g.val).1)
    (hdx : g.val < self.dx.val.length) (hpref : g.val < self.prefix.val.length) :
    self.extend_chain store g (toArray toFp8 products) =
      let result := prepareStep self store g.val products
      ok (result.1, result.2.1, toArray toFp8 result.2.2) := by
  by_cases hzero : (difference self store g.val).is_zero_mask = 0
  · simp only [prepareStep, hzero, if_true, preparedUpdate]
    exact extend_chain_nonzero self store g products _ _ _ _ _ _
      (Msm8.references_refines _ _ ha) (Msm8.references_refines _ _ hb)
      (load_x_refines store _ hba) (load_x_refines store _ hbb) hdx hpref hzero
  · simp only [prepareStep, hzero, if_false]
    exact extend_chain_zero self store g (toArray toFp8 products) _ _ _ _ _ _
      (Msm8.references_refines _ _ ha) (Msm8.references_refines _ _ hb)
      (load_x_refines store _ hba) (load_x_refines store _ hbb) hzero

structure PreparationBounds (adds : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (groups : ℕ) : Prop where
  aLength : groups * 8 ≤ adds.a.val.length
  bLength : groups * 8 ≤ adds.b.val.length
  dxLength : groups ≤ adds.dx.val.length
  prefixLength : groups ≤ adds.prefix.val.length
  aBounds : ∀ g < groups, indicesInBounds store (referencesAt adds.a.val g).1
  bBounds : ∀ g < groups, indicesInBounds store (referencesAt adds.b.val g).1

theorem PreparationBounds.updated {self : msm8.pairs.BatchedAdds} {store : msm8.store.PointStore} {groups : ℕ}
    (h : PreparationBounds self store groups) (g : ℕ) (products : Vector Fp8 4) (dx : Fp8) :
    PreparationBounds (preparedUpdate self g products dx).1 store groups := by
  rcases h with ⟨ha, hb, hdx, hpref, hba, hbb⟩
  exact ⟨ha, hb, by simpa [preparedUpdate, setFp8Entry] using hdx,
    by simpa [preparedUpdate, setFp8Entry] using hpref, hba, hbb⟩

def prepareFrom (store : msm8.store.PointStore) :
    ℕ → msm8.pairs.BatchedAdds → Vector Fp8 4 → ℕ → msm8.pairs.BatchedAdds × Vector Fp8 4 × ℕ
  | 0, self, products, g => (self, products, g)
  | n + 1, self, products, g =>
    let result := prepareStep self store g products
    if result.1 then prepareFrom store n result.2.1 result.2.2 (g + 1)
    else (result.2.1, result.2.2, g)

theorem prepareFrom_range (store : msm8.store.PointStore) (n : ℕ)
    (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4) (g : ℕ) :
    g ≤ (prepareFrom store n self products g).2.2 ∧
      (prepareFrom store n self products g).2.2 ≤ g + n := by
  induction n generalizing self products g with
  | zero => simp [prepareFrom]
  | succ n ih =>
    simp only [prepareFrom]
    split
    · have h := ih (prepareStep self store g products).2.1 (prepareStep self store g products).2.2 (g + 1)
      omega
    · simp only
      omega

theorem prepare_loop_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups : Usize) (products : Vector Fp8 4) (g : Usize)
    (hgroups : groups.val < 2 ^ 32) (hg : g.val ≤ groups.val)
    (hb : PreparationBounds self store groups.val) :
    let result := prepareFrom store (groups.val - g.val) self products g.val
    ∃ counter : Usize, counter.val = result.2.2 ∧
      self.run_loop0 store groups (toArray toFp8 products) g =
        ok (result.1, toArray toFp8 result.2.1, counter) := by
  unfold msm8.pairs.BatchedAdds.run_loop0
  induction hn : groups.val - g.val generalizing self products g with
  | zero =>
    have hge : ¬g < groups := by change ¬g.val < groups.val; omega
    refine ⟨g, rfl, ?_⟩
    rw [loop.eq_1]
    simp only [msm8.pairs.BatchedAdds.run_loop0.body, hge, if_false, prepareFrom]
  | succ n ih =>
    have hlt : g < groups := by change g.val < groups.val; omega
    have hstep := extend_chain_refines self store g products
      (by have := hb.aLength; change g.val < groups.val at hlt; omega)
      (by have := hb.bLength; change g.val < groups.val at hlt; omega)
      (hb.aBounds g.val hlt) (hb.bBounds g.val hlt)
      (by have := hb.dxLength; change g.val < groups.val at hlt; omega)
      (by have := hb.prefixLength; change g.val < groups.val at hlt; omega)
    by_cases hz : (difference self store g.val).is_zero_mask = 0
    · let updated := preparedUpdate self g.val products (difference self store g.val)
      let next : Usize := UScalar.ofNatCore (g.val + 1)
        (lt_of_lt_of_le (by change g.val < groups.val at hlt; omega) two_pow_32_le_usize)
      obtain ⟨counter, hcounter, hloop⟩ := ih updated.1 updated.2 next
        (by simp only [next, UScalar.ofNatCore_val_eq]; change g.val < groups.val at hlt; omega)
        (hb.updated g.val products (difference self store g.val))
        (by simp only [next, UScalar.ofNatCore_val_eq]; omega)
      refine ⟨counter, ?_, ?_⟩
      · simpa only [prepareFrom, prepareStep, hz, if_true, next, UScalar.ofNatCore_val_eq] using hcounter
      · rw [loop.eq_1]
        simp only [msm8.pairs.BatchedAdds.run_loop0.body, hlt, if_true, hstep, bind_tc_ok,
          prepareStep, hz, prepareFrom]
        rw [usize_add_ok g 1#usize (by change g.val + 1 < 2 ^ 32; change g.val < groups.val at hlt; omega)]
        simpa only [bind_tc_ok, updated, next] using hloop
    · refine ⟨g, ?_, ?_⟩
      · simp only [prepareFrom, prepareStep, hz, if_false, Bool.false_eq_true]
      · rw [loop.eq_1]
        simp only [msm8.pairs.BatchedAdds.run_loop0.body, hlt, if_true, hstep, bind_tc_ok,
          prepareFrom, prepareStep, hz, if_false]
        rfl

open EthCryptographySpecs.Bls

abbrev ChainField := ZMod Fp.modulus

def chainValues (a : ℕ → ChainField) : ℕ → Fin 4 → ChainField
  | 0 => fun _ => 1
  | g + 1 =>
    let k : Fin 4 := ⟨g % 4, by omega⟩
    Function.update (chainValues a g) k (chainValues a g k * a g)

structure ChainInvariant (adds : msm8.pairs.BatchedAdds) (products : Vector Fp8 4)
    (a : ℕ → ChainField) (g : ℕ) (lane : Fin 8) : Prop where
  product : ∀ k : Fin 4, products[k].Holds lane (chainValues a g k)
  savedDifference : ∀ i < g, (ofFp8 adds.dx.val[i]!).Holds lane (a i)
  savedPrefix : ∀ i < g, (ofFp8 adds.prefix.val[i]!).Holds lane
    (chainValues a (i + 1) ⟨i % 4, by omega⟩)
  nonzero : ∀ i < g, a i ≠ 0

theorem setFp8Entry_get_self (v : alloc.vec.Vec fp8.Fp8) (i : ℕ) (x : Fp8)
    (hi : i < v.val.length) : ofFp8 (setFp8Entry v i x).val[i]! = x := by
  simp [setFp8Entry, hi]

theorem setFp8Entry_get_ne (v : alloc.vec.Vec fp8.Fp8) (i j : ℕ) (x : Fp8)
    (hne : i ≠ j) : ofFp8 (setFp8Entry v i x).val[j]! = ofFp8 v.val[j]! := by
  simp [setFp8Entry, getElem!_def, List.getElem?_set_ne hne]

theorem ChainInvariant.updated {self : msm8.pairs.BatchedAdds} {products : Vector Fp8 4}
    {a : ℕ → ChainField} {g : ℕ} {lane : Fin 8}
    (h : ChainInvariant self products a g lane) (dx : Fp8) (hv : dx.Holds lane (a g))
    (hnz : a g ≠ 0) (hdx : g < self.dx.val.length) (hpref : g < self.prefix.val.length) :
    ChainInvariant (preparedUpdate self g products dx).1 (preparedUpdate self g products dx).2
      a (g + 1) lane := by
  let key : Fin 4 := ⟨g % 4, by omega⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro k
    by_cases hk : k = key
    · subst k
      simpa [preparedUpdate, chainValues, key] using (h.product key).mul hv
    · have hne : g % 4 ≠ k.val := by intro heq; apply hk; apply Fin.ext; exact heq.symm
      simpa [preparedUpdate, chainValues, key, Fin.getElem_fin, Vector.getElem_set_ne, hne,
        show k ≠ ⟨g % 4, by omega⟩ from hk] using h.product k
  · intro i hi
    by_cases heq : i = g
    · subst i
      simpa only [preparedUpdate, setFp8Entry_get_self self.dx g dx hdx] using hv
    · have hne : g ≠ i := Ne.symm heq
      simpa only [preparedUpdate, setFp8Entry_get_ne self.dx g i dx hne] using h.savedDifference i (by omega)
  · intro i hi
    by_cases heq : i = g
    · subst i
      change (ofFp8 (setFp8Entry self.prefix g (products[key].mul dx)).val[g]!).Holds lane _
      rw [setFp8Entry_get_self self.prefix g (products[key].mul dx) hpref]
      simpa [chainValues, key] using (h.product key).mul hv
    · have hne : g ≠ i := Ne.symm heq
      simpa only [preparedUpdate, setFp8Entry_get_ne self.prefix g i _ hne] using h.savedPrefix i (by omega)
  · intro i hi
    by_cases heq : i = g
    · simpa only [heq] using hnz
    · exact h.nonzero i (by omega)

theorem mask_clear_nonzero (x : Fp8) (lane : Fin 8) (a : ChainField)
    (hx : x.Holds lane a) (hm : x.is_zero_mask = 0) : a ≠ 0 := by
  have h := hx.testBit_is_zero_mask
  intro ha
  simp [hm, ha] at h

theorem chainValues_nonzero (a : ℕ → ChainField) (g : ℕ) (h : ∀ i < g, a i ≠ 0) :
    ∀ k, chainValues a g k ≠ 0 := by
  induction g with
  | zero => simp [chainValues]
  | succ g ih =>
    intro k
    by_cases hk : k = ⟨g % 4, by omega⟩
    · simp only [chainValues, hk, Function.update_self]
      exact mul_ne_zero (ih (fun i hi => h i (by omega)) _) (h g (by omega))
    · simp only [chainValues, Function.update_of_ne hk]
      exact ih (fun i hi => h i (by omega)) k

theorem ChainInvariant.initial (self : msm8.pairs.BatchedAdds) (a : ℕ → ChainField) (lane : Fin 8) :
    ChainInvariant self (Vector.replicate 4 Fp8.one) a 0 lane := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro k; simpa [chainValues] using Fp8.holds_one lane
  · intro i hi; omega
  · intro i hi; omega
  · intro i hi; omega

theorem prepareFrom_chainInvariant (store : msm8.store.PointStore) (n : ℕ)
    (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4) (g groups : ℕ)
    (a : ℕ → ChainField) (lane : Fin 8)
    (hcap : g + n ≤ groups) (hb : PreparationBounds self store groups)
    (hi : ChainInvariant self products a g lane)
    (hdiff : ∀ i < groups, (difference self store i).Holds lane (a i)) :
    let result := prepareFrom store n self products g
    ChainInvariant result.1 result.2.1 a result.2.2 lane := by
  induction n generalizing self products g with
  | zero => exact hi
  | succ n ih =>
    by_cases hz : (difference self store g).is_zero_mask = 0
    · simp only [prepareFrom, prepareStep, hz, if_true]
      apply ih _ _ (g + 1) (by omega) (hb.updated g products (difference self store g))
      · exact hi.updated _ (hdiff g (by omega))
          (mask_clear_nonzero _ lane _ (hdiff g (by omega)) hz)
          (by have := hb.dxLength; omega) (by have := hb.prefixLength; omega)
      · exact hdiff
    · simpa only [prepareFrom, prepareStep, hz, if_false, Bool.false_eq_true] using hi

theorem chainValues_step_ne (a : ℕ → ChainField) (g : ℕ) (k : Fin 4)
    (hne : g % 4 ≠ k.val) : chainValues a (g + 1) k = chainValues a g k := by
  simp only [chainValues, Function.update_of_ne (show k ≠ ⟨g % 4, by omega⟩ from
    fun heq => hne (congrArg Fin.val heq).symm)]

theorem chainValues_previous (a : ℕ → ChainField) (g : ℕ) :
    let k : Fin 4 := ⟨g % 4, by omega⟩
    chainValues a g k = if g < 4 then 1 else chainValues a (g - 3) k := by
  by_cases hg : g < 4
  · interval_cases g <;> simp [chainValues]
  · simp only [hg, if_false]
    have h1 := chainValues_step_ne a (g - 1) ⟨g % 4, by omega⟩ (by simp only; omega)
    have h2 := chainValues_step_ne a (g - 2) ⟨g % 4, by omega⟩ (by simp only; omega)
    have h3 := chainValues_step_ne a (g - 3) ⟨g % 4, by omega⟩ (by simp only; omega)
    rw [show g - 1 + 1 = g by omega] at h1
    rw [show g - 2 + 1 = g - 1 by omega] at h2
    rw [show g - 3 + 1 = g - 2 by omega] at h3
    exact h1.trans (h2.trans h3)

theorem unwindValue_correct (self : msm8.pairs.BatchedAdds) (products inv : Vector Fp8 4)
    (a : ℕ → ChainField) (processed g : ℕ) (lane : Fin 8)
    (hstate : ChainInvariant self products a processed lane) (hg : g < processed)
    (hinv : inv[(⟨g % 4, by omega⟩ : Fin 4)].Holds lane (chainValues a (g + 1) ⟨g % 4, by omega⟩)⁻¹) :
    (unwindValue self g inv).Holds lane (a g)⁻¹ := by
  let key : Fin 4 := ⟨g % 4, by omega⟩
  have hcurrent : chainValues a (g + 1) key = chainValues a g key * a g := by
    simp [chainValues, key]
  have hprevious := chainValues_previous a g
  change chainValues a g key = _ at hprevious
  by_cases hsmall : g < 4
  · rw [if_pos hsmall] at hprevious
    simpa only [unwindValue, hsmall, if_true, ← show key = ⟨g % 4, by omega⟩ from rfl,
      hcurrent, hprevious, one_mul] using hinv
  · rw [if_neg hsmall] at hprevious
    have hkey : (⟨(g - 4) % 4, by omega⟩ : Fin 4) = key := by apply Fin.ext; simp only [key]; omega
    have hprior := hstate.savedPrefix (g - 4) (by omega)
    rw [show g - 4 + 1 = g - 3 by omega, hkey, ← hprevious] at hprior
    have hnonzero := chainValues_nonzero a g (fun i hi => hstate.nonzero i (by omega)) key
    have hout := hinv.mul hprior
    apply Fp8.Holds.of_eq (by simpa only [unwindValue, hsmall, if_false, key] using hout)
    rw [hcurrent, mul_inv_rev, mul_assoc, inv_mul_cancel₀ hnonzero, mul_one]

section
attribute [local irreducible] Fp8.mul Fp8.zero unwindValue

def popChain (self : msm8.pairs.BatchedAdds) (g : ℕ) (inv : Vector Fp8 4) : Vector Fp8 4 :=
  let k : Fin 4 := ⟨g % 4, by omega⟩
  inv.set k (inv[k].mul (ofFp8 self.dx.val[g]!))

theorem popChain_get_self (self : msm8.pairs.BatchedAdds) (g : ℕ) (inv : Vector Fp8 4) :
    (popChain self g inv)[(⟨g % 4, by omega⟩ : Fin 4)] =
      inv[(⟨g % 4, by omega⟩ : Fin 4)].mul (ofFp8 self.dx.val[g]!) := by simp [popChain]

theorem popChain_get_ne (self : msm8.pairs.BatchedAdds) (g : ℕ) (inv : Vector Fp8 4)
    (k : Fin 4) (hne : g % 4 ≠ k.val) : (popChain self g inv)[k] = inv[k] := by
  simp [popChain, Fin.getElem_fin, Vector.getElem_set_ne, hne]

theorem popChain_correct (self : msm8.pairs.BatchedAdds) (products inv : Vector Fp8 4)
    (a : ℕ → ChainField) (processed g : ℕ) (lane : Fin 8)
    (hstate : ChainInvariant self products a processed lane) (hg : g < processed)
    (hinv : inv[(⟨g % 4, by omega⟩ : Fin 4)].Holds lane (chainValues a (g + 1) ⟨g % 4, by omega⟩)⁻¹) :
    (popChain self g inv)[(⟨g % 4, by omega⟩ : Fin 4)].Holds lane (chainValues a g ⟨g % 4, by omega⟩)⁻¹ := by
  rw [popChain_get_self]
  apply (hinv.mul (hstate.savedDifference g hg)).of_eq
  simp only [chainValues, Function.update_self, mul_inv_rev]
  calc
    (a g)⁻¹ * (chainValues a g ⟨g % 4, by omega⟩)⁻¹ * a g =
      (chainValues a g ⟨g % 4, by omega⟩)⁻¹ * ((a g)⁻¹ * a g) := by ring
    _ = _ := by rw [inv_mul_cancel₀ (hstate.nonzero g hg), mul_one]

theorem unwindChains_eq (self : msm8.pairs.BatchedAdds) (g : ℕ) (inv : Vector Fp8 4) :
    unwindChains self g inv =
      (((Vector.replicate 2 Fp8.zero).set 0 (unwindValue self g inv)).set 1
        (unwindValue self (g + 1) (popChain self g inv)),
        popChain self (g + 1) (popChain self g inv)) := by
  simp only [unwindChains, show List.finRange 2 = [0, 1] from rfl, List.foldl_cons, List.foldl_nil,
    unwindStep, popChain, Fin.val_zero, Fin.val_one, Nat.add_zero]

theorem unwindChains_correct (self : msm8.pairs.BatchedAdds) (products inv : Vector Fp8 4)
    (a : ℕ → ChainField) (processed g : ℕ) (lane : Fin 8)
    (hstate : ChainInvariant self products a processed lane) (hg : g + 2 ≤ processed)
    (hinv : ∀ k : Fin 4, inv[k].Holds lane (chainValues a (g + 2) k)⁻¹) :
    (∀ j : Fin 2, (unwindChains self g inv).1[j].Holds lane (a (g + j.val))⁻¹) ∧
    (∀ k : Fin 4, (unwindChains self g inv).2[k].Holds lane (chainValues a g k)⁻¹) := by
  let k0 : Fin 4 := ⟨g % 4, by omega⟩
  let k1 : Fin 4 := ⟨(g + 1) % 4, by omega⟩
  have h01 : g % 4 ≠ k1.val := by simp only [k1]; omega
  have h10 : (g + 1) % 4 ≠ k0.val := by simp only [k0]; omega
  have hc0 := chainValues_step_ne a (g + 1) k0 h10
  have hi0 : inv[k0].Holds lane (chainValues a (g + 1) k0)⁻¹ :=
    (hinv k0).of_eq (congrArg Inv.inv hc0)
  have hi1 : (popChain self g inv)[k1].Holds lane (chainValues a (g + 2) k1)⁻¹ := by
    rw [popChain_get_ne self g inv k1 h01]
    exact hinv k1
  have hv0 := unwindValue_correct self products inv a processed g lane hstate (by omega) hi0
  have hv1 := unwindValue_correct self products (popChain self g inv) a processed (g + 1) lane hstate (by omega) hi1
  have hp0 := popChain_correct self products inv a processed g lane hstate (by omega) hi0
  have hp1 := popChain_correct self products (popChain self g inv) a processed (g + 1) lane hstate (by omega) hi1
  rw [unwindChains_eq]
  constructor
  · intro j
    fin_cases j
    · simpa using hv0
    · simpa using hv1
  · intro k
    by_cases hk1 : k = k1
    · subst k
      exact hp1.of_eq (congrArg Inv.inv (chainValues_step_ne a g k1 h01))
    · have hn1 : (g + 1) % 4 ≠ k.val := by intro heq; apply hk1; apply Fin.ext; exact heq.symm
      rw [popChain_get_ne _ _ _ k hn1]
      by_cases hk0 : k = k0
      · subst k; exact hp0
      · have hn0 : g % 4 ≠ k.val := by intro heq; apply hk0; apply Fin.ext; exact heq.symm
        rw [popChain_get_ne _ _ _ k hn0]
        exact (hinv k).of_eq (congrArg Inv.inv
          ((chainValues_step_ne a (g + 1) k hn1).trans (chainValues_step_ne a g k hn0)))

end

theorem prepareFrom_rejected (store : msm8.store.PointStore) (n : ℕ)
    (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4) (g : ℕ)
    (hstopped : (prepareFrom store n self products g).2.2 < g + n) :
    (difference (prepareFrom store n self products g).1 store
      (prepareFrom store n self products g).2.2).is_zero_mask ≠ 0 := by
  induction n generalizing self products g with
  | zero => simp only [prepareFrom] at hstopped; omega
  | succ n ih =>
    by_cases hz : (difference self store g).is_zero_mask = 0
    · simp only [prepareFrom, prepareStep, hz, if_true] at hstopped ⊢
      exact ih _ _ (g + 1) (by omega)
    · simp only [prepareFrom, prepareStep, hz, if_false, Bool.false_eq_true]
      exact hz

theorem prepareFrom_references (store : msm8.store.PointStore) (n : ℕ)
    (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4) (g : ℕ) :
    let result := (prepareFrom store n self products g).1
    result.a = self.a ∧ result.b = self.b ∧ result.out = self.out := by
  induction n generalizing self products g with
  | zero => simp [prepareFrom]
  | succ n ih =>
    by_cases hz : (difference self store g).is_zero_mask = 0
    · simpa only [prepareFrom, prepareStep, hz, if_true, preparedUpdate] using
        ih (preparedUpdate self g products (difference self store g)).1
          (preparedUpdate self g products (difference self store g)).2 (g + 1)
    · simp only [prepareFrom, prepareStep, hz, if_false, Bool.false_eq_true, and_self]

section
attribute [local irreducible] writeCoordinates Msm8.affineAdd signedCoordinates

theorem finishPair_length (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) :
    (finishPair self store g inv).rows.val.length = store.rows.val.length := by
  let step := fun (current : msm8.store.PointStore) (j : Fin 2) =>
    let a := signedCoordinates store (referencesAt self.a.val (g + j.val))
    let b := signedCoordinates store (referencesAt self.b.val (g + j.val))
    let result := Msm8.affineAdd a.1 a.2 b.1 b.2 inv[j]
    writeCoordinates current (referencesAt self.out.val (g + j.val)).1 result.1 result.2
  have hs (current : msm8.store.PointStore) (j : Fin 2) :
      (step current j).rows.val.length = current.rows.val.length := writeCoordinates_length current _ _ _
  have hf (js : List (Fin 2)) (current : msm8.store.PointStore) :
      (js.foldl step current).rows.val.length = current.rows.val.length := by
    induction js generalizing current with
    | nil => rfl
    | cons j js ih => exact (ih (step current j)).trans (hs current j)
  exact hf (List.finRange 2) store

structure ExecutionBounds (adds : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (groups : ℕ) : Prop where
  prep : PreparationBounds adds store groups
  outLength : groups * 8 ≤ adds.out.val.length
  outBounds : ∀ g < groups, indicesInBounds store (referencesAt adds.out.val g).1

theorem ExecutionBounds.with_store {self : msm8.pairs.BatchedAdds} {store : msm8.store.PointStore}
    {groups : ℕ} (h : ExecutionBounds self store groups) (updated : msm8.store.PointStore)
    (hlen : updated.rows.val.length = store.rows.val.length) : ExecutionBounds self updated groups := by
  refine ⟨⟨h.prep.aLength, h.prep.bLength, h.prep.dxLength, h.prep.prefixLength, ?_, ?_⟩, h.outLength, ?_⟩
  · intro g hg; simpa only [indicesInBounds, hlen] using h.prep.aBounds g hg
  · intro g hg; simpa only [indicesInBounds, hlen] using h.prep.bBounds g hg
  · intro g hg; simpa only [indicesInBounds, hlen] using h.outBounds g hg

def executeFrom (self : msm8.pairs.BatchedAdds) :
    ℕ → msm8.store.PointStore → Vector Fp8 4 → msm8.store.PointStore
  | 0, store, _ => store
  | n + 1, store, inv =>
    let recovered := unwindChains self (2 * n) inv
    executeFrom self n (finishPair self store (2 * n) recovered.1) recovered.2

theorem execute_loop_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups : ℕ) (inv : Vector Fp8 4) (g : Usize) (n : ℕ)
    (hgroups : groups < 2 ^ 32) (hg : g.val = 2 * n) (hcap : g.val ≤ groups)
    (hb : ExecutionBounds self store groups) :
    self.run_loop1 store g (toArray toFp8 inv) = ok (executeFrom self n store inv) := by
  unfold msm8.pairs.BatchedAdds.run_loop1
  induction n generalizing store inv g with
  | zero =>
    have hz : ¬g > 0#usize := by change ¬0 < g.val; omega
    rw [loop.eq_1]
    simp only [msm8.pairs.BatchedAdds.run_loop1.body, hz, if_false, executeFrom]
  | succ n ih =>
    have hpos : g > 0#usize := by change 0 < g.val; omega
    let group : Usize := UScalar.ofNatCore (2 * n)
      (lt_of_lt_of_le (by omega : 2 * n < 2 ^ 32) two_pow_32_le_usize)
    have hsub : g - msm8.pairs.PAIR = ok group := by
      rw [msm8.pairs.PAIR, sub_ok _ _ (by change 2 ≤ g.val; omega)]
      congr 1
      apply UScalar.eq_of_val_eq
      simp only [UScalar.ofNatCore_val_eq, group]
      omega
    have hunwind := unwind_chains_refines self group inv
      (by simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (by have := hb.prep.dxLength; simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (by have := hb.prep.prefixLength; simp only [group, UScalar.ofNatCore_val_eq]; omega)
    have hfinish := finish_pair_concrete self store group (unwindChains self group.val inv).1
      (by simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (by have := hb.prep.aLength; simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (by have := hb.prep.bLength; simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (by have := hb.outLength; simp only [group, UScalar.ofNatCore_val_eq]; omega)
      (fun j => hb.prep.aBounds _ (by simp only [group, UScalar.ofNatCore_val_eq]; omega))
      (fun j => hb.prep.bBounds _ (by simp only [group, UScalar.ofNatCore_val_eq]; omega))
      (fun j => hb.outBounds _ (by simp only [group, UScalar.ofNatCore_val_eq]; omega))
    have hbody : msm8.pairs.BatchedAdds.run_loop1.body self store g (toArray toFp8 inv) =
        ok (cont (finishPair self store group.val (unwindChains self group.val inv).1,
          group, toArray (n := 4#usize) toFp8 (unwindChains self group.val inv).2)) := by
      simp only [msm8.pairs.BatchedAdds.run_loop1.body, hpos, if_true, hsub, bind_tc_ok, hunwind]
      change (do
        let store1 ← self.finish_pair store group (toArray toFp8 (unwindChains self group.val inv).1)
        ok (cont (store1, group, toArray (n := 4#usize) toFp8 (unwindChains self group.val inv).2))) = _
      rw [hfinish]
      rfl
    rw [loop.eq_1]
    simp only [hbody]
    rw [ih _ _ group (by simp [group]) (by simp [group]; omega)
      (hb.with_store _ (finishPair_length _ _ _ _))]
    rfl

end

theorem executeFrom_invariant (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4)
    (a : Fin 8 → ℕ → ChainField) (processed : ℕ)
    (hstate : ∀ lane, ChainInvariant self products (a lane) processed lane)
    (P : ℕ → msm8.store.PointStore → Prop)
    (hstep : ∀ n store recovered, 2 * (n + 1) ≤ processed → P (n + 1) store →
      (∀ lane (j : Fin 2), recovered[j].Holds lane (a lane (2 * n + j.val))⁻¹) →
      P n (finishPair self store (2 * n) recovered))
    (n : ℕ) (store : msm8.store.PointStore) (inv : Vector Fp8 4)
    (hcap : 2 * n ≤ processed) (hp : P n store)
    (hinv : ∀ lane (k : Fin 4), inv[k].Holds lane (chainValues (a lane) (2 * n) k)⁻¹) :
    P 0 (executeFrom self n store inv) := by
  induction n generalizing store inv with
  | zero => exact hp
  | succ n ih =>
    have hu (lane : Fin 8) := unwindChains_correct self products inv (a lane)
      processed (2 * n) lane (hstate lane) (by omega)
      (by simpa only [Nat.mul_add, Nat.mul_one] using hinv lane)
    apply ih _ _ (by omega)
    · exact hstep n store (unwindChains self (2 * n) inv).1 hcap hp (fun lane => (hu lane).1)
    · exact fun lane => (hu lane).2

def resizeVec {α : Type} (v : alloc.vec.Vec α) (n : Usize) (x : α) : alloc.vec.Vec α :=
  ⟨v.val.resize n.val x, by simp only [List.resize_length]; scalar_tac⟩

theorem resizeVec_refines {α : Type} (v : alloc.vec.Vec α) (n : Usize) (x : α)
    (clone : core.clone.Clone α) (hc : clone.clone x = ok x) :
    alloc.vec.Vec.resize clone v n x = ok (resizeVec v n x) := by
  obtain ⟨out, ho, hv⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec clone v n x hc)
  have heq : out = resizeVec v n x := Subtype.ext hv
  exact heq ▸ ho

def paddedAdds (self : msm8.pairs.BatchedAdds) (groups entries : Usize) : msm8.pairs.BatchedAdds :=
  let last := self.a.val.length - 1
  { a := resizeVec self.a entries self.a.val[last]!
    b := resizeVec self.b entries self.b.val[last]!
    out := resizeVec self.out entries self.out.val[last]!
    dx := resizeVec self.dx groups (toFp8 Fp8.zero)
    «prefix» := resizeVec self.prefix groups (toFp8 Fp8.zero) }

theorem ExecutionBounds.updated {self : msm8.pairs.BatchedAdds} {store : msm8.store.PointStore}
    {groups : ℕ} (h : ExecutionBounds self store groups) (g : ℕ) (products : Vector Fp8 4) (dx : Fp8) :
    ExecutionBounds (preparedUpdate self g products dx).1 store groups :=
  ⟨h.prep.updated g products dx, h.outLength, h.outBounds⟩

theorem prepareFrom_bounds (store : msm8.store.PointStore) (n : ℕ)
    (self : msm8.pairs.BatchedAdds) (products : Vector Fp8 4) (g groups : ℕ)
    (hb : ExecutionBounds self store groups) :
    ExecutionBounds (prepareFrom store n self products g).1 store groups := by
  induction n generalizing self products g with
  | zero => exact hb
  | succ n ih =>
    by_cases hz : (difference self store g).is_zero_mask = 0
    · simp only [prepareFrom, prepareStep, hz, if_true]
      exact ih _ _ _ (hb.updated _ _ _)
    · simpa only [prepareFrom, prepareStep, hz, if_false, Bool.false_eq_true] using hb

def runBody (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (groups : Usize) :
    Result (Bool × msm8.pairs.BatchedAdds × msm8.store.PointStore) := do
  let (prepared, products, g) ← self.run_loop0 store groups (toArray toFp8 (Vector.replicate 4 Fp8.one)) 0#usize
  if g < groups then ok (false, prepared, store)
  else
    let inv ← msm8.pairs.batch_inverse products
    let out ← prepared.run_loop1 store g inv
    ok (true, prepared, out)

theorem run_initializes (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups entries : Usize)
    (ha : 0 < self.a.val.length) (hb : self.a.val.length ≤ self.b.val.length)
    (ho : self.a.val.length ≤ self.out.val.length)
    (hg : groups.val = ((self.a.val.length - 1) / 16 + 1) * 2)
    (he : entries.val = groups.val * 8) (hsize : entries.val < 2 ^ 32) :
    self.run store = runBody (paddedAdds self groups entries) store groups := by
  let last : Usize := UScalar.ofNatCore (self.a.val.length - 1)
    (by have := (alloc.vec.Vec.len self.a).hBounds; change self.a.val.length < 2 ^ UScalarTy.Usize.numBits at this; omega)
  let q : Usize := UScalar.ofNatCore ((self.a.val.length - 1) / 16)
    (lt_of_le_of_lt (Nat.div_le_self _ _) last.hBounds)
  let q1 : Usize := UScalar.ofNatCore (q.val + 1)
    (lt_of_lt_of_le (by simp only [q, UScalar.ofNatCore_val_eq]; omega) two_pow_32_le_usize)
  have hlast : alloc.vec.Vec.len self.a - 1#usize = ok last := by
    rw [sub_ok _ _ (by simp only [alloc.vec.Vec.len_val]; change 1 ≤ self.a.val.length; omega)]
    rfl
  have hpair : msm8.pairs.PAIR * fp8.LANES = ok 16#usize := by
    rw [msm8.pairs.PAIR, fp8.LANES, mul_ok _ _ (by simpa using lt_of_lt_of_le (by decide : 16 < 2 ^ 32) two_pow_32_le_usize)]
    rfl
  have hdiv : last / 16#usize = ok q := by rw [div_ok _ _ (by decide)]; rfl
  have hadd : q + 1#usize = ok q1 := by
    rw [add_ok _ _ (by simpa only [q, UScalar.ofNatCore_val_eq] using q1.hBounds)]
    rfl
  have hgroups : q1 * msm8.pairs.PAIR = ok groups := by
    rw [msm8.pairs.PAIR, mul_ok _ _ (by
      simp only [q1, q, UScalar.ofNatCore_val_eq]
      rw [← hg]; exact lt_of_lt_of_le (by omega) two_pow_32_le_usize)]
    congr 1
    apply UScalar.eq_of_val_eq
    simpa only [q1, q, UScalar.ofNatCore_val_eq] using hg.symm
  have hentries : groups * fp8.LANES = ok entries := by
    rw [fp8.LANES, mul_ok _ _ (by change groups.val * 8 < 2 ^ UScalarTy.Usize.numBits; rw [← he]; exact lt_of_lt_of_le hsize two_pow_32_le_usize)]
    congr 1
    apply UScalar.eq_of_val_eq
    exact he.symm
  have hia := vec_index_eq self.a last (by simp only [last, UScalar.ofNatCore_val_eq]; omega)
  have hib := vec_index_eq self.b last (by simp only [last, UScalar.ofNatCore_val_eq]; omega)
  have hio := vec_index_eq self.out last (by simp only [last, UScalar.ofNatCore_val_eq]; omega)
  have hnonempty : self.a.val.isEmpty = false := List.isEmpty_eq_false_iff.mpr (List.ne_nil_of_length_pos ha)
  simp only [msm8.pairs.BatchedAdds.run, alloc.vec.Vec.is_empty, hnonempty, bind_tc_ok,
    Bool.false_eq_true, not_false_eq_true, massert, if_true, hlast, hpair, hdiv, hadd, hgroups,
    hia, hib, hio, hentries]
  rw [resizeVec_refines _ _ _ _ (by rfl), resizeVec_refines _ _ _ _ (by rfl),
    resizeVec_refines _ _ _ _ (by rfl)]
  simp only [bind_tc_ok, Fp8.zero_refines]
  rw [resizeVec_refines _ _ _ _ (by rfl), resizeVec_refines _ _ _ _ (by rfl)]
  simp only [bind_tc_ok, Fp8.one_refines]
  rw [← toArray_replicate toFp8 Fp8.one (show (4#usize).val = 4 by simp)]
  have hla : self.a.val[self.a.val.length - 1]! = self.a.val[self.a.val.length - 1] :=
    getElem!_pos self.a.val (self.a.val.length - 1) (by omega)
  have hlb : self.b.val[self.a.val.length - 1]! = self.b.val[self.a.val.length - 1] :=
    getElem!_pos self.b.val (self.a.val.length - 1) (by omega)
  have hlo : self.out.val[self.a.val.length - 1]! = self.out.val[self.a.val.length - 1] :=
    getElem!_pos self.out.val (self.a.val.length - 1) (by omega)
  simp only [runBody, paddedAdds, hla, hlb, hlo, last, UScalar.ofNatCore_val_eq]

def runModel (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (groups : ℕ) :
    Bool × msm8.pairs.BatchedAdds × msm8.store.PointStore :=
  let prepared := prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0
  if prepared.2.2 < groups then (false, prepared.1, store)
  else (true, prepared.1, executeFrom prepared.1 (groups / 2) store (Msm8.batchInverse prepared.2.1))

theorem runBody_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups : Usize) (n : ℕ) (heven : groups.val = 2 * n) (hgroups : groups.val < 2 ^ 32)
    (hb : ExecutionBounds self store groups.val) :
    runBody self store groups = ok (runModel self store groups.val) := by
  obtain ⟨counter, hcounter, hprep⟩ := prepare_loop_refines self store groups
    (Vector.replicate 4 Fp8.one) 0#usize hgroups (by simp) hb.prep
  simp only [show (0#usize).val = 0 from rfl, Nat.sub_zero] at hcounter hprep
  let prepared := prepareFrom store groups.val self (Vector.replicate 4 Fp8.one) 0
  change counter.val = prepared.2.2 at hcounter
  have hbounds := prepareFrom_bounds store groups.val self (Vector.replicate 4 Fp8.one) 0 groups.val hb
  have hrange := (prepareFrom_range store groups.val self (Vector.replicate 4 Fp8.one) 0).2
  change prepared.2.2 ≤ 0 + groups.val at hrange
  unfold runBody
  rw [hprep]
  change (if counter < groups then ok (false, prepared.1, store) else do
    let inv ← msm8.pairs.batch_inverse (toArray toFp8 prepared.2.1)
    let out ← prepared.1.run_loop1 store counter inv
    ok (true, prepared.1, out)) = ok (runModel self store groups.val)
  by_cases hlt : prepared.2.2 < groups.val
  · have hlt' : counter < groups := by change counter.val < groups.val; omega
    simp only [hlt', if_true, runModel, hlt, prepared]
  · have heq : counter.val = groups.val := by omega
    have hn : groups.val / 2 = n := by omega
    have hlt' : ¬counter < groups := by change ¬counter.val < groups.val; omega
    rw [if_neg hlt', Msm8.batchInverse_refines]
    simp only [ofArray_toArray ofFp8_toFp8, bind_tc_ok]
    rw [execute_loop_refines prepared.1 store groups.val (Msm8.batchInverse prepared.2.1)
      counter n hgroups (heq.trans heven) (by omega) hbounds]
    simp only [bind_tc_ok, runModel, hlt, if_false, hn, prepared]

theorem run_refines (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups entries : Usize)
    (ha : 0 < self.a.val.length) (hb : self.a.val.length ≤ self.b.val.length)
    (ho : self.a.val.length ≤ self.out.val.length)
    (hg : groups.val = ((self.a.val.length - 1) / 16 + 1) * 2)
    (he : entries.val = groups.val * 8) (hsize : entries.val < 2 ^ 32)
    (hbound : ExecutionBounds (paddedAdds self groups entries) store groups.val) :
    self.run store = ok (runModel (paddedAdds self groups entries) store groups.val) := by
  rw [run_initializes self store groups entries ha hb ho hg he hsize]
  exact runBody_refines _ _ groups ((self.a.val.length - 1) / 16 + 1)
    (by omega) (by omega) hbound

theorem runModel_rejected (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups : ℕ) (hrejected : (runModel self store groups).1 = false) :
    (runModel self store groups).2.2 = store ∧
      let prepared := prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0
      (difference prepared.1 store prepared.2.2).is_zero_mask ≠ 0 := by
  by_cases h : (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups
  · simp only [runModel, h, if_true]
    exact ⟨True.intro, prepareFrom_rejected store groups self (Vector.replicate 4 Fp8.one) 0 (by omega)⟩
  · simp only [runModel, h, if_false, Bool.true_eq_false] at hrejected

theorem run_rejects_first (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups entries : Usize)
    (ha : 0 < self.a.val.length) (hb : self.a.val.length ≤ self.b.val.length)
    (ho : self.a.val.length ≤ self.out.val.length)
    (hg : groups.val = ((self.a.val.length - 1) / 16 + 1) * 2)
    (he : entries.val = groups.val * 8) (hsize : entries.val < 2 ^ 32)
    (hbound : ExecutionBounds (paddedAdds self groups entries) store groups.val)
    (hzero : (difference (paddedAdds self groups entries) store 0).is_zero_mask ≠ 0) :
    self.run store = ok (false, paddedAdds self groups entries, store) := by
  rw [run_refines self store groups entries ha hb ho hg he hsize hbound]
  have hpositive : 0 < groups.val := by omega
  obtain ⟨n, hn⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : groups.val ≠ 0)
  rw [hn]
  simp only [runModel, prepareFrom, prepareStep, hzero, if_false, Bool.false_eq_true,
    Nat.succ_pos, if_true]

theorem runModel_success_invariant (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups n : ℕ) (heven : groups = 2 * n) (hb : PreparationBounds self store groups)
    (a : Fin 8 → ℕ → ChainField)
    (hdiff : ∀ lane i, i < groups → (difference self store i).Holds lane (a lane i))
    (P : ℕ → msm8.store.PointStore → Prop) (hstart : P n store)
    (hstep : ∀ m current recovered, 2 * (m + 1) ≤ groups → P (m + 1) current →
      (∀ lane (j : Fin 2), recovered[j].Holds lane (a lane (2 * m + j.val))⁻¹) →
      P m (finishPair (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).1
        current (2 * m) recovered))
    (hsuccess : (runModel self store groups).1 = true) :
    P 0 (runModel self store groups).2.2 := by
  let prepared := prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0
  have hstop : ¬prepared.2.2 < groups := by
    intro h
    simp only [runModel, show (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from h,
      if_true, Bool.false_eq_true] at hsuccess
  have hcomplete : prepared.2.2 = groups := by
    have hr := (prepareFrom_range store groups self (Vector.replicate 4 Fp8.one) 0).2
    change prepared.2.2 ≤ 0 + groups at hr
    omega
  have hstate (lane : Fin 8) : ChainInvariant prepared.1 prepared.2.1 (a lane) groups lane := by
    have h := prepareFrom_chainInvariant store groups self (Vector.replicate 4 Fp8.one)
      0 groups (a lane) lane (by omega) hb (ChainInvariant.initial self (a lane) lane) (hdiff lane)
    change ChainInvariant prepared.1 prepared.2.1 (a lane) prepared.2.2 lane at h
    rw [hcomplete] at h
    exact h
  have hinv (lane : Fin 8) (k : Fin 4) :
      (Msm8.batchInverse prepared.2.1)[k].Holds lane (chainValues (a lane) (2 * n) k)⁻¹ := by
    rw [← heven]
    exact Msm8.batchInverse_correct prepared.2.1 (chainValues (a lane) groups) lane
      (hstate lane).product (chainValues_nonzero _ _ (hstate lane).nonzero) k
  have hfinal := executeFrom_invariant prepared.1 prepared.2.1 a groups hstate P hstep n store
    (Msm8.batchInverse prepared.2.1) (by omega) hstart hinv
  simpa only [runModel, show ¬(prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from hstop,
    if_false, show groups / 2 = n by omega] using hfinal

theorem run_equal_x_first (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups entries : Usize)
    (ha : 0 < self.a.val.length) (hb : self.a.val.length ≤ self.b.val.length)
    (ho : self.a.val.length ≤ self.out.val.length)
    (hg : groups.val = ((self.a.val.length - 1) / 16 + 1) * 2)
    (he : entries.val = groups.val * 8) (hsize : entries.val < 2 ^ 32)
    (hbound : ExecutionBounds (paddedAdds self groups entries) store groups.val)
    (lane : Fin 8)
    (hxa : Fp8Inv ((loadedCoordinate store (referencesAt (paddedAdds self groups entries).a.val 0).1 0).lane lane))
    (hxb : Fp8Inv ((loadedCoordinate store (referencesAt (paddedAdds self groups entries).b.val 0).1 0).lane lane))
    (heq : decode ((loadedCoordinate store (referencesAt (paddedAdds self groups entries).a.val 0).1 0).lane lane) =
      decode ((loadedCoordinate store (referencesAt (paddedAdds self groups entries).b.val 0).1 0).lane lane)) :
    self.run store = ok (false, paddedAdds self groups entries, store) :=
  run_rejects_first self store groups entries ha hb ho hg he hsize hbound
    (equal_x_zero_mask _ _ lane hxa hxb heq)

theorem storeLane_frame (store : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) (p : ℕ) (c : Fin 2) (hne : p ≠ indices[j]) :
    (pointRows (storeLane store indices xs ys j))[2 * p + c.val]! =
      (pointRows store)[2 * p + c.val]! := by
  have h0 : 2 * indices[j] ≠ 2 * p + c.val := by omega
  have h1 : 2 * indices[j] + 1 ≠ 2 * p + c.val := by omega
  simp only [pointRows_storeLane, getElem!_def, List.getElem?_set_ne h1, List.getElem?_set_ne h0]

theorem writeCoordinates_frame (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) (p : ℕ) (c : Fin 2) (hne : ∀j : Fin 8, p ≠ (pointIndices indices)[j]) :
    (pointRows (writeCoordinates store indices x y))[2 * p + c.val]! =
      (pointRows store)[2 * p + c.val]! := by
  unfold writeCoordinates
  generalize List.finRange 8 = lanes
  induction lanes generalizing store with
  | nil => rfl
  | cons j lanes ih =>
    rw [List.foldl_cons, ih]
    exact storeLane_frame _ _ _ _ _ _ _ (hne j)

section
attribute [local irreducible] writeCoordinates Msm8.affineAdd signedCoordinates

theorem finishPair_frame (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (p : ℕ) (c : Fin 2)
    (hne : ∀ (j : Fin 2) (lane : Fin 8),
      p ≠ (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane]) :
    (pointRows (finishPair self store g inv))[2 * p + c.val]! = (pointRows store)[2 * p + c.val]! := by
  let step := fun (current : msm8.store.PointStore) (j : Fin 2) =>
    let a := signedCoordinates store (referencesAt self.a.val (g + j.val))
    let b := signedCoordinates store (referencesAt self.b.val (g + j.val))
    let result := Msm8.affineAdd a.1 a.2 b.1 b.2 inv[j]
    writeCoordinates current (referencesAt self.out.val (g + j.val)).1 result.1 result.2
  have hs (current : msm8.store.PointStore) (j : Fin 2) :
      (pointRows (step current j))[2 * p + c.val]! = (pointRows current)[2 * p + c.val]! :=
    writeCoordinates_frame current _ _ _ p c (hne j)
  have hf (js : List (Fin 2)) (current : msm8.store.PointStore) :
      (pointRows (js.foldl step current))[2 * p + c.val]! = (pointRows current)[2 * p + c.val]! := by
    induction js generalizing current with
    | nil => rfl
    | cons j js ih => exact (ih (step current j)).trans (hs current j)
  exact hf (List.finRange 2) store

end

theorem loadedCoordinate_eq_of_rows (s t : msm8.store.PointStore) (indices : Array U32 8#usize)
    (c : ℕ) (h : ∀ lane : Fin 8,
      (pointRows s)[2 * (pointIndices indices)[lane] + c]! =
        (pointRows t)[2 * (pointIndices indices)[lane] + c]!) :
    loadedCoordinate s indices c = loadedCoordinate t indices c := by
  have heq : indexedRows (pointRows s) (pointIndices indices) c =
      indexedRows (pointRows t) (pointIndices indices) c := by
    apply Vector.ext
    intro i hi
    simp only [indexedRows, Vector.getElem_ofFn]
    exact h ⟨i, hi⟩
  simp only [loadedCoordinate, heq]

theorem finishPair_signedCoordinates_frame (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (refs : Array U32 8#usize × U8)
    (hne : ∀ (readLane : Fin 8) (j : Fin 2) (outLane : Fin 8),
      (pointIndices refs.1)[readLane] ≠ (pointIndices (referencesAt self.out.val (g + j.val)).1)[outLane]) :
    signedCoordinates (finishPair self store g inv) refs = signedCoordinates store refs := by
  have hrows (c : Fin 2) := loadedCoordinate_eq_of_rows (finishPair self store g inv) store refs.1 c.val
    (fun lane => finishPair_frame self store g inv _ c (hne lane))
  have hx : loadedCoordinate (finishPair self store g inv) refs.1 0 = loadedCoordinate store refs.1 0 := hrows 0
  have hy : loadedCoordinate (finishPair self store g inv) refs.1 1 = loadedCoordinate store refs.1 1 := hrows 1
  simp only [signedCoordinates, hx, hy]

theorem writeCoordinates_len (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) : (writeCoordinates store indices x y).len = store.len :=
  storeLane_fold_len store _ _ _ _

theorem writeCoordinates_rows (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) :
    pointRows (writeCoordinates store indices x y) = storeRows (pointRows store) (pointIndices indices)
      (transpose8 (ofArray id (toFp8 x))) (transpose8 (ofArray id (toFp8 y))) :=
  storeLane_fold_rows store _ _ _ _

theorem storeLane_row_self (store : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) (c : Fin 2)
    (hb : 2 * indices[j] + 1 < store.rows.val.length) :
    (pointRows (storeLane store indices xs ys j))[2 * indices[j] + c.val]! =
      (if c.val = 0 then xs[j] else ys[j]) := by
  have hx : 2 * indices[j] < (pointRows store).length := by simp only [pointRows, List.length_map]; omega
  have hy : 2 * indices[j] + 1 < ((pointRows store).set (2 * indices[j]) xs[j]).length := by
    simp only [List.length_set, pointRows, List.length_map]; exact hb
  fin_cases c
  · simp only [pointRows_storeLane, Nat.add_zero, if_true]
    rw [List.getElem!_set_ne _ _ _ _ (by omega), List.getElem!_set _ _ _ hx]
  · simp only [pointRows_storeLane, show ¬(1 : ℕ) = 0 by decide, if_false]
    exact List.getElem!_set _ _ _ hy

theorem storeLane_fold_value (store : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (lanes : List (Fin 8)) (p : ℕ) (c : Fin 2) (value : M512)
    (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀j : Fin 8, indices[j] = p → (if c.val = 0 then xs[j] else ys[j]) = value)
    (hstart : (pointRows store)[2 * p + c.val]! = value ∨ ∃j ∈ lanes, indices[j] = p) :
    (pointRows (lanes.foldl (fun current j => storeLane current indices xs ys j) store))[2 * p + c.val]! = value := by
  induction lanes generalizing store with
  | nil =>
    rcases hstart with h|⟨j, hj, _⟩
    · exact h
    · simp only [List.not_mem_nil] at hj
  | cons j lanes ih =>
    simp only [List.foldl_cons]
    apply ih _ (by simpa only [storeLane_length] using hb) hsame
    by_cases hj : indices[j] = p
    · left
      have hv := storeLane_row_self store indices xs ys j c (by simpa only [hj] using hb)
      rw [hj, hsame j hj] at hv
      exact hv
    · rcases hstart with h|⟨k, hk, hkp⟩
      · left
        exact (storeLane_frame store indices xs ys j p c (Ne.symm hj)).trans h
      · right
        refine ⟨k, ?_, hkp⟩
        simp only [List.mem_cons] at hk
        rcases hk with rfl|hk
        · exact False.elim (hj hkp)
        · exact hk

theorem writeCoordinates_value (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) (p : ℕ) (c : Fin 2) (value : M512)
    (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀j : Fin 8, (pointIndices indices)[j] = p →
      (if c.val = 0 then (transpose8 (ofArray id (toFp8 x)))[j]
       else (transpose8 (ofArray id (toFp8 y)))[j]) = value)
    (hwritten : ∃j : Fin 8, (pointIndices indices)[j] = p) :
    (pointRows (writeCoordinates store indices x y))[2 * p + c.val]! = value := by
  apply storeLane_fold_value store _ _ _ _ p c value hb hsame
  right
  obtain ⟨j, hj⟩ := hwritten
  exact ⟨j, List.mem_finRange j, hj⟩

def pairResult (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (j : Fin 2) : Fp8 × Fp8 :=
  let a := signedCoordinates store (referencesAt self.a.val (g + j.val))
  let b := signedCoordinates store (referencesAt self.b.val (g + j.val))
  Msm8.affineAdd a.1 a.2 b.1 b.2 inv[j]

section
attribute [local irreducible] writeCoordinates Msm8.affineAdd signedCoordinates pairResult

theorem finishPair_eq (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) :
    finishPair self store g inv =
      writeCoordinates
        (writeCoordinates store (referencesAt self.out.val g).1
          (pairResult self store g inv 0).1 (pairResult self store g inv 0).2)
        (referencesAt self.out.val (g + 1)).1
        (pairResult self store g inv 1).1 (pairResult self store g inv 1).2 := by
  simp only [finishPair, pairResult, show List.finRange 2 = [0, 1] from rfl,
    List.foldl_cons, List.foldl_nil, Fin.val_zero, Fin.val_one, Nat.add_zero]

theorem finishPair_len (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) : (finishPair self store g inv).len = store.len := by
  rw [finishPair_eq, writeCoordinates_len, writeCoordinates_len]

theorem finishPair_value (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (p : ℕ) (c : Fin 2) (value : M512)
    (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀ (j : Fin 2) (lane : Fin 8),
      (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane] = p →
      (if c.val = 0 then (transpose8 (ofArray id (toFp8 (pairResult self store g inv j).1)))[lane]
       else (transpose8 (ofArray id (toFp8 (pairResult self store g inv j).2)))[lane]) = value)
    (hwritten : ∃ (j : Fin 2) (lane : Fin 8),
      (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane] = p) :
    (pointRows (finishPair self store g inv))[2 * p + c.val]! = value := by
  rw [finishPair_eq]
  by_cases hlast : ∃ lane : Fin 8, (pointIndices (referencesAt self.out.val (g + 1)).1)[lane] = p
  · exact writeCoordinates_value _ _ _ _ p c value
      (by simpa only [writeCoordinates_length] using hb) (hsame 1) hlast
  · have hfirst : ∃ lane : Fin 8, (pointIndices (referencesAt self.out.val g).1)[lane] = p := by
      obtain ⟨j, lane, hj⟩ := hwritten
      fin_cases j
      · exact ⟨lane, hj⟩
      · exact False.elim (hlast ⟨lane, hj⟩)
    rw [writeCoordinates_frame _ _ _ _ p c
      (fun lane h => hlast ⟨lane, h.symm⟩)]
    exact writeCoordinates_value _ _ _ _ p c value hb (hsame 0) hfirst

end

end LeanBlsSimd.BatchedRefines
