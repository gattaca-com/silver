import LeanBlsSimd.Proofs.Limbs

/-!
# The vector layer: lanes, mask bits, blends, `load` and `store`

Lane `l` of each `_mm512_*` intrinsic is its lane function on lane `l` (`getElem_*`). Bit `l` of
`_mm512_cmpeq_epi64_mask` is the equality of lane `l` (`testBit_cmpeq_epi64_mask`); the blend
takes its second vector where the bit is set (`getElem_mask_blend_epi64`); `_mm512_set_epi64`
puts its last argument in lane 0 (`getElem_set_epi64`). `Fp8.lane_load` and `Fp8.getElem_store`
give `load` and `store` the lane order of `Fp8.lane`.
-/

namespace LeanBlsSimd

/-- Lane `l` of a vector of `__m512i`; `Fp8.lane` is `laneOf` of the limbs. -/
def laneOf {n : ℕ} (v : Vector M512 n) (l : Fin 8) : Vector UInt64 n := v.map (·[l])

theorem Fp8.lane_eq (x : Fp8) (l : Fin 8) : x.lane l = laneOf x.limbs l := rfl

@[simp] theorem getElem_laneOf {n : ℕ} (v : Vector M512 n) (l : Fin 8) (j : ℕ) (hj : j < n) :
    (laneOf v l)[j] = v[j][l] := by simp [laneOf]

theorem laneOf_set {n : ℕ} (v : Vector M512 n) (j : ℕ) (hj : j < n) (x : M512) (l : Fin 8) :
    laneOf (v.set j x hj) l = (laneOf v l).set j x[l] hj := by
  ext i hi
  simp [laneOf, Vector.getElem_set]

@[simp] theorem getElem_madd52lo_epu64 (a b c : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_madd52lo_epu64 a b c)[l] = madd52lo a[l] b[l] c[l] := by
  simp [_mm512_madd52lo_epu64]

@[simp] theorem getElem_add_epi64 (a b : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_add_epi64 a b)[l] = a[l] + b[l] := by simp [_mm512_add_epi64]

@[simp] theorem getElem_sub_epi64 (a b : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_sub_epi64 a b)[l] = a[l] - b[l] := by simp [_mm512_sub_epi64]

@[simp] theorem getElem_and_si512 (a b : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_and_si512 a b)[l] = a[l] &&& b[l] := by simp [_mm512_and_si512]

@[simp] theorem getElem_srli_epi64 (n : ℕ) (a : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_srli_epi64 n a)[l] = srli n a[l] := by simp [_mm512_srli_epi64]

@[simp] theorem getElem_srai_epi64 (n : ℕ) (a : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_srai_epi64 n a)[l] = srai n a[l] := by simp [_mm512_srai_epi64]

@[simp] theorem getElem_set1_epi64 (a : Int64) (l : ℕ) (hl : l < 8) :
    (_mm512_set1_epi64 a)[l] = a.toUInt64 := by simp [_mm512_set1_epi64]

@[simp] theorem getElem_setzero_si512 (l : ℕ) (hl : l < 8) : _mm512_setzero_si512[l] = 0 := by
  simp [_mm512_setzero_si512]

@[simp] theorem getElem_mask_blend_epi64 (k : Mmask8) (a b : M512) (l : ℕ) (hl : l < 8) :
    (_mm512_mask_blend_epi64 k a b)[l] = if k.toNat.testBit l then b[l] else a[l] := by
  simp [_mm512_mask_blend_epi64]

theorem getElem_set_epi64 (e7 e6 e5 e4 e3 e2 e1 e0 : Int64) (l : ℕ) (hl : l < 8) :
    (_mm512_set_epi64 e7 e6 e5 e4 e3 e2 e1 e0)[l] = #v[e0, e1, e2, e3, e4, e5, e6, e7][l].toUInt64 := by
  interval_cases l <;> simp [_mm512_set_epi64]

theorem testBit_mask8 : ∀ (b0 b1 b2 b3 b4 b5 b6 b7 : Bool) (l : Fin 8),
    (UInt8.ofNat ((List.finRange 8).map fun i =>
      if #v[b0, b1, b2, b3, b4, b5, b6, b7][i] then 2 ^ i.val else 0).sum).toNat.testBit l =
      #v[b0, b1, b2, b3, b4, b5, b6, b7][l] := by
  decide

theorem testBit_cmpeq_epi64_mask (a b : M512) (l : Fin 8) :
    (_mm512_cmpeq_epi64_mask a b).toNat.testBit l = decide (a[l] = b[l]) := by
  have h := testBit_mask8 (decide (a[0] = b[0])) (decide (a[1] = b[1])) (decide (a[2] = b[2]))
    (decide (a[3] = b[3])) (decide (a[4] = b[4])) (decide (a[5] = b[5])) (decide (a[6] = b[6]))
    (decide (a[7] = b[7])) l
  have hv : #v[decide (a[0] = b[0]), decide (a[1] = b[1]), decide (a[2] = b[2]),
      decide (a[3] = b[3]), decide (a[4] = b[4]), decide (a[5] = b[5]), decide (a[6] = b[6]),
      decide (a[7] = b[7])] = .ofFn fun i : Fin 8 => decide (a[i] = b[i]) := by
    ext i hi
    interval_cases i <;> rfl
  rw [hv] at h
  simpa [_mm512_cmpeq_epi64_mask] using h

theorem foldl_band {α : Type} (p : α → Bool) :
    ∀ (b : Bool) (L : List α), L.foldl (fun b j => b && p j) b = (b && L.all p)
  | b, [] => by simp
  | b, j :: L => by rw [List.foldl_cons, foldl_band p _ L, List.all_cons, Bool.and_assoc]

/-- Bit `l` of `eq_mask`'s and `is_zero_mask`'s fold: all limbs of lane `l` compare equal. -/
theorem testBit_foldl_cmpeq (u w : Fin LIMBS → M512) (l : Fin 8) :
    ((List.finRange LIMBS).foldl (init := (0xff : Mmask8)) fun k j =>
        k &&& _mm512_cmpeq_epi64_mask (u j) (w j)).toNat.testBit l =
      decide (∀ j, (u j)[l] = (w j)[l]) := by
  rw [← List.foldl_hom (fun k : Mmask8 => k.toNat.testBit l)
    (g₂ := fun b j => b && decide ((u j)[l] = (w j)[l])) fun k j => by
      simp [UInt8.toNat_and, Nat.testBit_and, testBit_cmpeq_epi64_mask]]
  have h0 : (0xff : Mmask8).toNat.testBit l = true := by fin_cases l <;> decide
  rw [h0, foldl_band, Bool.true_and]
  rw [Bool.eq_iff_iff]
  simp only [List.all_eq_true, List.mem_finRange, true_implies, decide_eq_true_eq]

namespace Lane

/-- Lane `l` of `Simd.sub_limbs`. -/
def sub_limbs (a b : Limbs) : Limbs × UInt64 :=
  let mask := splat (.ofNat MASK52)
  (List.finRange LIMBS).foldl (init := (.replicate _ zero, zero)) fun (d, borrow) (j : Fin LIMBS) =>
    let s := a[j] - b[j] + borrow
    let borrow := srai 63 s
    (d.set j (s &&& mask), borrow)

/-- Lane `l` of `Simd.add_limbs`, with the carry out of the top limb, which `add_limbs` drops. -/
def add_limbs (a b : Limbs) : Limbs × UInt64 :=
  let mask := splat (.ofNat MASK52)
  (List.finRange LIMBS).foldl (init := (.replicate _ zero, zero)) fun (s, carry) (j : Fin LIMBS) =>
    let t := a[j] + b[j] + carry
    let carry := srli 52 t
    (s.set j (t &&& mask), carry)

end Lane

namespace Simd

@[simp] theorem getElem_splat (x : UInt64) (l : ℕ) (hl : l < 8) : (splat x)[l] = x := by
  simp [splat]

@[simp] theorem getElem_zero (l : ℕ) (hl : l < 8) : zero[l] = 0 := by simp [zero]

theorem laneOf_splat_limbs (t : Limbs) (l : Fin 8) : laneOf (splat_limbs t) l = t := by
  ext j hj
  simp [splat_limbs]

theorem laneOf_blend (k : Mmask8) (a b : Vector M512 LIMBS) (l : Fin 8) :
    laneOf (blend k a b) l = if k.toNat.testBit l then laneOf b l else laneOf a l := by
  ext j hj
  simp only [getElem_laneOf, blend, Vector.getElem_ofFn, Fin.getElem_fin, getElem_mask_blend_epi64]
  split_ifs <;> simp

theorem testBit_borrowed (borrow : M512) (l : Fin 8) :
    (borrowed borrow).toNat.testBit l = decide (borrow[l] = 0xffffffffffffffff) := by
  simp [borrowed, testBit_cmpeq_epi64_mask]

theorem laneOf_replicate_zero (l : Fin 8) :
    laneOf (Vector.replicate LIMBS zero) l = Vector.replicate LIMBS Lane.zero := by
  ext j hj
  simp [laneOf, Lane.zero]

theorem sub_limbs_lane (a b : Vector M512 LIMBS) (l : Fin 8) :
    (laneOf (sub_limbs a b).1 l, (sub_limbs a b).2[l]) = Lane.sub_limbs (laneOf a l) (laneOf b l) := by
  simp only [sub_limbs, Lane.sub_limbs]
  rw [← laneOf_replicate_zero l, show Lane.zero = zero[l] by simp [Lane.zero]]
  exact (List.foldl_hom (fun st : Vector M512 LIMBS × M512 => (laneOf st.1 l, st.2[l]))
    (init := (.replicate _ zero, zero)) fun ⟨d, borrow⟩ j => by simp [laneOf_set, Lane.splat]).symm

theorem add_limbs_lane (a b : Vector M512 LIMBS) (l : Fin 8) :
    laneOf (add_limbs a b) l = (Lane.add_limbs (laneOf a l) (laneOf b l)).1 := by
  simp only [add_limbs, Lane.add_limbs]
  rw [← laneOf_replicate_zero l, show Lane.zero = zero[l] by simp [Lane.zero]]
  exact congrArg Prod.fst
    (List.foldl_hom (fun st : Vector M512 LIMBS × M512 => (laneOf st.1 l, st.2[l]))
      (init := (.replicate _ zero, zero)) fun ⟨d, carry⟩ j => by simp [laneOf_set, Lane.splat]).symm

end Simd

namespace Fp8

theorem lane_load (values : Vector Limbs 8) (l : Fin 8) : (load values).lane l = values[l] := by
  ext j hj
  simp only [lane, load, Vector.getElem_map, Vector.getElem_ofFn, Fin.getElem_fin,
    getElem_set_epi64]
  fin_cases l <;> simp

theorem getElem_store_foldl_inner (v : Vector UInt64 8) (j : ℕ) (hj : j < LIMBS) (l : Fin 8) :
    ∀ (ls : List (Fin 8)) (out : Vector Limbs 8), ls.Nodup →
      (ls.foldl (fun out (lane : Fin 8) => out.set lane (out[lane].set j v[lane])) out)[l] =
        if l ∈ ls then out[l].set j v[l] else out[l]
  | [], out, _ => by simp
  | i :: ls, out, hnd => by
    rw [List.foldl_cons, getElem_store_foldl_inner v j hj l ls _ (List.nodup_cons.mp hnd).2]
    have hi := (List.nodup_cons.mp hnd).1
    by_cases hl : l ∈ ls
    · have : i ≠ l := fun h => hi (h ▸ hl)
      simp [hl, Fin.val_ne_of_ne this]
    · by_cases hil : i = l
      · subst hil; simp [hl]
      · simp [hl, Fin.val_ne_of_ne hil, Ne.symm hil]

theorem getElem_store (x : Fp8) (l : Fin 8) : x.store[l] = x.lane l := by
  have outer : ∀ (js : List (Fin LIMBS)) (out : Vector Limbs 8) (j' : ℕ) (hj' : j' < LIMBS),
      (js.foldl (fun out (j : Fin LIMBS) =>
        (List.finRange 8).foldl (fun out (lane : Fin 8) =>
          out.set lane (out[lane].set j (Simd.lanes x.limbs[j])[lane])) out) out)[l][j'] =
        if j' ∈ js.map (·.val) then x.limbs[j'][l] else out[l][j'] := by
    intro js
    induction js with
    | nil => simp
    | cons j js ih =>
      intro out j' hj'
      rw [List.foldl_cons, ih]
      rw [getElem_store_foldl_inner _ _ j.isLt l _ _ (List.nodup_finRange 8)]
      by_cases h : j' ∈ js.map (·.val)
      · simp [h]
      · by_cases hjj : j.val = j'
        · subst hjj; simp [Simd.lanes]
        · simp [h, hjj, Ne.symm hjj]
  ext j' hj'
  rw [store, outer]
  simp [lane, hj']

end Fp8

end LeanBlsSimd
