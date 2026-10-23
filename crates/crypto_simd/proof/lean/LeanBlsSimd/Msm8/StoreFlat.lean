import LeanBlsSimd.Msm8.StoreField

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd

theorem getElem_ofFn_limbs (f : Fin 8 → Limbs) (j : ℕ) (hj : j < 8) :
    (show Vector M512 8 from Vector.ofFn f)[j] = f ⟨j, hj⟩ := Vector.getElem_ofFn hj

def writePoint (rows : List Limbs) (index : ℕ) (point : Limbs × Limbs) : List Limbs :=
  (rows.set (2 * index) point.1).set (2 * index + 1) point.2

@[simp] theorem writePoint_twice (rows : List Limbs) (index : ℕ) (a b : Limbs × Limbs) :
    writePoint (writePoint rows index a) index b = writePoint rows index b :=
  repeated_write_last_wins rows index a.1 a.2 b.1 b.2

theorem padded_write_fold (rows : List Limbs) (base count : ℕ) (point : ℕ → Limbs × Limbs)
    (hc : 0 < count) (hc8 : count ≤ 8) :
    (List.finRange 8).foldl (fun rows l => writePoint rows (base + min l.val (count - 1))
      (point (min l.val (count - 1)))) rows =
      (List.range count).foldl (fun rows j => writePoint rows (base + j) (point j)) rows := by
  have hf : List.finRange 8 = [0, 1, 2, 3, 4, 5, 6, 7] := by decide
  rw [hf]
  interval_cases count <;>
    norm_num [List.foldl_cons, List.foldl_nil, List.range_succ, List.foldl_append, writePoint_twice]

theorem storeRows_ofFn (rows : List Limbs) (indices : Fin 8 → ℕ) (point : Fin 8 → Limbs × Limbs) :
    storeRows rows (Vector.ofFn indices) (Vector.ofFn fun l => (point l).1)
      (Vector.ofFn fun l => (point l).2) =
      (List.finRange 8).foldl (fun rows l => writePoint rows (indices l) (point l)) rows := by
  unfold storeRows
  apply List.foldl_ext
  intro r l hl
  have hi : (Vector.ofFn indices)[l] = indices l := Vector.getElem_ofFn l.isLt
  have hx : (show Vector M512 8 from Vector.ofFn fun l => (point l).1)[l] = (point l).1 :=
    Vector.getElem_ofFn l.isLt
  have hy : (show Vector M512 8 from Vector.ofFn fun l => (point l).2)[l] = (point l).2 :=
    Vector.getElem_ofFn l.isLt
  change (r.set (2 * (Vector.ofFn indices)[l]) _).set (2 * (Vector.ofFn indices)[l] + 1) _ = _
  rw [hi]
  exact congrArg₂ (fun x y => (r.set (2 * indices l) x).set (2 * indices l + 1) y) hx hy

theorem storeRows_padded (rows : List Limbs) (base count : ℕ) (point : ℕ → Limbs × Limbs)
    (hc : 0 < count) (hc8 : count ≤ 8) :
    storeRows rows (Vector.ofFn fun l : Fin 8 => base + min l.val (count - 1))
      (Vector.ofFn fun l : Fin 8 => (point (min l.val (count - 1))).1)
      (Vector.ofFn fun l : Fin 8 => (point (min l.val (count - 1))).2) =
      (List.range count).foldl (fun rows j => writePoint rows (base + j) (point j)) rows := by
  rw [storeRows_ofFn]
  exact padded_write_fold rows base count point hc hc8

theorem transpose8_fp8_lane (x : Fp8) (l : Fin 8) : (transpose8 x.limbs)[l] = x.lane l := by
  ext j hj
  simp [transpose8, Fp8.lane, LIMBS]

theorem store_convertedBatch (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (endomorphism : Bool) (rows : List Limbs)
    (hc : 0 < count) (hc8 : count ≤ 8) :
    let gathered := gatherBatch points negated base offset count emptyGathered
    let converted := convertedBatch gathered fromBlstFactor endomorphismFactor endomorphism
    storeRows rows gathered.indices (transpose8 converted.1.limbs) (transpose8 converted.2.limbs) =
      (List.range count).foldl (fun rows j => writePoint rows (base + j)
        (convertedPoint points[offset + j]! negated[offset + j]! endomorphism)) rows := by
  let gathered := gatherBatch points negated base offset count emptyGathered
  let converted := convertedBatch gathered fromBlstFactor endomorphismFactor endomorphism
  have hi : gathered.indices = Vector.ofFn (fun l : Fin 8 => base + min l.val (count - 1)) := by
    rw [gatherBatch_indices]
    ext j hj
    simp only [Vector.getElem_ofFn, batchSource]
    omega
  have hx : transpose8 converted.1.limbs = Vector.ofFn (fun l : Fin 8 =>
      (convertedPoint points[batchSource offset count l]! negated[batchSource offset count l]! endomorphism).1) := by
    apply Vector.ext
    intro j hj
    have h := congrArg Prod.fst (convertedBatch_lane points negated base offset count endomorphism ⟨j, hj⟩)
    conv_rhs => erw [Vector.getElem_ofFn]
    simpa only [← transpose8_fp8_lane, Fin.getElem_fin] using h
  have hy : transpose8 converted.2.limbs = Vector.ofFn (fun l : Fin 8 =>
      (convertedPoint points[batchSource offset count l]! negated[batchSource offset count l]! endomorphism).2) := by
    apply Vector.ext
    intro j hj
    have h := congrArg Prod.snd (convertedBatch_lane points negated base offset count endomorphism ⟨j, hj⟩)
    conv_rhs => erw [Vector.getElem_ofFn]
    simpa only [← transpose8_fp8_lane, Fin.getElem_fin] using h
  change storeRows rows gathered.indices (transpose8 converted.1.limbs) (transpose8 converted.2.limbs) = _
  rw [hi, hx, hy]
  exact storeRows_padded rows base count
    (fun j => convertedPoint points[offset + j]! negated[offset + j]! endomorphism) hc hc8

end LeanBlsSimd

namespace LeanBlsSimd

def pushFlatModel (points : List (Vector UInt64 6 × Vector UInt64 6)) (negated : List Bool)
    (endomorphism : Bool) (rows : List Limbs) (base offset : ℕ) : List Limbs :=
  (List.range (points.length - offset)).foldl (fun rows j => writePoint rows (base + j)
    (convertedPoint points[offset + j]! negated[offset + j]! endomorphism)) rows

theorem pushRowsModel_flat (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (endomorphism : Bool) (rows : List Limbs) (base offset : ℕ) :
    pushRowsModel points negated endomorphism fromBlstFactor endomorphismFactor rows base offset =
      pushFlatModel points negated endomorphism rows base offset := by
  induction hd : points.length - offset using Nat.strong_induction_on generalizing rows base offset with
  | h d ih =>
    by_cases hlt : offset < points.length
    · let count := min 8 (points.length - offset)
      have hc : 0 < count := by dsimp [count]; omega
      have hc8 : count ≤ 8 := Nat.min_le_left _ _
      have hcle : count ≤ points.length - offset := Nat.min_le_right _ _
      have hdlt : points.length - (offset + count) < d := by omega
      rw [pushRowsModel, if_pos hlt]
      change pushRowsModel points negated endomorphism fromBlstFactor endomorphismFactor
        (storeRows _ _ _ _) (base + count) (offset + count) = _
      rw [store_convertedBatch points negated base offset count endomorphism rows hc hc8]
      rw [ih _ hdlt _ (base + count) (offset + count) rfl]
      unfold pushFlatModel
      conv_rhs => rw [show points.length - offset = count + (points.length - (offset + count)) by omega]
      rw [List.range_add, List.foldl_append, List.foldl_map]
      simp only [Nat.add_assoc]
    · rw [pushRowsModel, if_neg hlt]
      have hz : points.length - offset = 0 := by omega
      simp only [pushFlatModel, hz, List.range_zero, List.foldl_nil]

theorem push_blst_flat_refines (s : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2) :
    ∃ out, msm8.store.PointStore.push_blst s points negated endomorphism = ok out ∧
      pointRows out = pushFlatModel (blstPointWords points) negated.val endomorphism
        (pointRows s) s.len.val 0 ∧
      out.len.val = s.len.val + points.val.length ∧ out.rows.val.length = s.rows.val.length := by
  obtain ⟨out, hout, hrows, hlen, hsize⟩ := push_blst_refines s points negated endomorphism hn h31 hcap
  exact ⟨out, hout, hrows.trans (pushRowsModel_flat _ _ _ _ _ _), hlen, hsize⟩

end LeanBlsSimd

namespace LeanBlsSimd
open EthLib.Cryptography.Bls

def PointRowsHold (rows : Limbs × Limbs) (x y : ZMod Fp.modulus) : Prop :=
  Fp8Inv rows.1 ∧ decode rows.1 = x ∧ Fp8Inv rows.2 ∧ decode rows.2 = y

theorem convertedPoint_holds (point : Vector UInt64 6 × Vector UInt64 6)
    (negated endomorphism : Bool) (x y : ZMod Fp.modulus)
    (hx : val64 point.1 = (x * 2 ^ 384).val) (hy : val64 point.2 = (y * 2 ^ 384).val) :
    PointRowsHold (convertedPoint point negated endomorphism)
      (if endomorphism then x * beta else x) (if negated then -y else y) := by
  have h := convertedBatch_holds [point] [negated] 0 0 1 endomorphism 0 x y
    (by simpa [batchSource] using hx) (by simpa [batchSource] using hy)
  have hl := convertedBatch_lane [point] [negated] 0 0 1 endomorphism 0
  simp only [batchSource, Fin.val_zero, Nat.sub_self, Nat.min_zero, Nat.add_zero,
    List.getElem!_cons_zero] at h hl
  obtain ⟨hxh, hyh⟩ := h
  have hxl := congrArg Prod.fst hl
  have hyl := congrArg Prod.snd hl
  exact ⟨hxl ▸ hxh.inv, hxl ▸ hxh.eq, hyl ▸ hyh.inv, hyl ▸ hyh.eq⟩

end LeanBlsSimd
