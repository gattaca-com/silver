import LeanBlsSimd.Msm8.StoreFlat

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd

def convertedRows (n : ℕ) (point : ℕ → Limbs × Limbs) : List Limbs :=
  (List.range n).flatMap fun j => [(point j).1, (point j).2]

@[simp] theorem convertedRows_length (n : ℕ) (point : ℕ → Limbs × Limbs) :
    (convertedRows n point).length = 2 * n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [convertedRows, List.range_succ, List.flatMap_append, List.flatMap_cons,
      List.flatMap_nil, List.append_nil, List.length_append, List.length_cons, List.length_nil]
    change (convertedRows n point).length + (1 + (1 + 0)) = _
    rw [ih]
    omega

theorem writePoint_boundary (before tail : List Limbs) (index : ℕ) (point : Limbs × Limbs)
    (hp : before.length = 2 * index) (ht : 2 ≤ tail.length) :
    writePoint (before ++ tail) index point = before ++ [point.1, point.2] ++ tail.drop 2 := by
  cases tail with
  | nil => simp at ht
  | cons x tail =>
    cases tail with
    | nil => simp at ht
    | cons y tail =>
      simp [writePoint, List.set_append_right, hp,
        show 2 * index + 1 - 2 * index = 1 by omega]

theorem writePoints_append (rows : List Limbs) (base n : ℕ) (point : ℕ → Limbs × Limbs)
    (hcap : 2 * (base + n) ≤ rows.length) :
    (List.range n).foldl (fun rows j => writePoint rows (base + j) (point j)) rows =
      rows.take (2 * base) ++ convertedRows n point ++ rows.drop (2 * (base + n)) := by
  induction n with
  | zero => simp [convertedRows]
  | succ n ih =>
    have hcap' : 2 * (base + n) ≤ rows.length := by omega
    rw [List.range_succ, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    rw [ih hcap']
    have hp : (rows.take (2 * base) ++ convertedRows n point).length = 2 * (base + n) := by
      simp only [List.length_append, List.length_take, convertedRows_length]
      rw [Nat.min_eq_left (by omega)]
      omega
    have ht : 2 ≤ (rows.drop (2 * (base + n))).length := by
      simp only [List.length_drop]
      omega
    rw [writePoint_boundary _ _ _ _ hp ht, List.drop_drop]
    have hc : convertedRows (n + 1) point = convertedRows n point ++ [(point n).1, (point n).2] := by
      simp [convertedRows, List.range_succ]
    rw [hc]
    simp only [List.append_assoc]
    congr 2

theorem push_blst_append_refines (s : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2) :
    ∃ out, msm8.store.PointStore.push_blst s points negated endomorphism = ok out ∧
      pointRows out = (pointRows s).take (2 * s.len.val) ++
        convertedRows points.val.length (fun j => convertedPoint (blstPointWords points)[j]!
          negated.val[j]! endomorphism) ++
        (pointRows s).drop (2 * (s.len.val + points.val.length)) ∧
      out.len.val = s.len.val + points.val.length ∧ out.rows.val.length = s.rows.val.length := by
  obtain ⟨out, hout, hrows, hlen, hsize⟩ := push_blst_flat_refines s points negated endomorphism hn h31 hcap
  refine ⟨out, hout, ?_, hlen, hsize⟩
  rw [hrows]
  simp only [pushFlatModel, blstPointWords_length, Nat.sub_zero, Nat.zero_add]
  apply writePoints_append
  simp only [pointRows_length]
  omega

end LeanBlsSimd
