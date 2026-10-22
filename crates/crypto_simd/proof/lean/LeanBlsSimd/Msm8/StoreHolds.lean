import LeanBlsSimd.Msm8.StoreAppend

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd
open EthCryptographySpecs.Bls

def readPoint (rows : List Limbs) (index : ℕ) : Limbs × Limbs :=
  (rows[2 * index]!, rows[2 * index + 1]!)

@[simp] theorem writePoint_length (rows : List Limbs) (i : ℕ) (point : Limbs × Limbs) :
    (writePoint rows i point).length = rows.length := by simp [writePoint]

theorem readPoint_writePoint_self (rows : List Limbs) (i : ℕ) (point : Limbs × Limbs)
    (hi : 2 * i + 1 < rows.length) : readPoint (writePoint rows i point) i = point := by
  simp only [readPoint, writePoint, List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_set_ne (by omega), List.getElem?_set_self (by omega),
    List.getElem?_set_self (by simp; omega)]
  rfl

theorem readPoint_writePoint_other (rows : List Limbs) (i j : ℕ) (point : Limbs × Limbs)
    (hij : i ≠ j) : readPoint (writePoint rows i point) j = readPoint rows j := by
  simp only [readPoint, writePoint, List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_set_ne (by omega), List.getElem?_set_ne (by omega),
    List.getElem?_set_ne (by omega), List.getElem?_set_ne (by omega)]

theorem writePoints_length (rows : List Limbs) (base n : ℕ) (point : ℕ → Limbs × Limbs) :
    ((List.range n).foldl (fun rows j => writePoint rows (base + j) (point j)) rows).length = rows.length := by
  induction n with
  | zero => rfl
  | succ n ih => simpa only [List.range_succ, List.foldl_append, List.foldl_cons,
      List.foldl_nil, writePoint_length] using ih

theorem writePoints_read (rows : List Limbs) (base n : ℕ) (point : ℕ → Limbs × Limbs)
    (hcap : 2 * (base + n) ≤ rows.length) (j : ℕ) (hj : j < n) :
    readPoint ((List.range n).foldl (fun rows j => writePoint rows (base + j) (point j)) rows)
      (base + j) = point j := by
  induction n with
  | zero => omega
  | succ n ih =>
    rw [List.range_succ, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    by_cases heq : j = n
    · subst j
      apply readPoint_writePoint_self
      rw [writePoints_length]
      omega
    · rw [readPoint_writePoint_other _ _ _ _ (by omega)]
      exact ih (by omega) (by omega)

theorem push_blst_holds (s : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2)
    (x y : ℕ → ZMod Fp.modulus)
    (hx : ∀ j, j < points.val.length → val64 (blstPointWords points)[j]!.1 = (x j * 2 ^ 384).val)
    (hy : ∀ j, j < points.val.length → val64 (blstPointWords points)[j]!.2 = (y j * 2 ^ 384).val) :
    ∃ out, msm8.store.PointStore.push_blst s points negated endomorphism = ok out ∧
      out.len.val = s.len.val + points.val.length ∧
      ∀ j, j < points.val.length → PointRowsHold (readPoint (pointRows out) (s.len.val + j))
        (if endomorphism then x j * beta else x j) (if negated.val[j]! then -y j else y j) := by
  obtain ⟨out, hout, hrows, hlen, _⟩ := push_blst_flat_refines s points negated endomorphism hn h31 hcap
  refine ⟨out, hout, hlen, ?_⟩
  intro j hj
  rw [hrows]
  simp only [pushFlatModel, blstPointWords_length, Nat.sub_zero, Nat.zero_add]
  rw [writePoints_read _ _ _ _ (by simp only [pointRows_length]; omega) j hj]
  exact convertedPoint_holds _ _ _ _ _ (hx j hj) (hy j hj)

end LeanBlsSimd
