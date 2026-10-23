import LeanBlsSimd.Msm8.InputGroup
import LeanBlsSimd.Msm8.Prepare
import LeanBlsSimd.Msm8.SignedDigits

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthLib.Cryptography Bls
local instance splitGroupAffineInhabited0 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem digit_wordsValue_eq_limbs (xs : List U64) : SignedDigits.wordsValue xs = Kzg.limbs xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp only [SignedDigits.wordsValue, Kzg.limbs, List.foldr_cons] at *; rw [ih]

theorem digit_value_eq_limbs (words : ScalarWords) : SignedDigits.value words = Kzg.limbs words.val :=
  digit_wordsValue_eq_limbs words.val

theorem SplitInv.get {n : ℕ} {first second : Fin n → msm8.glv.Half}
    {halves : alloc.vec.Vec ScalarWords} {fs ss : alloc.vec.Vec Bool}
    (h : SplitInv n first second halves fs ss n) (j : Fin n) :
    halves.val[j.val]! = (first j).magnitude ∧ halves.val[n + j.val]! = (second j).magnitude ∧
      fs.val[j.val]! = (first j).negative ∧ ss.val[j.val]! = (second j).negative := by
  obtain ⟨ha, hb, hf, hs⟩ := h.2.2.2 j j.isLt
  simp [List.getElem!_eq_getElem?_getD, ha, hb, hf, hs]

def splitPoint (points : List blst.blst_p1_affine) (fs ss : List Bool) (i : ℕ) : G1Spec.E.Point :=
  if i < points.length then transformedPoint points[i]! false fs[i]!
    else transformedPoint points[i - points.length]! true ss[i - points.length]!

theorem splitPoint_first (points : List blst.blst_p1_affine) (fs ss : List Bool)
    (i : ℕ) (hi : i < points.length) :
    splitPoint points fs ss i = transformedPoint points[i]! false fs[i]! := by
  simp only [splitPoint, hi, if_true]

theorem splitPoint_second (points : List blst.blst_p1_affine) (fs ss : List Bool) (i : ℕ) :
    splitPoint points fs ss (points.length + i) = transformedPoint points[i]! true ss[i]! := by
  simp only [splitPoint, show ¬points.length + i < points.length by omega, if_false,
    Nat.add_sub_cancel_left]

theorem split_points_rep (points : List blst.blst_p1_affine) (fs ss : List Bool)
    (rows : List Limbs)
    (hf : ∀ i, i < points.length → RowRep rows i (transformedPoint points[i]! false fs[i]!))
    (hs : ∀ i, i < points.length → RowRep rows (points.length + i)
      (transformedPoint points[i]! true ss[i]!)) :
    ∀ i, i < 2 * points.length → RowRep rows i (splitPoint points fs ss i) := by
  intro i hi
  by_cases h : i < points.length
  · rw [splitPoint_first _ _ _ _ h]
    exact hf i h
  · have he : i = points.length + (i - points.length) := by omega
    rw [he, splitPoint_second]
    exact hs _ (by omega)

theorem split_values_bound {n : ℕ} {first second : Fin n → msm8.glv.Half}
    {halves : alloc.vec.Vec ScalarWords} {fs ss : alloc.vec.Vec Bool}
    (h : SplitInv n first second halves fs ss n)
    (hb : ∀ j, GlvRefines.value (first j).magnitude < 2 ^ 127 ∧
      GlvRefines.value (second j).magnitude < 2 ^ 127) :
    ∀ i, i < 2 * n → Kzg.limbs halves.val[i]!.val < 2 ^ 127 := by
  intro i hi
  by_cases hin : i < n
  · rw [(h.get ⟨i, hin⟩).1]
    have hb' := (hb ⟨i, hin⟩).1
    rw [glv_value_eq_limbs] at hb'
    exact_mod_cast hb'
  · have hj : i - n < n := by omega
    have he : i = n + (i - n) := by omega
    rw [he, (h.get ⟨i - n, hj⟩).2.1]
    have hb' := (hb ⟨i - n, hj⟩).2
    rw [glv_value_eq_limbs] at hb'
    exact_mod_cast hb'

theorem split_sum_contribution (points : List blst.blst_p1_affine) (scalars : List ScalarWords)
    (halign : points.length = scalars.length)
    (first second : Fin scalars.length → msm8.glv.Half)
    (halves : alloc.vec.Vec ScalarWords) (fs ss : alloc.vec.Vec Bool)
    (hinv : SplitInv scalars.length first second halves fs ss scalars.length)
    (hp : ∀ i, i < points.length → Kzg.G1AffineValid points[i]!)
    (hfirst : ∀ j : Fin scalars.length,
      GlvRefines.signedValue (first j) = Glv.first (GlvRefines.value scalars[j.val]))
    (hsecond : ∀ j : Fin scalars.length,
      GlvRefines.signedValue (second j) = Glv.second (GlvRefines.value scalars[j.val])) :
    (∑ i ∈ Finset.range halves.val.length,
      Kzg.limbs halves.val[i]!.val • splitPoint points fs.val ss.val i) =
        ∑ i ∈ Finset.range scalars.length, inputContribution (points[i]!, scalars[i]!) := by
  rw [hinv.1, show 2 * scalars.length = scalars.length + scalars.length by omega,
    Finset.sum_range_add, ← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro i hi
  have hi' : i < scalars.length := Finset.mem_range.mp hi
  have hip : i < points.length := by omega
  obtain ⟨ha, hb, hf, hs⟩ := hinv.get ⟨i, hi'⟩
  have hpt : splitPoint points fs.val ss.val (scalars.length + i) =
      transformedPoint points[i]! true ss.val[i]! := by
    rw [← halign, splitPoint_second]
  rw [ha, hb, splitPoint_first _ _ _ _ hip, hpt, hf, hs]
  simpa only [transformedPoint, if_false, if_true, List.getElem!_eq_getElem?_getD,
    List.getElem?_eq_getElem hi', Option.getD_some] using
    split_scalar_contribution points[i]! scalars[i] (first ⟨i, hi'⟩) (second ⟨i, hi'⟩)
      (hp i hip) (hfirst ⟨i, hi'⟩) (hsecond ⟨i, hi'⟩)

end LeanBlsSimd.Msm8
