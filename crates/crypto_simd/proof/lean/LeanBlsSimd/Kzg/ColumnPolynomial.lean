import LeanBlsSimd.Kzg.PolynomialArithmetic
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg

set_option maxHeartbeats 1000000
set_option maxRecDepth 4000

private def columnAdd (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) (acc : Array Fr) (k : Nat) : Array Fr :=
  if indices[k]! = c then
    Array.ofFn (n := 64) (fun j => acc[j.val]! + powers[k]! * (evals[k]!)[j.val]!)
  else acc

def columnValues (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) : Array Fr :=
  (Array.range indices.size).foldl (columnAdd indices evals powers c)
    (Array.replicate 64 Fr.zero)

private theorem columnAdd_size (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) (acc : Array Fr) (k : Nat) (ha : acc.size = 64) :
    (columnAdd indices evals powers c acc k).size = 64 := by
  unfold columnAdd
  split <;> simp_all

private theorem column_fold_size (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) (ks : List Nat) (acc : Array Fr) (ha : acc.size = 64) :
    (ks.foldl (columnAdd indices evals powers c) acc).size = 64 := by
  induction ks generalizing acc with
  | nil => exact ha
  | cons k ks ih => exact ih _ (columnAdd_size indices evals powers c acc k ha)

theorem columnValues_size (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) : (columnValues indices evals powers c).size = 64 := by
  rw [columnValues, ← Array.foldl_toList]
  exact column_fold_size _ _ _ _ _ _ (by simp)

private theorem column_fold_get (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) (ks : List Nat) (acc : Array Fr) (ha : acc.size = 64)
    (j : Fin 64) :
    (ks.foldl (columnAdd indices evals powers c) acc)[j.val]! = acc[j.val]! +
      (ks.map fun k => if indices[k]! = c then powers[k]! * (evals[k]!)[j.val]! else 0).sum := by
  induction ks generalizing acc with
  | nil => simp
  | cons k ks ih =>
    rw [List.foldl_cons, ih _ (columnAdd_size indices evals powers c acc k ha)]
    simp only [List.map_cons, List.sum_cons]
    unfold columnAdd
    split
    · rename_i hc
      rw [getElem!_pos (Array.ofFn (n := 64)
        (fun i => acc[i.val]! + powers[k]! * (evals[k]!)[i.val]!)) j.val (by simp),
        Array.getElem_ofFn]
      abel
    · rename_i hc
      simp

theorem columnValues_get (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) (j : Fin 64) :
    (columnValues indices evals powers c)[j.val]! =
      ∑ k ∈ Finset.range indices.size,
        if indices[k]! = c then powers[k]! * (evals[k]!)[j.val]! else 0 := by
  rw [columnValues, ← Array.foldl_toList, Array.toList_range,
    column_fold_get _ _ _ _ _ _ (by simp)]
  rw [getElem!_pos (Array.replicate 64 Fr.zero) j.val (by simp),
    Array.getElem_replicate]
  simp only [Fr.zero_def]
  trans (List.range indices.size |>.map fun k =>
    if indices[k]! = c then powers[k]! * (evals[k]!)[j.val]! else (0 : Fr)).sum
  · exact zero_add _
  simpa only [List.toFinset_range] using
    (List.sum_toFinset (fun k => if indices[k]! = c then powers[k]! * (evals[k]!)[j.val]! else (0 : Fr))
      (List.nodup_range (n := indices.size))).symm

theorem cellInterpolant_zero (c : Nat) : cellInterpolant c (fun _ => 0) = 0 := by
  exact (cellInterpolant c).map_zero

theorem cellInterpolant_add (c : Nat) (a b : Fin 64 → Fr) :
    cellInterpolant c (fun j => a j + b j) = cellInterpolant c a + cellInterpolant c b := by
  exact (cellInterpolant c).map_add a b

theorem cellInterpolant_mul (c : Nat) (r : Fr) (a : Fin 64 → Fr) :
    cellInterpolant c (fun j => r * a j) =
      _root_.Polynomial.C r * cellInterpolant c a := by
  simp only [cellInterpolant, Lagrange.interpolate_apply, map_mul, Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro j _
  rw [mul_assoc]

private theorem cellInterpolant_sum (c : Nat) (ks : Finset Nat) (values : Nat → Fin 64 → Fr) :
    cellInterpolant c (fun j => ∑ k ∈ ks, values k j) =
      ∑ k ∈ ks, cellInterpolant c (values k) := by
  classical
  induction ks using Finset.induction_on with
  | empty => simp [cellInterpolant_zero]
  | @insert k ks hk ih =>
    simp only [Finset.sum_insert hk]
    rw [cellInterpolant_add, ih]

theorem columnValues_interpolant (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (c : Nat) :
    cellInterpolant c (fun j => (columnValues indices evals powers c)[j.val]!) =
      ∑ k ∈ Finset.range indices.size, if indices[k]! = c then
        _root_.Polynomial.C powers[k]! * cellInterpolant c (fun j => (evals[k]!)[j.val]!)
      else 0 := by
  simp only [columnValues_get]
  rw [cellInterpolant_sum]
  apply Finset.sum_congr rfl
  intro k _
  by_cases hc : indices[k]! = c
  · simp only [hc, if_true, cellInterpolant_mul]
  · simp only [hc, if_false, cellInterpolant_zero]

theorem sum_columnValues_interpolant (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hi : ∀ c ∈ indices, c < 128) :
    (∑ c ∈ Finset.range 128,
      cellInterpolant c (fun j => (columnValues indices evals powers c)[j.val]!)) =
      ∑ k ∈ Finset.range indices.size,
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  simp only [columnValues_interpolant]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro k hk
  have hkb : k < indices.size := Finset.mem_range.mp hk
  have hic : indices[k]! < 128 := by
    rw [getElem!_pos indices k hkb]
    exact hi _ (Array.getElem_mem hkb)
  simp [Finset.sum_ite_eq, hic]

private theorem column_fold_polynomial
    (hifft : ∀ c, c < 128 → ∀ values : Array Fr, values.size = 64 →
      coeffPolynomial (cellIfft c values) = cellInterpolant c (fun j => values[j.val]!))
    (indices : Array Nat) (evals : Array CosetEvals) (powers : Array Fr)
    (cs : List Nat) (hcs : ∀ c ∈ cs, c < 128) (initial : Array Fr) :
    coeffPolynomial (cs.foldl (fun total c => addPolynomialcoeff total
      (cellIfft c (columnValues indices evals powers c))) initial) =
      coeffPolynomial initial +
        (cs.map fun c => cellInterpolant c
          (fun j => (columnValues indices evals powers c)[j.val]!)).sum := by
  induction cs generalizing initial with
  | nil => simp
  | cons c cs ih =>
    rw [List.foldl_cons, ih (fun d hd => hcs d (by simp [hd])),
      coeffPolynomial_add, hifft c (hcs c (by simp)) _ (columnValues_size ..)]
    simp only [List.map_cons, List.sum_cons]
    exact add_assoc _ _ _

theorem columnRli_polynomial
    (hifft : ∀ c, c < 128 → ∀ values : Array Fr, values.size = 64 →
      coeffPolynomial (cellIfft c values) = cellInterpolant c (fun j => values[j.val]!))
    (indices : Array Nat) (evals : Array CosetEvals) (powers : Array Fr)
    (hi : ∀ c ∈ indices, c < 128) :
    coeffPolynomial (Model.columnRli indices evals powers) =
      ∑ k ∈ Finset.range indices.size,
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  change coeffPolynomial ((Array.range 128).foldl
    (fun total c => addPolynomialcoeff total (cellIfft c (columnValues indices evals powers c)))
    (Array.replicate 64 Fr.zero)) = _
  rw [← Array.foldl_toList, Array.toList_range,
    column_fold_polynomial hifft indices evals powers _ (fun c hc => List.mem_range.mp hc),
    coeffPolynomial_replicate_zero, zero_add]
  rw [← List.sum_toFinset _ List.nodup_range]
  exact sum_columnValues_interpolant indices evals powers hi

end LeanBlsSimd.Kzg
