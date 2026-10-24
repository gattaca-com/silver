import LeanBlsSimd.Pairing.CombinedMiller
import LeanBlsSimd.Refines.G1x8

open EthLib.Cryptography Bls
open Aeneas Aeneas.Std

namespace LeanBlsSimd.Pairing

set_option maxRecDepth 8000
set_option maxHeartbeats 1000000

/-- Number of table rows consumed before the remaining `n` bits. -/
def consumed (n : Nat) : Nat := 68 - (lineKinds n).length

theorem consumed_zero : consumed 0 = 68 := by decide +kernel

theorem consumed_start : consumed 63 = 0 := by decide +kernel

theorem consumed_bound (n : Nat) : consumed n ≤ 68 := Nat.sub_le _ _

theorem consumed_positive (n : Fin 63) : 0 < consumed n.val := by
  revert n
  decide +kernel

theorem double_row_bound (n : Fin 63) : consumed (n.val + 1) < 68 := by
  revert n
  decide +kernel

def doubleRow (n : Fin 63) : Fin 68 := ⟨consumed (n.val + 1), double_row_bound n⟩

theorem double_row_kind (n : Fin 63) : lineKind (doubleRow n) = false := by
  revert n
  decide +kernel

theorem add_row_bound (n : Fin 63) (h : blsX.testBit n.val = true) :
    consumed (n.val + 1) + 1 < 68 := by
  revert h n
  decide +kernel

def addRow (n : Fin 63) (h : blsX.testBit n.val = true) : Fin 68 :=
  ⟨consumed (n.val + 1) + 1, add_row_bound n h⟩

theorem add_row_kind (n : Fin 63) (h : blsX.testBit n.val = true) :
    lineKind (addRow n h) = true := by
  revert h n
  decide +kernel

theorem consumed_step (n : Fin 63) :
    consumed n.val = consumed (n.val + 1) + 1 + if blsX.testBit n.val then 1 else 0 := by
  revert n
  decide +kernel

theorem lower_bit_agrees (n : Fin 63) : G1x8.is_lower_z_bit n.val = blsX.testBit n.val := by
  revert n
  decide +kernel

def bitRows (n : Fin 63) : List (Fin 68) :=
  doubleRow n :: (if h : blsX.testBit n.val = true then [addRow n h] else [])

def remainingRows (n : Nat) : List (Fin 68) := (List.finRange 68).drop (consumed n)

theorem remaining_zero : remainingRows 0 = [] := by decide +kernel

theorem remaining_start : remainingRows 63 = List.finRange 68 := by
  rw [remainingRows, consumed_start, List.drop_zero]

theorem remaining_step (n : Fin 63) :
    remainingRows (n.val + 1) = bitRows n ++ remainingRows n.val := by
  revert n
  decide +kernel

noncomputable def bitStep (v : Factors) (present : Array Bool 2#usize)
    (n : Fin 63) (f : Fp12) : Fp12 := (bitRows n).foldl (combinedStep v present) f

noncomputable def remainingMiller (v : Factors) (present : Array Bool 2#usize)
    (n : Nat) (f : Fp12) : Fp12 := (remainingRows n).foldl (combinedStep v present) f

theorem remaining_miller_step (v : Factors) (present : Array Bool 2#usize)
    (n : Fin 63) (f : Fp12) :
    remainingMiller v present (n.val + 1) f =
      remainingMiller v present n.val (bitStep v present n f) := by
  rw [remainingMiller, remaining_step, List.foldl_append]
  rfl

theorem remaining_miller_start (points : Fin 2 → G1) :
    remainingMiller (g1Factors points) (presence points) 63 Fp12.one = combinedMiller points := by
  rw [remainingMiller, remaining_start]
  rfl

theorem consumed_eq_zero (n : Fin 64) : consumed n.val = 0 ↔ n.val = 63 := by
  revert n
  decide +kernel

noncomputable def applyLines (v : Factors) (present : Array Bool 2#usize)
    (step : Fin 68) (f : Fp12) : Fp12 := pairApply step v present 1 (pairApply step v present 0 f)

theorem bit_step_eq (v : Factors) (present : Array Bool 2#usize) (n : Fin 63) (f : Fp12) :
    bitStep v present n f =
      if h : blsX.testBit n.val = true then
        applyLines v present (addRow n h) (applyLines v present (doubleRow n) (f * f))
      else applyLines v present (doubleRow n) (f * f) := by
  unfold bitStep bitRows
  split_ifs with h
  · simp only [List.foldl_cons, List.foldl_nil, combinedStep, activeStep,
      double_row_kind, add_row_kind, Bool.false_eq_true, if_false, if_true, applyLines]
  · simp only [List.foldl_cons, List.foldl_nil, combinedStep, activeStep,
      double_row_kind, Bool.false_eq_true, if_false, applyLines]

theorem initial_square (n : Fin 63) (f : Fp12) (h : n.val + 1 = 63 → f = Fp12.one) :
    (if consumed (n.val + 1) > 0 then f.square else f) = f * f := by
  split_ifs with hp
  · rfl
  · have hz : consumed (n.val + 1) = 0 := by omega
    have hn := (consumed_eq_zero ⟨n.val + 1, by omega⟩).mp hz
    rw [h hn]
    apply Fp12.toField.injective
    simp only [map_mul, Fp12.toField_one, one_mul]

end LeanBlsSimd.Pairing
