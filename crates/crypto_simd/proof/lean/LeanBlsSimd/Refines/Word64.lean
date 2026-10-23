import LeanBlsSimd.Refines.Basic
import Mathlib.Tactic

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd.Word64

abbrev radix : ℕ := 2 ^ 64

theorem cast128_val (x : U64) : (UScalar.cast .U128 x).val = x.val := by
  rw [UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (lt_trans x.hBounds (by norm_num [UScalarTy.numBits]))

theorem mac_bounds (a b p : U64) (c : U128) (hc : c.val < radix) :
    a.val * b.val + p.val + c.val < 2 ^ 128 := by
  have ha := a.hBounds
  have hb := b.hBounds
  have hp := p.hBounds
  norm_num [UScalarTy.numBits, radix] at *
  have hmul := Nat.mul_le_mul (show a.val ≤ 18446744073709551615 by omega)
    (show b.val ≤ 18446744073709551615 by omega)
  omega


def wordsValue : List U64 → ℤ
  | [] => 0
  | x :: xs => x.val + (radix : ℤ) * wordsValue xs

def value {n : Usize} (a : Array U64 n) : ℤ := wordsValue a.val

theorem wordsValue_set (xs : List U64) (j : ℕ) (x : U64) (hj : j < xs.length) :
    wordsValue (xs.set j x) = wordsValue xs +
      ((x.val : ℤ) - xs[j].val) * (radix : ℤ) ^ j := by
  induction xs generalizing j with
  | nil => simp at hj
  | cons a xs ih =>
    cases j with
    | zero => simp [wordsValue]; ring
    | succ j =>
      have hj' : j < xs.length := by simpa using hj
      simp only [List.set_cons_succ, wordsValue, ih j hj', List.getElem_cons_succ, pow_succ]
      ring

theorem value_set {n : Usize} (p : Array U64 n) (i : Usize) (x : U64)
    (hi : i.val < n.val) :
    value (p.set i x) = value p +
      ((x.val : ℤ) - (p.val[i.val]'(by rw [p.property]; exact hi)).val) *
      (radix : ℤ) ^ i.val := by
  exact wordsValue_set p.val i.val x (by rw [p.property]; exact hi)

theorem cast64_val (t : U128) : (UScalar.cast .U64 t).val = t.val % radix := by
  exact UScalar.cast_val_eq _ _

theorem high_val (t : U128) : (⟨t.bv.ushiftRight 64⟩ : U128).val = t.val / radix := by
  change (t.bv >>> (64 : ℕ)).toNat = t.val / radix
  rw [BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  rfl

theorem high_bound (t : U128) : (⟨t.bv.ushiftRight 64⟩ : U128).val < radix := by
  rw [high_val]
  have ht := t.hBounds
  norm_num [UScalarTy.numBits, radix] at *
  omega

theorem wordsValue_bounds (xs : List U64) :
    0 ≤ wordsValue xs ∧ wordsValue xs < (radix : ℤ) ^ xs.length := by
  induction xs with
  | nil => simp [wordsValue]
  | cons a xs ih =>
    have ha := a.hBounds
    simp only [wordsValue, List.length_cons, pow_succ]
    norm_num [radix, UScalarTy.numBits] at ha ih ⊢
    omega

theorem value_bounds {n : Usize} (p : Array U64 n) :
    0 ≤ value p ∧ value p < (radix : ℤ) ^ n.val := by
  simpa only [value, p.property] using wordsValue_bounds p.val

theorem complement_val (a : U64) : (~~~ a).val = radix - 1 - a.val := by
  change (~~~a.bv).toNat = radix - 1 - a.val
  rw [BitVec.toNat_not]
  rfl

theorem add_value {ty : UScalarTy} (x y : UScalar ty)
    (h : x.val + y.val < 2 ^ ty.numBits) :
    ∃ z : UScalar ty, x + y = ok z ∧ z.val = x.val + y.val :=
  ⟨UScalar.ofNatCore _ h, add_ok x y h, rfl⟩

theorem sub_value {ty : UScalarTy} (x y : UScalar ty) (h : y.val ≤ x.val) :
    ∃ z : UScalar ty, x - y = ok z ∧ z.val = x.val - y.val :=
  ⟨UScalar.ofNatCore _ (by have := x.hBounds; omega), sub_ok x y h, rfl⟩

end LeanBlsSimd.Word64
