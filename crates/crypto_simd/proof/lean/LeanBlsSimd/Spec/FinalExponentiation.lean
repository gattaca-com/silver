import LeanBlsSimd.Spec.Fp12
import Mathlib.RingTheory.RootsOfUnity.Basic

/-! Final exponentiation is multiplicative on the field and has a group-valued nonzero restriction. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

theorem finalExpExponent_pos : 0 < finalExpExponent := by decide +kernel

theorem finalExpExponent_mul_r :
    finalExpExponent * Fr.modulus = Fp.modulus ^ 12 - 1 := by decide +kernel

@[simp] theorem Fp12.toField_eq_zero_iff (f : Fp12) :
    Fp12.toField f = 0 ↔ f = Fp12.zero := by
  rw [← Fp12.toField_zero, Fp12.toField.injective.eq_iff]

@[simp] theorem toField_finalExponentiation (f : Fp12) :
    Fp12.toField (finalExponentiation f) = Fp12.toField f ^ finalExpExponent :=
  Fp12.toField_powNat f finalExpExponent

/-- Multiplicativity holds even when a factor is zero. -/
theorem finalExponentiation_mul (f g : Fp12) :
    finalExponentiation (f * g) = finalExponentiation f * finalExponentiation g := by
  apply Fp12.toField.injective
  simp only [toField_finalExponentiation, map_mul, mul_pow]

@[simp] theorem finalExponentiation_one : finalExponentiation Fp12.one = Fp12.one := by
  apply Fp12.toField.injective
  simp

@[simp] theorem finalExponentiation_zero : finalExponentiation Fp12.zero = Fp12.zero := by
  apply Fp12.toField.injective
  simp [ne_of_gt finalExpExponent_pos]

theorem finalExponentiation_ne_zero (f : Fp12) (hf : f ≠ Fp12.zero) :
    finalExponentiation f ≠ Fp12.zero := by
  intro h
  have h0 := (Fp12.toField_eq_zero_iff _).mpr h
  rw [toField_finalExponentiation] at h0
  exact pow_ne_zero _ (mt (Fp12.toField_eq_zero_iff f).mp hf) h0

theorem finalExponentiation_pow_r (f : Fp12) (hf : f ≠ Fp12.zero) :
    Fp12.toField (finalExponentiation f) ^ Fr.modulus = 1 := by
  rw [toField_finalExponentiation, ← pow_mul, finalExpExponent_mul_r, ← Fp12Field.card_eq]
  exact FiniteField.pow_card_sub_one_eq_one _ (mt (Fp12.toField_eq_zero_iff f).mp hf)

theorem target_pow_r (x : rootsOfUnity Fr.modulus Fp12Field) : x ^ Fr.modulus = 1 := by
  apply Subtype.ext
  exact x.property

/-- The nonzero hypothesis is required because the roots of unity consist of units. -/
def finalExponentiationTarget (f : Fp12) (hf : f ≠ Fp12.zero) :
    rootsOfUnity Fr.modulus Fp12Field :=
  rootsOfUnity.mkOfPowEq (Fp12.toField (finalExponentiation f)) (finalExponentiation_pow_r f hf)

@[simp] theorem finalExponentiationTarget_val (f : Fp12) (hf : f ≠ Fp12.zero) :
    ((finalExponentiationTarget f hf : Fp12Fieldˣ) : Fp12Field) =
      Fp12.toField (finalExponentiation f) := rfl

theorem finalExponentiation_isOne_iff (f : Fp12) :
    (finalExponentiation f).isOne = true ↔ Fp12.toField f ^ finalExpExponent = 1 := by
  rw [Fp12.isOne_iff, toField_finalExponentiation]

theorem finalExponentiation_zero_not_isOne : (finalExponentiation Fp12.zero).isOne = false := by
  rw [finalExponentiation_zero]
  apply Bool.eq_false_iff.mpr
  intro h
  have he := (Fp12.isOne_iff _).mp h
  simp at he

end

end LeanBlsSimd
