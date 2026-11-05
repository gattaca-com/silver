import LeanBlsSimd.Spec.Fp12
import LeanBlsSimd.Spec.Cyclotomic.Field
import Mathlib.RingTheory.RootsOfUnity.Basic

/-! Final exponentiation equals a total field power and has a group-valued nonzero restriction. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

theorem finalExpExponent_pos : 0 < finalExpExponent := by decide +kernel

theorem finalExpExponent_mul_r :
    finalExpExponent * Fr.modulus = Fp.modulus ^ 12 - 1 := by decide +kernel

@[simp] theorem Fp12.toField_eq_zero_iff (f : Fp12) :
    Fp12.toField f = 0 ↔ f = Fp12.zero := by
  rw [← Fp12.toField_zero, Fp12.toField.injective.eq_iff]

/-- The spec computes the power in three factors, `(p⁶ − 1) · (p² + 1) · finalExpHard`. -/
@[simp] theorem toField_finalExponentiation (f : Fp12) :
    Fp12.toField (finalExponentiation f) = Fp12.toField f ^ finalExpExponent := by
  have hfactors : (Fp.modulus ^ 6 - 1) * (Fp.modulus ^ 2 + 1) * finalExpHard = finalExpExponent := by
    decide +kernel
  simp only [finalExponentiation, Fp12.toField_powNat, map_mul, Cyclotomic.spec_conjugate,
    Fp12.toField_inverse]
  rw [← hfactors]
  by_cases hx : Fp12.toField f = 0
  · rw [hx, zero_pow (by decide +kernel), zero_pow (by decide +kernel), inv_zero, mul_zero,
      zero_pow (by decide +kernel), zero_mul, zero_pow (by decide +kernel)]
  · have heasy : Fp12.toField f ^ (Fp.modulus ^ 6) * (Fp12.toField f)⁻¹ =
        Fp12.toField f ^ (Fp.modulus ^ 6 - 1) := by
      rw [pow_sub₀ _ hx (by decide +kernel : 1 ≤ Fp.modulus ^ 6), pow_one]
    rw [heasy, ← pow_succ, ← pow_mul, ← pow_mul, Nat.mul_assoc]

@[simp] theorem finalExponentiation_one : finalExponentiation Fp12.one = Fp12.one := by
  apply Fp12.toField.injective
  simp

@[simp] theorem finalExponentiation_zero : finalExponentiation Fp12.zero = Fp12.zero := by
  apply Fp12.toField.injective
  simp [ne_of_gt finalExpExponent_pos]

theorem finalExponentiation_pow_r (f : Fp12) (hf : f ≠ Fp12.zero) :
    Fp12.toField (finalExponentiation f) ^ Fr.modulus = 1 := by
  rw [toField_finalExponentiation, ← pow_mul, finalExpExponent_mul_r, ← Fp12Field.card_eq]
  exact FiniteField.pow_card_sub_one_eq_one _ (mt (Fp12.toField_eq_zero_iff f).mp hf)

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

end

end LeanBlsSimd

namespace LeanBlsSimd.SpecPairing

open EthLib.Cryptography.Bls

end LeanBlsSimd.SpecPairing
