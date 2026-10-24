import LeanBlsSimd.Spec.PairingProduct
import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.Refines.FrobeniusConstants

namespace LeanBlsSimd.Controls.Tower

open EthLib.Cryptography.Bls
open Cyclotomic

noncomputable section

theorem fp6_inverse_zero : Fp6.zero.inverse = Fp6.zero := by
  apply Fp6.toField.injective
  simp [Fp6.toField_inverse]

theorem fp6_inverse_one : Fp6.one.inverse = Fp6.one := by
  apply Fp6.toField.injective
  simp [Fp6.toField_inverse]

theorem fp12_inverse_zero : Fp12.zero.inverse = Fp12.zero := by
  apply Fp12.toField.injective
  simp [Fp12.toField_inverse]

theorem fp12_inverse_one : Fp12.one.inverse = Fp12.one := by
  apply Fp12.toField.injective
  simp [Fp12.toField_inverse]

theorem fp12_zero_pow_zero : Fp12.powNat Fp12.zero 0 = Fp12.one := by
  apply Fp12.toField.injective
  simp

theorem fp12_zero_pow_one : Fp12.powNat Fp12.zero 1 = Fp12.zero := by
  apply Fp12.toField.injective
  simp

theorem fp2_zero_pow_zero : Fp2.powNat Fp2.zero 0 = Fp2.one := by
  apply Fp2.toField.injective
  simp

theorem fp2_zero_pow_one : Fp2.powNat Fp2.zero 1 = Fp2.zero := by
  apply Fp2.toField.injective
  simp

theorem field_coordinates_roundtrip (x : Fp12) :
    fieldEquiv.symm (Schedule.decode Bls.xi (specCoeffs x)) = Fp12.toField x := by
  rw [← spec_toCubic, RingEquiv.symm_apply_apply]

theorem zero_final_exponent_rejected : (finalExponentiation Fp12.zero).isOne = false :=
  finalExponentiation_zero_not_isOne

theorem zero_easy_part_rejected : fieldEasyPart 0 ^ (Bls.p^4-Bls.p^2+1) ≠ 1 := by
  rw [field_easy_zero, zero_pow (by decide +kernel)]
  exact zero_ne_one

theorem zero_factor_multiplicativity (x : Fp12) :
    finalExponentiation (Fp12.zero * x) = Fp12.zero := by
  apply Fp12.toField.injective
  simp [toField_finalExponentiation, ne_of_gt finalExpExponent_pos]

theorem empty_pairing_accepted : pairingCheck #[] = true := pairingCheck_empty

theorem tower_cardinality : Fintype.card Fp6Field = Fp.modulus^6 ∧
    Fintype.card Fp12Field = Fp.modulus^12 := ⟨Fp6Field.card_eq,Fp12Field.card_eq⟩

#print axioms Fp6.toField_inverse
#print axioms Fp12.toField_inverse
#print axioms Fp12.toField_powNat
#print axioms fieldEquiv
#print axioms field_cyclotomic_square
#print axioms field_frobenius
#print axioms field_star
#print axioms field_easy_cyclotomic
#print axioms finalExponentiationTarget
#print axioms FrobeniusConstants.table_certificates

end
end LeanBlsSimd.Controls.Tower
