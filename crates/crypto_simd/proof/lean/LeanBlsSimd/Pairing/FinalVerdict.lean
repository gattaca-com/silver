import LeanBlsSimd.Pairing.FinalInvariant

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FinalExponent

set_option maxRecDepth 4000
set_option exponentiation.threshold 20000

theorem optimized_cube (a : Bls.Fp12) :
    Fp12.toField (optimized a) = Fp12.toField (finalExponentiation a) ^ 3 := by
  rw [optimized_power, toField_finalExponentiation, ← pow_mul]
  have he : finalExpExponent * 3 = 3 * finalExpExponent := Nat.mul_comm _ _
  rw [he]
  by_cases hz : Fp12.toField a = 0
  · rw [hz, zero_pow (ne_of_gt exponent_positive), zero_pow]
    exact Nat.mul_ne_zero (by decide) (ne_of_gt finalExpExponent_pos)
  · have hp : Fp12.toField a ^ period = 1 := by
      rw [period, ← Fp12Field.card_eq]
      exact FiniteField.pow_card_sub_one_eq_one _ hz
    rw [pow_eq_pow_mod exponent hp, exponent_certificate, ← pow_eq_pow_mod (3 * finalExpExponent) hp]

theorem cube_one_iff (x : Fp12Field) (hx : x ^ Fr.modulus = 1) : x ^ 3 = 1 ↔ x = 1 := by
  constructor
  · intro h
    have hd : orderOf x ∣ 1 := by
      rw [← cube_coprime.gcd_eq_one]
      exact Nat.dvd_gcd (orderOf_dvd_of_pow_eq_one h) (orderOf_dvd_of_pow_eq_one hx)
    exact orderOf_eq_one_iff.mp (Nat.eq_one_of_dvd_one hd)
  · rintro rfl
    exact one_pow _

theorem verdict (a : Bls.Fp12) : (optimized a).isOne = (finalExponentiation a).isOne := by
  rw [Bool.eq_iff_iff, Fp12.isOne_iff, Fp12.isOne_iff, optimized_cube]
  by_cases hz : a = Bls.Fp12.zero
  · subst a
    simp
  · exact cube_one_iff _ (finalExponentiation_pow_r a hz)

end LeanBlsSimd.Pairing.FinalExponent
