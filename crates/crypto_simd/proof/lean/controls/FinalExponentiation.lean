import LeanBlsSimd.Pairing.LaneFinal

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd
open LeanBlsSimd LeanBlsSimd.Pairing.FinalExponent

namespace FinalExponentiationControl

set_option exponentiation.threshold 20000

theorem easy_zero : Fp12.toField (easy Bls.Fp12.zero) = 0 := by
  rw [easy_field, Fp12.toField_zero, Cyclotomic.field_easy_zero]

theorem easy_zero_not_phi : Fp12.toField (easy Bls.Fp12.zero) ^ Pairing.FinalExponent.phi ≠ 1 := by
  rw [easy_zero, zero_pow (by decide +kernel : Pairing.FinalExponent.phi ≠ 0)]
  exact zero_ne_one

theorem factor_three_is_needed : exponent % period ≠ finalExpExponent % period := by
  decide +kernel

theorem optimized_zero : optimized Bls.Fp12.zero = Bls.Fp12.zero := by
  apply Fp12.toField.injective
  rw [optimized_power, Fp12.toField_zero, zero_pow (ne_of_gt exponent_positive)]

theorem optimized_one : optimized Bls.Fp12.one = Bls.Fp12.one := by
  apply Fp12.toField.injective
  rw [optimized_power, Fp12.toField_one, one_pow]


theorem lane_zero_rejected {raw : bls.fp2x8.Fp2x8} (h : LaneTower.Rep raw Bls.Fp12.zero) :
    (do let out ← bls.fp12.Fp12.final_exponentiation raw
        bls.fp12.Fp12.is_one out) = ok false := by
  rw [Lanes.final_verdict h, finalExponentiation_zero_not_isOne]


theorem lane_one_accepted {raw : bls.fp2x8.Fp2x8} (h : LaneTower.Rep raw Bls.Fp12.one) :
    (do let out ← bls.fp12.Fp12.final_exponentiation raw
        bls.fp12.Fp12.is_one out) = ok true := by
  rw [Lanes.final_verdict h, finalExponentiation_one]
  rfl

end FinalExponentiationControl
