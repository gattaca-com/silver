import LeanBlsSimd.Constants

namespace LeanBlsSimd

open EthLib.Cryptography EthLib.Cryptography.Bls

/-- The cubic Euler test for 2, evaluated on modular natural representatives. -/
theorem two_pow_ne_one : (2 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 3) ≠ 1 := by
  have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 381 2 ((Fp.modulus - 1) / 3)
    (by decide +kernel)).not.mpr (by decide +kernel)
  rwa [Nat.cast_ofNat] at h

theorem two_not_cube (a : ZMod Fp.modulus) : a ^ 3 ≠ 2 := by
  intro h
  have ha : a ≠ 0 := by
    intro ha
    have h02 : (0 : ZMod Fp.modulus) = 2 := by simpa [ha] using h
    exact (by decide +kernel : (0 : ZMod Fp.modulus) ≠ 2) h02
  apply two_pow_ne_one
  rw [← h, ← pow_mul, show 3 * ((Fp.modulus - 1) / 3) = Fp.modulus - 1 by decide +kernel]
  exact ZMod.pow_card_sub_one_eq_one ha

theorem two_pow_half_ne_one : (2 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 2) ≠ 1 := by
  have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 381 2 ((Fp.modulus - 1) / 2)
    (by decide +kernel)).not.mpr (by decide +kernel)
  rwa [Nat.cast_ofNat] at h

theorem two_not_square (a : ZMod Fp.modulus) : a ^ 2 ≠ 2 := by
  intro h
  have ha : a ≠ 0 := by
    intro ha
    have h02 : (0 : ZMod Fp.modulus) = 2 := by simpa [ha] using h
    exact (by decide +kernel : (0 : ZMod Fp.modulus) ≠ 2) h02
  apply two_pow_half_ne_one
  rw [← h, ← pow_mul, show 2 * ((Fp.modulus - 1) / 2) = Fp.modulus - 1 by decide +kernel]
  exact ZMod.pow_card_sub_one_eq_one ha

end LeanBlsSimd
