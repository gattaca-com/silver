import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.Spec.FinalExponentiation

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

abbrev fp2Embed : Fp2Field →+* Fp12Field :=
  (algebraMap Fp6Field Fp12Field).comp Fp6Field.of

theorem w_sixth : Fp12Field.w ^ 6 = fp2Embed Fp6Field.xi := by
  rw [show (6 : Nat) = 2 * 3 from rfl, pow_mul, Fp12Field.w_sq,
    ← map_pow, Fp6Field.v_cube]
  rfl

theorem xi_ne_zero : Fp6Field.xi ≠ 0 := by
  intro h
  have he : (1 : ZMod Fp.modulus) = 0 := by
    simpa [Fp6Field.xi, QuadraticAlgebra.re_one] using congrArg QuadraticAlgebra.re h
  exact one_ne_zero he

theorem w_ne_zero : Fp12Field.w ≠ 0 := by
  intro h
  have he := w_sixth
  rw [h, zero_pow (by decide : (6 : Nat) ≠ 0)] at he
  apply xi_ne_zero
  apply fp2Embed.injective
  simpa only [map_zero] using he.symm

theorem fp2_period (a : Fp2Field) (ha : a ≠ 0) :
    fp2Embed a ^ (Fp.modulus ^ 2 - 1) = 1 := by
  rw [← map_pow, ← Fp2Field.card_eq,
    FiniteField.pow_card_sub_one_eq_one a ha, map_one]

theorem fp2_period_four (a : Fp2Field) (ha : a ≠ 0) :
    fp2Embed a ^ (Fp.modulus ^ 4 - 1) = 1 := by
  rw [show Fp.modulus ^ 4 - 1 = (Fp.modulus ^ 2 - 1) * (Fp.modulus ^ 2 + 1)
    from by decide +kernel, pow_mul, fp2_period a ha, one_pow]

theorem w_cube_period : (Fp12Field.w ^ 3) ^ (Fp.modulus ^ 4 - 1) = 1 := by
  rw [← pow_mul,
    show 3 * (Fp.modulus ^ 4 - 1) = 6 * ((Fp.modulus ^ 2 - 1) * ((Fp.modulus ^ 2 + 1) / 2))
      from by decide +kernel,
    pow_mul, w_sixth, pow_mul, fp2_period Fp6Field.xi xi_ne_zero, one_pow]

/-- The factor discarded when a twist line is normalized by its constant coefficient. -/
def lineScale (c : Fp2Field) : Fp12Field := fp2Embed c * (Fp12Field.w ^ 3)⁻¹

theorem lineScale_ne_zero (c : Fp2Field) (hc : c ≠ 0) : lineScale c ≠ 0 := by
  apply mul_ne_zero
  · exact (map_ne_zero fp2Embed).mpr hc
  · exact inv_ne_zero (pow_ne_zero 3 w_ne_zero)

/-- A nonzero normalized-line factor lies in the multiplicative Fp4 subfield. -/
theorem lineScale_period (c : Fp2Field) (hc : c ≠ 0) :
    lineScale c ^ (Fp.modulus ^ 4 - 1) = 1 := by
  rw [lineScale, mul_pow, inv_pow, fp2_period_four c hc, w_cube_period, inv_one, mul_one]

theorem period_four_final_power {a : Fp12Field}
    (h : a ^ (Fp.modulus ^ 4 - 1) = 1) : a ^ finalExpExponent = 1 := by
  rw [show finalExpExponent = (Fp.modulus ^ 4 - 1) *
      (finalExpExponent / (Fp.modulus ^ 4 - 1)) from by decide +kernel,
    pow_mul, h, one_pow]

theorem lineScale_final_power (c : Fp2Field) (hc : c ≠ 0) :
    lineScale c ^ finalExpExponent = 1 := period_four_final_power (lineScale_period c hc)

/-- Removing the line's Fp4 factor preserves final exponentiation even at zero. -/
theorem lineScale_remove (c : Fp2Field) (hc : c ≠ 0) (f : Fp12Field) :
    (lineScale c * f) ^ finalExpExponent = f ^ finalExpExponent := by
  rw [mul_pow, lineScale_final_power c hc, one_mul]

end

end LeanBlsSimd.Pairing
