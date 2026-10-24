import LeanBlsSimd.Spec.Fp6

/-! The executable cofactor formula computes the quotient-field inverse, including at zero. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

namespace Fp6Field

def cofactor (a b c : Fp2Field) : Fp6Field :=
  assemble (a * a - (b * c) * xi) ((c * c) * xi - a * b) (b * b - a * c)

def determinant (a b c : Fp2Field) : Fp2Field :=
  a * (a * a - (b * c) * xi) + (c * ((c * c) * xi - a * b)) * xi +
    (b * (b * b - a * c)) * xi

theorem mul_cofactor (a b c : Fp2Field) :
    assemble a b c * cofactor a b c = of (determinant a b c) := by
  rw [cofactor, assemble_mul]
  simp only [assemble, determinant, map_add, map_mul, map_sub]
  ring

theorem cofactor_ne_zero (a b c : Fp2Field) (h : assemble a b c ≠ 0) :
    cofactor a b c ≠ 0 := by
  intro hc0
  obtain ⟨ht0, ht1, ht2⟩ := (assemble_eq_zero_iff _ _ _).mp hc0
  by_cases hc : c = 0
  · have hb : b = 0 := mul_self_eq_zero.mp (by simpa [hc] using ht2)
    have ha : a = 0 := mul_self_eq_zero.mp (by simpa [hb, hc] using ht0)
    exact h ((assemble_eq_zero_iff _ _ _).mpr ⟨ha, hb, hc⟩)
  · apply xi_not_cube (b / c)
    rw [div_pow, div_eq_iff (pow_ne_zero 3 hc)]
    linear_combination b * ht2 - c * ht1

theorem determinant_ne_zero (a b c : Fp2Field) (h : assemble a b c ≠ 0) :
    determinant a b c ≠ 0 := by
  intro hd
  have hp := mul_ne_zero h (cofactor_ne_zero a b c h)
  apply hp
  rw [mul_cofactor, hd, map_zero]

theorem inverse_formula (a b c : Fp2Field) :
    (assemble a b c)⁻¹ = cofactor a b c * of (determinant a b c)⁻¹ := by
  by_cases h : assemble a b c = 0
  · obtain ⟨rfl, rfl, rfl⟩ := (assemble_eq_zero_iff _ _ _).mp h
    simp [assemble, cofactor, determinant]
  · have hd := determinant_ne_zero a b c h
    apply mul_left_cancel₀ h
    rw [mul_inv_cancel₀ h, ← mul_assoc, mul_cofactor, ← map_mul, mul_inv_cancel₀ hd, map_one]

end Fp6Field

namespace Fp6

open EthLib.Cryptography.Bls.Fp6

open Fp6Field

theorem toField_inverse (a : Fp6) : toField a.inverse = (toField a)⁻¹ := by
  change assemble (Fp2.toField (inverse a).c0) (Fp2.toField (inverse a).c1)
    (Fp2.toField (inverse a).c2) = _
  simp only [inverse, map_mul, map_add, Fp2.toField_sub, Fp2.toField_mulByOnePlusI,
    Fp2.toField_inverse]
  rw [show toField a = assemble (Fp2.toField a.c0) (Fp2.toField a.c1)
    (Fp2.toField a.c2) from rfl, inverse_formula]
  simp only [cofactor, determinant, assemble, map_mul, map_add, map_sub, xi]
  ring

end Fp6

end

end LeanBlsSimd
