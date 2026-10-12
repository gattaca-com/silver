import Mathlib.NumberTheory.JacobiSum.Basic

/-! Regroup a cubic character sum into two Jacobi sums, given the cube-fiber count. -/

namespace LeanBlsSimd
open scoped BigOperators
variable {F : Type*} [Field F] [Fintype F]

theorem sum_mulChar_shift (χ φ : MulChar F ℂ) {b : F} (hb : b ≠ 0) :
    ∑ t : F, χ t * φ (t + b) = χ (-b) * φ b * jacobiSum χ φ := by
  classical
  rw [← Equiv.sum_comp (Equiv.mulLeft₀ (-b) (neg_ne_zero.mpr hb))]
  simp only [Equiv.mulLeft₀_apply]
  have he (u : F) : -b * u + b = b * (1 - u) := by ring
  simp_rw [he, map_mul]
  rw [jacobiSum, Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro u _
  ring

theorem sum_cube_eq_jacobiSum (χ φ : MulChar F ℂ) (hφ : φ ≠ 1)
    (hcube : ∀ t : F, (Nat.card {x : F // x ^ 3 = t} : ℂ) = 1 + χ t + χ⁻¹ t)
    {b : F} (hb : b ≠ 0) :
    ∑ x : F, φ (x ^ 3 + b) =
      χ (-b) * φ b * jacobiSum χ φ + χ⁻¹ (-b) * φ b * jacobiSum χ⁻¹ φ := by
  classical
  have hf : ∑ x : F, φ (x ^ 3 + b) = ∑ t : F, (1 + χ t + χ⁻¹ t) * φ (t + b) := by
    rw [← Fintype.sum_fiberwise (fun x : F => x ^ 3) (fun x => φ (x ^ 3 + b))]
    apply Finset.sum_congr rfl
    intro t _
    simp only [show ∀ x : {x : F // x ^ 3 = t}, (x : F) ^ 3 = t from fun x => x.property,
      Finset.sum_const, Finset.card_univ, nsmul_eq_mul, ← Nat.card_eq_fintype_card, hcube]
  rw [hf]
  simp_rw [add_mul, one_mul, Finset.sum_add_distrib]
  have hz : ∑ t : F, φ (t + b) = 0 := by
    exact (Equiv.sum_comp (Equiv.addRight b) φ).trans (MulChar.sum_eq_zero_of_ne_one hφ)
  rw [hz, zero_add, sum_mulChar_shift χ φ hb, sum_mulChar_shift χ⁻¹ φ hb]
end LeanBlsSimd
