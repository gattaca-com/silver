import Mathlib.NumberTheory.JacobiSum.Basic
import Mathlib.NumberTheory.MulChar.Lemmas

/-! Complex norms of character values and of Jacobi sums over a finite field. -/

namespace LeanBlsSimd

open MulChar

variable {F : Type*} [Field F] [Fintype F]

theorem norm_mulChar_apply_eq_one (χ : MulChar F ℂ) {a : F} (ha : a ≠ 0) : ‖χ a‖ = 1 := by
  classical
  obtain ⟨u, rfl⟩ := ha.isUnit
  simpa using Complex.norm_eq_one_of_mem_rootsOfUnity (χ.apply_mem_rootsOfUnity u)

theorem norm_mulChar_apply_le_one (χ : MulChar F ℂ) (a : F) : ‖χ a‖ ≤ 1 := by
  by_cases ha : a = 0
  · simp [ha]
  · exact (norm_mulChar_apply_eq_one χ ha).le

theorem jacobiSum_inv_inv_eq_star (χ φ : MulChar F ℂ) :
    jacobiSum χ⁻¹ φ⁻¹ = star (jacobiSum χ φ) := by
  simp only [jacobiSum, star_sum, star_mul', star_apply']

theorem norm_jacobiSum_sq {χ φ : MulChar F ℂ} (hχ : χ ≠ 1) (hφ : φ ≠ 1) (hχφ : χ * φ ≠ 1) :
    ‖jacobiSum χ φ‖ ^ 2 = Fintype.card F := by
  have hc : ringChar ℂ ≠ ringChar F := by
    rw [ringChar.eq_zero]
    exact (CharP.char_ne_zero_of_finite F (ringChar F)).symm
  have h := jacobiSum_mul_jacobiSum_inv hc hχ hφ hχφ
  rw [jacobiSum_inv_inv_eq_star, Complex.star_def, Complex.mul_conj'] at h
  exact_mod_cast h

theorem norm_jacobiSum {χ φ : MulChar F ℂ} (hχ : χ ≠ 1) (hφ : φ ≠ 1) (hχφ : χ * φ ≠ 1) :
    ‖jacobiSum χ φ‖ = Real.sqrt (Fintype.card F) := by
  rw [← norm_jacobiSum_sq hχ hφ hχφ, Real.sqrt_sq (norm_nonneg _)]

end LeanBlsSimd
