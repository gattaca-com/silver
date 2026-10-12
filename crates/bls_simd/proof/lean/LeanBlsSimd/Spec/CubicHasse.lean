import LeanBlsSimd.Spec.PointCount
import LeanBlsSimd.Spec.CharacterSum
import LeanBlsSimd.Spec.JacobiNorm
import LeanBlsSimd.Spec.CubeFiber
import LeanBlsSimd.Spec.ScottCardinality
import Mathlib.RingTheory.RootsOfUnity.Complex

/-!
# Hasse bounds for E′ and Scott completeness

The curve's point count is p² + 1 plus a quadratic-character sum. An order-three character
expresses that sum as two Jacobi sums with coefficients of norm one. Each Jacobi sum has norm p,
giving the Hasse interval. The interval excludes multiples of r², so the generator of order r
generates all rational r-torsion and its Scott identity extends to every such point.
-/

namespace LeanBlsSimd
open EthCryptographySpecs.Bls
variable (F : Type*) [Field F] [Fintype F] [DecidableEq F]

noncomputable def quadraticCharComplex : MulChar F ℂ :=
  (quadraticChar F).ringHomComp (Int.castRingHom ℂ)

theorem quadraticCharComplex_apply (a : F) :
    quadraticCharComplex F a = (quadraticChar F a : ℂ) := rfl

theorem quadraticCharComplex_ne_one (hF : ringChar F ≠ 2) : quadraticCharComplex F ≠ 1 := by
  apply MulChar.ringHomComp_ne_one_iff (Int.cast_injective (α := ℂ)) |>.mpr
  exact quadraticChar_ne_one hF

theorem quadraticCharComplex_sq : quadraticCharComplex F ^ 2 = 1 := by
  rw [quadraticCharComplex, MulChar.ringHomComp_pow,
    (quadraticChar_isQuadratic F).sq_eq_one, MulChar.ringHomComp_one]

theorem orderOf_quadraticCharComplex (hF : ringChar F ≠ 2) :
    orderOf (quadraticCharComplex F) = 2 :=
  orderOf_eq_prime (quadraticCharComplex_sq F) (quadraticCharComplex_ne_one F hF)

theorem cubic_mul_quadratic_ne_one {χ : MulChar F ℂ} (hχ : orderOf χ = 3)
    (hF : ringChar F ≠ 2) : χ * quadraticCharComplex F ≠ 1 := by
  intro h
  have he : χ = (quadraticCharComplex F)⁻¹ := mul_eq_one_iff_eq_inv.mp h
  have ho := congrArg orderOf he
  rw [hχ, orderOf_inv, orderOf_quadraticCharComplex F hF] at ho
  contradiction

theorem exists_cubicChar : ∃ χ : MulChar Fp2Field ℂ, orderOf χ = 3 := by
  apply MulChar.exists_mulChar_orderOf Fp2Field _ (Complex.isPrimitiveRoot_exp 3 (by decide))
  rw [Fp2Field.card_eq]
  decide +kernel

theorem E'.hasse_bounds_of_character_sum_bound
    (h : ‖∑ x : Fp2Field, quadraticCharComplex Fp2Field (x ^ 3 + bTwist)‖ ≤
      2 * (Fp.modulus : ℝ)) :
    (Fp.modulus - 1) ^ 2 ≤ Nat.card E'.Point ∧
      Nat.card E'.Point ≤ (Fp.modulus + 1) ^ 2 := by
  have hc : (Nat.card E'.Point : ℂ) = (Fp.modulus : ℂ) ^ 2 + 1 +
      ∑ x : Fp2Field, quadraticCharComplex Fp2Field (x ^ 3 + bTwist) := by
    have hi := congrArg (fun x : ℤ => (x : ℂ)) E'.card_eq_character_sum
    push_cast at hi
    simpa only [quadraticCharComplex_apply] using hi
  have hr := congrArg Complex.re hc
  simp only [Complex.add_re, Complex.one_re,
    ← Complex.ofReal_natCast, ← Complex.ofReal_pow, Complex.ofReal_re] at hr
  have ha := (abs_le.mp ((Complex.abs_re_le_norm _).trans h))
  have hlo : ((Fp.modulus : ℝ) - 1) ^ 2 ≤ (Nat.card E'.Point : ℝ) := by
    nlinarith [ha.1]
  have hhi : (Nat.card E'.Point : ℝ) ≤ ((Fp.modulus : ℝ) + 1) ^ 2 := by
    nlinarith [ha.2]
  constructor
  · have hp : 1 ≤ Fp.modulus := by decide +kernel
    exact_mod_cast (show (((Fp.modulus - 1 : ℕ) : ℝ) ^ 2) ≤ (Nat.card E'.Point : ℝ) by
      rwa [Nat.cast_sub hp, Nat.cast_one])
  · exact_mod_cast hhi

theorem E'.character_sum_bound :
    ‖∑ x : Fp2Field, quadraticCharComplex Fp2Field (x ^ 3 + bTwist)‖ ≤
      2 * (Fp.modulus : ℝ) := by
  obtain ⟨χ, hχ⟩ := exists_cubicChar
  let φ := quadraticCharComplex Fp2Field
  have hφ : φ ≠ 1 := quadraticCharComplex_ne_one Fp2Field Fp2Field.char_ne_two
  have hχne : χ ≠ 1 := by
    intro h
    rw [h, orderOf_one] at hχ
    contradiction
  have hinv : orderOf χ⁻¹ = 3 := by rw [orderOf_inv, hχ]
  have hb : bTwist ≠ 0 := by decide +kernel
  rw [sum_cube_eq_jacobiSum χ φ hφ (fun t => card_cube_fiber hχ t) hb]
  calc
    _ ≤ ‖χ (-bTwist) * φ bTwist * jacobiSum χ φ‖ +
        ‖χ⁻¹ (-bTwist) * φ bTwist * jacobiSum χ⁻¹ φ‖ := norm_add_le _ _
    _ = Real.sqrt (Fintype.card Fp2Field) + Real.sqrt (Fintype.card Fp2Field) := by
      simp only [norm_mul, norm_mulChar_apply_eq_one _ (neg_ne_zero.mpr hb),
        norm_mulChar_apply_eq_one _ hb, one_mul]
      rw [norm_jacobiSum hχne hφ (cubic_mul_quadratic_ne_one Fp2Field hχ Fp2Field.char_ne_two),
        norm_jacobiSum (inv_ne_one.mpr hχne) hφ
          (cubic_mul_quadratic_ne_one Fp2Field hinv Fp2Field.char_ne_two)]
    _ = 2 * (Fp.modulus : ℝ) := by
      rw [Fp2Field.card_eq, Nat.cast_pow, Real.sqrt_sq (Nat.cast_nonneg _)]
      ring

theorem E'.hasse_bounds :
    (Fp.modulus - 1) ^ 2 ≤ Nat.card E'.Point ∧
      Nat.card E'.Point ≤ (Fp.modulus + 1) ^ 2 :=
  E'.hasse_bounds_of_character_sum_bound E'.character_sum_bound

theorem scott_complete : ScottComplete :=
  scottComplete_of_hasse_bounds E'.hasse_bounds.1 E'.hasse_bounds.2

end LeanBlsSimd
