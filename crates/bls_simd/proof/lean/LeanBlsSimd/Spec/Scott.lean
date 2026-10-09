import LeanBlsSimd.Spec.G2Curve
import Mathlib.Tactic.Module

/-!
# Scott soundness on E′

ψ(x, y) = (c_x · x̄, c_y · ȳ), with c_x = `psiX` · i and c_y = `psiY`, is an additive map of E′'s
points. If ψ(P) = [z]P then [r]P = O, for every point P of E′ over Fp2:

1. ψ²(x, y) = (N(c_x) x, N(c_y) y) = (ζx, −y) = −φ(P), where φ(x, y) = (ζx, y) and ζ = `beta`.
2. So φ(P) = [−z²]P, and φ²(P) = ψ⁴(P) = [z⁴]P.
3. P, φ(P) and φ²(P) lie on the line Y = y, so they sum to O. At x = 0 the three coincide, and
   the line is the tangent at P.
4. Hence [z⁴ − z² + 1]P = O, and z⁴ − z² + 1 = r.

Only z² and z⁴ enter, so the theorem holds for −z as well. The converse, `ScottComplete`, is
not proved here.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls WeierstrassCurve Affine

local notation "ω" => (QuadraticAlgebra.omega : Fp2Field)

def cx : Fp2Field := psiX * ω

def cy : Fp2Field := psiY.1 + psiY.2 * ω

theorem cx_cube : cx ^ 3 = ω := psiX_cube Fp2Field.natCast_modulus Fp2Field.omega_sq

theorem cy_sq : cy ^ 2 = ω := psiY_sq Fp2Field.natCast_modulus Fp2Field.omega_sq

theorem Fp2Field.omega_ne_zero : ω ≠ 0 := by
  decide +kernel

theorem cx_ne_zero : cx ≠ 0 := fun h =>
  Fp2Field.omega_ne_zero (by rw [← cx_cube, h, zero_pow three_ne_zero])

theorem cy_ne_zero : cy ≠ 0 := fun h =>
  Fp2Field.omega_ne_zero (by rw [← cy_sq, h, zero_pow two_ne_zero])

theorem omega_mul_star_bTwist : ω * star bTwist = bTwist := by
  decide +kernel

/-! ## ψ on points -/

theorem equation_psi {x y : Fp2Field} (h : E'.Equation x y) :
    E'.Equation (cx * star x) (cy * star y) := by
  rw [E'.equation_iff] at h ⊢
  have hs := congrArg star h
  rw [star_pow, star_add, star_pow] at hs
  linear_combination star y ^ 2 * cy_sq - star x ^ 3 * cx_cube + ω * hs + omega_mul_star_bTwist

theorem nonsingular_psi {x y : Fp2Field} (h : E'.Nonsingular x y) :
    E'.Nonsingular (cx * star x) (cy * star y) := by
  rw [← equation_iff_nonsingular] at h ⊢
  exact equation_psi h

theorem slope_psi (x₁ x₂ y₁ y₂ : Fp2Field) :
    E'.slope (cx * star x₁) (cx * star x₂) (cy * star y₁) (cy * star y₂) =
      cy / cx * star (E'.slope x₁ x₂ y₁ y₂) := by
  have hx : cx * star x₁ = cx * star x₂ ↔ x₁ = x₂ := by
    rw [mul_right_inj' cx_ne_zero, star_inj]
  have hy : cy * star y₁ = -(cy * star y₂) ↔ y₁ = -y₂ := by
    rw [← mul_neg, ← star_neg, mul_right_inj' cy_ne_zero, star_inj]
  have hcx : cx ^ 2 / cy = cy / cx := by
    rw [div_eq_div_iff cy_ne_zero cx_ne_zero]
    linear_combination cx_cube - cy_sq
  simp only [slope, E'.negY_eq, E'.a₁_eq, E'.a₂_eq, E'.a₄_eq, hx, hy, mul_zero, zero_mul,
    add_zero, sub_zero]
  split_ifs
  · simp
  · rw [← hcx, star_div₀, star_mul', star_pow, star_ofNat, star_sub, star_neg, div_mul_div_comm]
    congr 1 <;> ring
  · rw [star_div₀, star_sub, star_sub, div_mul_div_comm]
    congr 1 <;> ring

theorem addX_psi (x₁ x₂ ℓ : Fp2Field) :
    E'.addX (cx * star x₁) (cx * star x₂) (cy / cx * star ℓ) = cx * star (E'.addX x₁ x₂ ℓ) := by
  have h : (cy / cx) ^ 2 = cx := by
    rw [div_pow, div_eq_iff (pow_ne_zero 2 cx_ne_zero)]
    linear_combination cy_sq - cx_cube
  simp only [addX, E'.a₁_eq, E'.a₂_eq, star_sub, star_pow, mul_pow, h, zero_mul, add_zero,
    sub_zero]
  ring

theorem addY_psi (x₁ x₂ y₁ ℓ : Fp2Field) :
    E'.addY (cx * star x₁) (cx * star x₂) (cy * star y₁) (cy / cx * star ℓ) =
      cy * star (E'.addY x₁ x₂ y₁ ℓ) := by
  have h : cy / cx * cx = cy := div_mul_cancel₀ cy cx_ne_zero
  rw [addY, negAddY, addX_psi, addY, negAddY, E'.negY_eq, E'.negY_eq]
  simp only [star_neg, star_add, star_mul', star_sub]
  linear_combination (-(star ℓ) * (star (E'.addX x₁ x₂ ℓ) - star x₁)) * h

def psi : E'.Point →+ E'.Point where
  toFun P := match P with
    | 0 => 0
    | .some x y h => .some (cx * star x) (cy * star y) (nonsingular_psi h)
  map_zero' := rfl
  map_add' := by
    rintro (_ | ⟨x₁, y₁, h₁⟩) (_ | ⟨x₂, y₂, h₂⟩)
    any_goals rfl
    have hx : cx * star x₁ = cx * star x₂ ↔ x₁ = x₂ := by
      rw [mul_right_inj' cx_ne_zero, star_inj]
    have hy : cy * star y₁ = E'.negY (cx * star x₂) (cy * star y₂) ↔ y₁ = E'.negY x₂ y₂ := by
      rw [E'.negY_eq, E'.negY_eq, ← mul_neg, ← star_neg, mul_right_inj' cy_ne_zero, star_inj]
    by_cases hxy : x₁ = x₂ ∧ y₁ = E'.negY x₂ y₂
    · rw [Point.add_of_Y_eq hxy.left hxy.right,
        Point.add_of_Y_eq (hx.mpr hxy.left) (hy.mpr hxy.right)]
    · rw [Point.add_some hxy, Point.add_some (fun h => hxy ⟨hx.mp h.1, hy.mp h.2⟩)]
      simp only [slope_psi, addX_psi, addY_psi]

/-! ## ψ² = −φ -/

theorem norm_cx : QuadraticAlgebra.norm cx = beta := by
  decide +kernel

theorem norm_cy : QuadraticAlgebra.norm cy = -1 := by
  decide +kernel

theorem cx_mul_star : cx * star cx = beta := by
  rw [← QuadraticAlgebra.algebraMap_norm_eq_mul_star, norm_cx, map_natCast]

theorem cy_mul_star : cy * star cy = -1 := by
  rw [← QuadraticAlgebra.algebraMap_norm_eq_mul_star, norm_cy, map_neg, map_one]

theorem zeta_cube : (beta : Fp2Field) ^ 3 = 1 := by
  rw [← map_natCast (algebraMap (ZMod Fp.modulus) Fp2Field), ← map_pow, beta_cube, map_one]

theorem zeta_ne_one : (beta : Fp2Field) ≠ 1 := by
  have h := (algebraMap (ZMod Fp.modulus) Fp2Field).injective.ne beta_ne_one
  rwa [map_natCast, map_one] at h

theorem zeta_sq_add_zeta_add_one : (beta : Fp2Field) ^ 2 + beta + 1 = 0 := by
  have h : ((beta : Fp2Field) - 1) * ((beta : Fp2Field) ^ 2 + beta + 1) = 0 := by
    linear_combination zeta_cube
  exact (mul_eq_zero.mp h).resolve_left (sub_ne_zero.mpr zeta_ne_one)

theorem nonsingular_phi {x y : Fp2Field} (h : E'.Nonsingular x y) :
    E'.Nonsingular (beta * x) y := by
  rw [E'.nonsingular_iff] at h ⊢
  linear_combination h - x ^ 3 * zeta_cube

/-- φ(x, y) = (ζx, y). Its additivity is never needed: φ² = ψ⁴ pointwise (`phi_phi`). -/
def phi : E'.Point → E'.Point
  | 0 => 0
  | .some x y h => .some (beta * x) y (nonsingular_phi h)

theorem psi_psi (P : E'.Point) : psi (psi P) = -phi P := by
  rcases P with _ | ⟨x, y, h⟩
  · rfl
  · simp only [psi, phi, AddMonoidHom.coe_mk, ZeroHom.coe_mk, Point.neg_some, Point.some.injEq,
      E'.negY_eq]
    constructor
    · rw [star_mul', star_star, ← mul_assoc, cx_mul_star]
    · rw [star_mul', star_star, ← mul_assoc, cy_mul_star, neg_one_mul]

theorem phi_phi (P : E'.Point) : phi (phi P) = psi (psi (psi (psi P))) := by
  rw [psi_psi P, map_neg, map_neg, psi_psi, neg_neg]

/-! ## The line Y = y -/

theorem add_phi_add_phi_phi (P : E'.Point) : P + phi P + phi (phi P) = 0 := by
  rcases P with _ | ⟨x, y, h⟩
  · rfl
  by_cases hx : x = 0
  · subst hx
    have hφ : phi (.some 0 y h) = .some 0 y h := by
      simp only [phi, mul_zero]
    have hy : y ≠ E'.negY 0 y := by
      rw [E'.negY_eq]
      intro hy
      have hb : bTwist = 0 := by
        have h2 : (2 : Fp2Field) * y = 0 := by linear_combination hy
        have hy0 : y = 0 := (mul_eq_zero.mp h2).resolve_left (by decide +kernel)
        rw [E'.nonsingular_iff, hy0] at h
        linear_combination -h
      exact absurd hb (by decide +kernel)
    have h2P : Point.some 0 y h + Point.some 0 y h = -Point.some 0 y h := by
      rw [Point.add_self_of_Y_ne hy, Point.neg_some, Point.some.injEq]
      simp [slope_of_Y_ne rfl hy]
    rw [hφ, hφ, h2P, neg_add_cancel]
  · have hxζ : x ≠ beta * x := by
      intro hxζ
      apply hx
      have h1 : ((beta : Fp2Field) - 1) * x = 0 := by linear_combination -hxζ
      exact (mul_eq_zero.mp h1).resolve_left (sub_ne_zero.mpr zeta_ne_one)
    have hs : Point.some x y h + phi (.some x y h) = -phi (phi (.some x y h)) := by
      simp only [phi]
      rw [Point.add_of_X_ne hxζ, Point.neg_some, Point.some.injEq]
      simp only [slope_of_X_ne hxζ, sub_self, zero_div, addX, addY, negAddY, E'.negY_eq,
        E'.a₁_eq, E'.a₂_eq, zero_mul, add_zero, sub_zero, zero_add]
      constructor
      · linear_combination (-x) * zeta_sq_add_zeta_add_one
      · trivial
    rw [hs, neg_add_cancel]

/-! ## Soundness -/

theorem torsion_of_psi_eq_zsmul (k : ℤ) (P : E'.Point) (h : psi P = k • P) :
    (k ^ 4 - k ^ 2 + 1) • P = 0 := by
  have h2 : psi (psi P) = (k * k) • P := by rw [h, map_zsmul, h, smul_smul]
  have h4 : psi (psi (psi (psi P))) = (k * k * (k * k)) • P := by
    rw [h2, map_zsmul, map_zsmul, h2, smul_smul]
  have hφ : phi P = -((k * k) • P) := by rw [← h2, psi_psi, neg_neg]
  have hl := add_phi_add_phi_phi P
  rw [phi_phi, h4, hφ] at hl
  calc (k ^ 4 - k ^ 2 + 1) • P = P + -((k * k) • P) + (k * k * (k * k)) • P := by module
    _ = 0 := hl

theorem scott_sound (P : E'.Point) (h : psi P = z • P) : Fr.modulus • P = 0 := by
  rw [← natCast_zsmul, r_eq]
  exact torsion_of_psi_eq_zsmul z P h

/-- Scott completeness, unproved: it serves only as a hypothesis.

No theorem here fixes the sign of `cy`: `cy_sq` and `norm_cy` hold for −cy too, and flipping
the signs of both `cy` and `z` keeps this statement true. `PSI_Y_MONT_eq` and `p_eq` pin each
of them, and `psi_generator` checks the pair on the spec's generator. -/
def ScottComplete : Prop := ∀ P : E'.Point, Fr.modulus • P = 0 → psi P = z • P

end LeanBlsSimd
