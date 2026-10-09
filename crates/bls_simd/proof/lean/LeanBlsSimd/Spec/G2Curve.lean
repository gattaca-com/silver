import LeanBlsSimd.Spec.Fp2
import EthCryptographySpecs.Bls.G2
import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point

/-!
# E′ as a Mathlib curve

E′ : y² = x³ + b′ over `Fp2Field`, with b′ = 4(1 + i), is the curve of the spec's `G2`. Its
discriminant −432·b′² is nonzero, so every solution of the equation is a nonsingular point, and
`E'.Point` carries Mathlib's group law.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls WeierstrassCurve

def bTwist : Fp2Field := ⟨4, 4⟩

theorem Fp2.toField_bTwist : Fp2.toField G2.bTwist = bTwist := rfl

def E' : Affine Fp2Field := { a₁ := 0, a₂ := 0, a₃ := 0, a₄ := 0, a₆ := bTwist }

namespace E'

@[simp] theorem a₁_eq : E'.a₁ = 0 := rfl
@[simp] theorem a₂_eq : E'.a₂ = 0 := rfl
@[simp] theorem a₃_eq : E'.a₃ = 0 := rfl
@[simp] theorem a₄_eq : E'.a₄ = 0 := rfl
@[simp] theorem a₆_eq : E'.a₆ = bTwist := rfl

theorem Δ_eq : E'.Δ = -432 * bTwist ^ 2 := by
  simp only [Δ, b₂, b₄, b₆, b₈, a₁_eq, a₂_eq, a₃_eq, a₄_eq, a₆_eq]
  ring

theorem Δ_ne_zero : E'.Δ ≠ 0 := by
  rw [Δ_eq]
  decide +kernel

instance instIsElliptic : E'.IsElliptic := ⟨isUnit_iff_ne_zero.mpr Δ_ne_zero⟩

theorem equation_iff (x y : Fp2Field) : E'.Equation x y ↔ y ^ 2 = x ^ 3 + bTwist := by
  rw [Affine.equation_iff]
  simp

theorem nonsingular_iff (x y : Fp2Field) : E'.Nonsingular x y ↔ y ^ 2 = x ^ 3 + bTwist := by
  rw [← Affine.equation_iff_nonsingular_of_Δ_ne_zero Δ_ne_zero, equation_iff]

@[simp] theorem negY_eq (x y : Fp2Field) : E'.negY x y = -y := by
  simp

/-- The spec's G2 generator, whose `z` is one, lies on E′. -/
theorem equation_generator :
    E'.Equation (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) := by
  rw [equation_iff]
  decide +kernel

end E'

end LeanBlsSimd
