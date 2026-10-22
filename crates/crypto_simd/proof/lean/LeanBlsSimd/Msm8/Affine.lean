import LeanBlsSimd.Model.Msm8
import LeanBlsSimd.Proofs.G1x8
import LeanBlsSimd.Spec.G1Curve

namespace LeanBlsSimd.Msm8

open EthCryptographySpecs.Bls


theorem affineAdd_correct (xa ya xb yb inverse : Fp8) (l : Fin 8)
    (x₁ y₁ x₂ y₂ : ZMod Fp.modulus)
    (hxa : xa.Holds l x₁) (hya : ya.Holds l y₁)
    (hxb : xb.Holds l x₂) (hyb : yb.Holds l y₂)
    (hinv : inverse.Holds l (x₂ - x₁)⁻¹) :
    let slope := (y₂ - y₁) * (x₂ - x₁)⁻¹
    let x₃ := slope ^ 2 - x₁ - x₂
    (affineAdd xa ya xb yb inverse).1.Holds l x₃ ∧
      (affineAdd xa ya xb yb inverse).2.Holds l (slope * (x₁ - x₃) - y₁) := by
  have hdy := (hyb.lazyRep.sub_raw hya.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)).normalise (by decide) (by decide)
  have hs := hdy.mul hinv.boundRep (by decide)
  have hsq := hs.square
  have hx := ((hsq.lazyRep.sub_raw hxa.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)).sub_raw hxb.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)).reduced_from_8p (by decide) (by decide)
  have hdx := (hxa.lazyRep.sub_raw hx.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)).normalise (by decide) (by decide)
  have hp := hs.boundRep.mul hdx (by decide)
  have hy := (hp.lazyRep.sub_raw hya.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)).reduced_from_4p (by decide) (by decide)
  exact ⟨hx, hy⟩

private theorem affine_add_coordinates (x₁ y₁ x₂ y₂ : ZMod Fp.modulus) (hx : x₁ ≠ x₂) :
    let slope := (y₂ - y₁) * (x₂ - x₁)⁻¹
    G1Spec.E.addX x₁ x₂ (G1Spec.E.slope x₁ x₂ y₁ y₂) = slope ^ 2 - x₁ - x₂ ∧
      G1Spec.E.addY x₁ x₂ y₁ (G1Spec.E.slope x₁ x₂ y₁ y₂) =
        slope * (x₁ - (slope ^ 2 - x₁ - x₂)) - y₁ := by
  have hs : G1Spec.E.slope x₁ x₂ y₁ y₂ = (y₂ - y₁) * (x₂ - x₁)⁻¹ := by
    rw [WeierstrassCurve.Affine.slope_of_X_ne hx]
    rw [← neg_sub y₂ y₁, ← neg_sub x₂ x₁, neg_div_neg_eq, div_eq_mul_inv]
  constructor
  · simp [hs, WeierstrassCurve.Affine.addX]
  · simp only [hs, WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
      G1Spec.negY_eq, WeierstrassCurve.Affine.addX, G1Spec.a₁_eq, G1Spec.a₂_eq,
      zero_mul, add_zero, sub_zero]
    ring

theorem affine_sum_nonsingular {x₁ y₁ x₂ y₂ : ZMod Fp.modulus}
    (h₁ : G1Spec.E.Nonsingular x₁ y₁) (h₂ : G1Spec.E.Nonsingular x₂ y₂)
    (hx : x₁ ≠ x₂) :
    let slope := (y₂ - y₁) * (x₂ - x₁)⁻¹
    G1Spec.E.Nonsingular (slope ^ 2 - x₁ - x₂)
      (slope * (x₁ - (slope ^ 2 - x₁ - x₂)) - y₁) := by
  have h := WeierstrassCurve.Affine.nonsingular_add h₁ h₂ (fun h => hx h.1)
  obtain ⟨hx₃, hy₃⟩ := affine_add_coordinates x₁ y₁ x₂ y₂ hx
  rwa [hx₃, hy₃] at h

theorem affine_sum_point {x₁ y₁ x₂ y₂ : ZMod Fp.modulus}
    (h₁ : G1Spec.E.Nonsingular x₁ y₁) (h₂ : G1Spec.E.Nonsingular x₂ y₂)
    (hx : x₁ ≠ x₂) :
    WeierstrassCurve.Affine.Point.some x₁ y₁ h₁ + .some x₂ y₂ h₂ =
      .some _ _ (affine_sum_nonsingular h₁ h₂ hx) := by
  rw [WeierstrassCurve.Affine.Point.add_of_X_ne hx]
  obtain ⟨hx₃, hy₃⟩ := affine_add_coordinates x₁ y₁ x₂ y₂ hx
  simp only [hx₃, hy₃]

end LeanBlsSimd.Msm8
