import LeanBlsSimd.Pairing.MillerSpec
import LeanBlsSimd.Pairing.LineFactors

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

/-- Homogeneous line coordinates differ from the normalized line by the common scale. -/
theorem scaled_line_field (step : Fin 68) (pair : Fin 2) (u xp yp : Fp2) :
    Fp12.toField (Portable.Fp12.line u
      (coefficient step pair 0 * (u * xp)) (coefficient step pair 1 * (u * yp))) =
      fp2Embed (Fp2.toField u) * Fp12.toField (FixedTable.normalizedLine step pair xp yp) := by
  simp only [FixedTable.normalizedLine, line_field, map_mul, Fp2.toField_one, map_one]
  ring

theorem scaled_line_final_eq (step : Fin 68) (pair : Fin 2) (u xp yp : Fp2)
    (hu : Fp2.toField u ≠ 0) :
    FinalEq (Portable.Fp12.line u
      (coefficient step pair 0 * (u * xp)) (coefficient step pair 1 * (u * yp)))
      (FixedTable.normalizedLine step pair xp yp) := by
  rw [FinalEq, scaled_line_field, mul_pow,
    period_four_final_power (fp2_period_four _ hu), one_mul]

def g1Factors (points : Fin 2 → G1) : Factors := fun pair =>
  ![(points pair).z * (points pair).z * (points pair).z,
    (points pair).x * (points pair).z, (points pair).y]

private theorem ofFp_mul (a b : Fp) : Fp2.ofFp (a * b) = Fp2.ofFp a * Fp2.ofFp b := by
  apply Fp2.toField.injective
  simp only [map_mul, Fp2.toField_ofFp]
  exact map_mul (algebraMap (ZMod Fp.modulus) Fp2Field) a b

theorem g1_scale_relations (p : G1) (hp : p.isInfinity = false) :
    let u := p.z * p.z * p.z
    Fp2.toField (Fp2.ofFp u) ≠ 0 ∧
      Fp2.ofFp (p.x * p.z) = Fp2.ofFp u * Fp2.ofFp p.toAffine.1 ∧
      Fp2.ofFp p.y = Fp2.ofFp u * Fp2.ofFp p.toAffine.2 := by
  have hz : (p.z : ZMod Fp.modulus) ≠ 0 := by
    intro hz
    have hi : p.isInfinity = true := by simp [G1.isInfinity, Fp.isZero, hz]
    rw [hp] at hi
    contradiction
  let x : ZMod Fp.modulus := p.x
  let y : ZMod Fp.modulus := p.y
  let z : ZMod Fp.modulus := p.z
  have hzz : z ≠ 0 := hz
  have hx : p.x * p.z = (p.z * p.z * p.z) * p.toAffine.1 := by
    simp only [G1.toAffine, show p.z.isZero = false from hp, Bool.false_eq_true, if_false,
      Fp.inverse_eq_inv]
    change x * z = (z * z * z) * (x * (z⁻¹ * z⁻¹))
    field_simp [hzz]
  have hy : p.y = (p.z * p.z * p.z) * p.toAffine.2 := by
    simp only [G1.toAffine, show p.z.isZero = false from hp, Bool.false_eq_true, if_false,
      Fp.inverse_eq_inv]
    change y = (z * z * z) * (y * (z⁻¹ * z⁻¹ * z⁻¹))
    field_simp [hzz]
  refine ⟨?_, ?_, ?_⟩
  · rw [Fp2.toField_ofFp]
    change (algebraMap (ZMod Fp.modulus) Fp2Field) (z * z * z) ≠ 0
    exact (map_ne_zero (algebraMap (ZMod Fp.modulus) Fp2Field)).mpr
      (mul_ne_zero (mul_ne_zero hz hz) hz)
  · rw [← ofFp_mul, ← hx]
  · rw [← ofFp_mul, ← hy]

theorem g1_line_final_eq (step : Fin 68) (pair : Fin 2) (points : Fin 2 → G1)
    (hp : (points pair).isInfinity = false) :
    FinalEq (factorLine step pair (g1Factors points))
      (FixedTable.normalizedLine step pair (Fp2.ofFp (points pair).toAffine.1)
        (Fp2.ofFp (points pair).toAffine.2)) := by
  obtain ⟨hu, hx, hy⟩ := g1_scale_relations (points pair) hp
  change FinalEq (Portable.Fp12.line
    (Fp2.ofFp ((points pair).z * (points pair).z * (points pair).z))
    (coefficient step pair 0 * Fp2.ofFp ((points pair).x * (points pair).z))
    (coefficient step pair 1 * Fp2.ofFp (points pair).y)) _
  rw [hx, hy]
  exact scaled_line_final_eq step pair _ _ _ hu

theorem ofG1_evaluationPoint (p : G1) (hp : p.isInfinity = false) :
    Embedded.ofG1 p = evaluationPoint (Fp2.ofFp p.toAffine.1) (Fp2.ofFp p.toAffine.2) := by
  simp only [Embedded.ofG1, hp, Bool.false_eq_true, if_false]
  rfl

end

end LeanBlsSimd.Pairing
