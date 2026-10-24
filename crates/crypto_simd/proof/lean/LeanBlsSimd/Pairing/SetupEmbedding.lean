import LeanBlsSimd.Pairing.MillerSpec

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

def setupPoint (pair : Fin 2) : G2 :=
  if pair = 0 then Kzg.SetupPoints.g2Point64 else G2.neg Kzg.SetupPoints.g2Point0

private theorem fp2_mul_one (x : Fp2) : x * Fp2.one = x := by
  apply Fp2.toField.injective
  simp only [map_mul, Fp2.toField_one, _root_.mul_one]

private theorem inverse_one : Fp2.one.inverse = Fp2.one := by
  apply Fp2.toField.injective
  simp only [Fp2.toField_inverse, Fp2.toField_one, inv_one]

theorem g2_affine_of_z_one (q : G2) (hq : q.z = Fp2.one) : q.toAffine = (q.x, q.y) := by
  simp only [G2.toAffine, hq, show Fp2.one.isZero = false from by decide +kernel,
    Bool.false_eq_true, if_false, inverse_one, fp2_mul_one]

theorem ofG2_untwist (q : G2) (hq : q.z = Fp2.one) :
    Embedded.ofG2 q = untwist (q.x, q.y) := by
  have hi : q.isInfinity = false := by
    simp only [G2.isInfinity, hq]
    decide +kernel
  simp only [Embedded.ofG2, hi, Bool.false_eq_true, if_false, g2_affine_of_z_one q hq]
  rfl

theorem setup_z (pair : Fin 2) : (setupPoint pair).z = Fp2.one := by
  unfold setupPoint
  split_ifs <;> rfl

theorem setup_xy (pair : Fin 2) : ((setupPoint pair).x, (setupPoint pair).y) = fixedPoint pair := by
  unfold setupPoint fixedPoint
  split_ifs <;> rfl

theorem setup_untwist (pair : Fin 2) :
    Embedded.ofG2 (setupPoint pair) = untwist (fixedPoint pair) := by
  rw [ofG2_untwist _ (setup_z pair), setup_xy]

theorem setup_finite (pair : Fin 2) : (setupPoint pair).isInfinity = false := by
  simp only [G2.isInfinity, setup_z]
  decide +kernel

end

end LeanBlsSimd.Pairing
