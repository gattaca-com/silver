import LeanBlsSimd.Spec.Fp6Inverse

/-! The remaining executable operations and cardinality of the cubic field. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

namespace Fp6

open EthLib.Cryptography.Bls.Fp6

open Fp6Field

@[simp] theorem toField_neg (a : Fp6) : toField (-a) = -toField a := by
  change assemble (Fp2.toField (-a.c0)) (Fp2.toField (-a.c1)) (Fp2.toField (-a.c2)) =
    -assemble (Fp2.toField a.c0) (Fp2.toField a.c1) (Fp2.toField a.c2)
  simp only [Fp2.toField_neg, assemble, map_neg]
  ring

@[simp] theorem toField_sub (a b : Fp6) : toField (a - b) = toField a - toField b := by
  change assemble (Fp2.toField (a.c0 - b.c0)) (Fp2.toField (a.c1 - b.c1))
    (Fp2.toField (a.c2 - b.c2)) =
      assemble (Fp2.toField a.c0) (Fp2.toField a.c1) (Fp2.toField a.c2) -
        assemble (Fp2.toField b.c0) (Fp2.toField b.c1) (Fp2.toField b.c2)
  simp only [Fp2.toField_sub, assemble, map_sub]
  ring

@[simp] theorem toField_div (a b : Fp6) : toField (a / b) = toField a / toField b := by
  change toField (a * b.inverse) = _
  rw [map_mul, toField_inverse, div_eq_mul_inv]

@[simp] theorem toField_v : toField Fp6.v = Fp6Field.v := by
  change assemble 0 1 0 = _
  simp [assemble]

@[simp] theorem toField_ofFp2 (a : Fp2) : toField (ofFp2 a) = of (Fp2.toField a) := by
  change assemble (Fp2.toField a) 0 0 = _
  simp [assemble]

@[simp] theorem toField_mulByV (a : Fp6) :
    toField a.mulByV = toField a * Fp6Field.v := by
  change assemble (Fp2.toField a.c2.mulByOnePlusI) (Fp2.toField a.c0)
    (Fp2.toField a.c1) = _
  rw [Fp2.toField_mulByOnePlusI]
  change assemble (Fp2.toField a.c2 * xi) (Fp2.toField a.c0) (Fp2.toField a.c1) = _
  simp only [assemble, map_mul]
  change _ = (of (Fp2.toField a.c0) + of (Fp2.toField a.c1) * Fp6Field.v +
    of (Fp2.toField a.c2) * Fp6Field.v ^ 2) * Fp6Field.v
  linear_combination -of (Fp2.toField a.c2) * v_cube

theorem isZero_iff (a : Fp6) : a.isZero = true ↔ toField a = 0 := by
  change _ ↔ assemble (Fp2.toField a.c0) (Fp2.toField a.c1) (Fp2.toField a.c2) = 0
  simp [isZero, Bool.and_eq_true, Fp2.isZero_iff, assemble_eq_zero_iff, and_assoc]

theorem beq_iff (a b : Fp6) : a.beq b = true ↔ toField a = toField b := by
  rw [toField.injective.eq_iff]
  cases a
  cases b
  simp [beq, Bool.and_eq_true, Fp2.beq_iff, Fp2.toField.injective.eq_iff, and_assoc]

end Fp6

instance Fp6Field.instFintype : Fintype Fp6Field :=
  Fintype.ofEquiv (Fin 3 → Fp2Field) Fp6Field.basis.equivFun.toEquiv.symm

theorem Fp6Field.card_eq : Fintype.card Fp6Field = Fp.modulus ^ 6 := by
  rw [Fintype.card_congr Fp6Field.basis.equivFun.toEquiv]
  simp [Fp2Field.card_eq, ← pow_mul]

instance Fp6Field.instCharP : CharP Fp6Field Fp.modulus :=
  charP_of_injective_algebraMap (algebraMap Fp2Field Fp6Field).injective Fp.modulus

end

end LeanBlsSimd
