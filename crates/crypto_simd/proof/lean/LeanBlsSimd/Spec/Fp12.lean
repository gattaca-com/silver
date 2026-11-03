import LeanBlsSimd.Spec.Fp12Field
import EthLib.Cryptography.Proofs.Bls.Fp12

/-! Exact field semantics for the executable Fp12 coordinates and total operations. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

namespace Fp12

open EthLib.Cryptography.Bls.Fp12

def toField : Fp12 ≃+* Fp12Field where
  toFun a := ⟨Fp6.toField a.c0, Fp6.toField a.c1⟩
  invFun x := ⟨Fp6.toField.symm x.re, Fp6.toField.symm x.im⟩
  left_inv a := by simp
  right_inv x := by simp
  map_add' a b := by
    apply QuadraticAlgebra.ext <;> exact Fp6.toField.map_add _ _
  map_mul' a b := by
    apply QuadraticAlgebra.ext
    · change Fp6.toField (a.c0 * b.c0 + (a.c1 * b.c1).mulByV) =
        Fp6.toField a.c0 * Fp6.toField b.c0 +
          Fp6Field.v * Fp6.toField a.c1 * Fp6.toField b.c1
      simp only [map_add, map_mul, Fp6.toField_mulByV]
      ring
    · change Fp6.toField ((a.c0 + a.c1) * (b.c0 + b.c1) - a.c0 * b.c0 - a.c1 * b.c1) =
        Fp6.toField a.c0 * Fp6.toField b.c1 + Fp6.toField a.c1 * Fp6.toField b.c0 +
          0 * Fp6.toField a.c1 * Fp6.toField b.c1
      simp only [map_add, map_mul, Fp6.toField_sub]
      ring

@[simp] theorem toField_mk (a b : Fp6) :
    toField ⟨a, b⟩ = ⟨Fp6.toField a, Fp6.toField b⟩ := rfl

@[simp] theorem re_toField (a : Fp12) : (toField a).re = Fp6.toField a.c0 := rfl

@[simp] theorem im_toField (a : Fp12) : (toField a).im = Fp6.toField a.c1 := rfl

@[simp] theorem toField_zero : toField zero = 0 := map_zero toField

@[simp] theorem toField_one : toField one = 1 := map_one toField

@[simp] theorem toField_neg (a : Fp12) : toField (-a) = -toField a := map_neg toField a

@[simp] theorem toField_sub (a b : Fp12) : toField (a - b) = toField a - toField b :=
  map_sub toField a b

theorem toField_mul (a b : Fp12) : toField (mul a b) = toField a * toField b :=
  toField.map_mul a b

@[simp] theorem toField_square (a : Fp12) : toField a.square = toField a ^ 2 := by
  rw [square, map_mul, pow_two]

theorem toField_mk_zero (a : Fp6) :
    toField ⟨a, Fp6.zero⟩ = algebraMap Fp6Field Fp12Field (Fp6.toField a) := by
  apply QuadraticAlgebra.ext
  · rfl
  · exact Fp6.toField_zero

theorem toField_w : toField ⟨Fp6.zero, Fp6.one⟩ = Fp12Field.w := by
  exact QuadraticAlgebra.ext Fp6.toField_zero Fp6.toField_one

theorem toField_inverse (a : Fp12) : toField a.inverse = (toField a)⁻¹ := map_inv₀ toField a

theorem toField_conjugate (a : Fp12) : toField a.conjugate = star (toField a) := by
  apply QuadraticAlgebra.ext
  · simp [conjugate, QuadraticAlgebra.re_star]
  · simp [conjugate, QuadraticAlgebra.im_star]

@[simp] theorem toField_powNat (a : Fp12) (n : ℕ) :
    toField (powNat a n) = toField a ^ n := by
  rw [EthLib.Cryptography.Bls.Fp12.powNat_eq_pow, map_pow]

theorem beq_iff (a b : Fp12) : a.beq b = true ↔ toField a = toField b := by
  rw [EthLib.Cryptography.Bls.Fp12.beq_iff_eq, toField.injective.eq_iff]

theorem isOne_iff (a : Fp12) : a.isOne = true ↔ toField a = 1 := by
  rw [EthLib.Cryptography.Bls.Fp12.isOne_iff, ← map_one toField, toField.injective.eq_iff]

end Fp12

end

end LeanBlsSimd
