import LeanBlsSimd.Constants
import Mathlib.Algebra.QuadraticAlgebra.Basic

/-!
# The spec's `Fp2` as a field

The spec's `Fp2` provides arithmetic operations but no ring structure. Fp2
arguments therefore run in `Fp2Field`, Mathlib's `QuadraticAlgebra (ZMod Fp.modulus) (-1) 0`,
and cross over through `Fp2.toField`. Zero, one, addition, negation and subtraction agree
definitionally. Multiplication agrees only propositionally: the spec computes
re·re′ − im·im′, `QuadraticAlgebra` computes re·re′ + (−1)·im·im′.

`Fp2.toField` is a `RingEquiv` built from the spec's own `+` and `*`. The spec's `Fp2` has no
`Zero` or `One` instance and no additive group structure, so Mathlib's `map_zero`, `map_one`,
`map_neg` and `map_sub` do not apply to it; `Fp2.toField_zero`, `Fp2.toField_one`,
`Fp2.toField_neg` and `Fp2.toField_sub` state them instead. The spec's `Fp2.powNat` is
`partial`, so no proof can unfold it.
-/

namespace LeanBlsSimd

open EthCryptographySpecs EthCryptographySpecs.Bls

abbrev Fp2Field : Type := QuadraticAlgebra (ZMod Fp.modulus) (-1) 0

/-- X² + 1 has no root in Fp, which is the hypothesis of `Field Fp2Field`. -/
instance instFactNegOneNotSquare : Fact (∀ r : ZMod Fp.modulus, r ^ 2 ≠ -1 + 0 * r) :=
  ⟨fun r => by simpa using neg_one_not_square r⟩

theorem Fp2Field.omega_sq : (QuadraticAlgebra.omega : Fp2Field) ^ 2 = -1 := by
  rw [sq, QuadraticAlgebra.omega_mul_omega_eq_mk]
  ext <;> simp [QuadraticAlgebra.re_one, QuadraticAlgebra.im_one]

theorem Fp2Field.natCast_modulus : (Fp.modulus : Fp2Field) = 0 := by
  rw [← map_natCast (algebraMap (ZMod Fp.modulus) Fp2Field), ZMod.natCast_self, map_zero]

/-- Upstream states this as `G1.isZero_iff`, in a module that also brings the curve imports. -/
theorem Fp.isZero_iff {a : Fp} : a.isZero = true ↔ (a : ZMod Fp.modulus) = 0 := by
  rw [Fp.isZero, beq_iff_eq]
  exact ZMod.val_eq_zero (n := Fp.modulus) a

/-- Upstream states this as `G1.beq_iff`, in a module that also brings the curve imports. -/
theorem Fp.beq_iff {a b : Fp} : a.beq b = true ↔ (a : ZMod Fp.modulus) = b := by
  rw [Fp.beq, beq_iff_eq]
  exact ⟨fun h => Fin.ext h, fun h => congrArg Fin.val h⟩

private theorem re_mul_eq (a b c d : ZMod Fp.modulus) : a * c - b * d = a * c + -1 * b * d := by
  ring

private theorem im_mul_eq (a b c d : ZMod Fp.modulus) :
    a * d + b * c = a * d + b * c + 0 * b * d := by
  ring

def Fp2.toField : Fp2 ≃+* Fp2Field where
  toFun x := ⟨x.c0, x.c1⟩
  invFun z := ⟨z.re, z.im⟩
  left_inv _ := rfl
  right_inv _ := rfl
  map_mul' x y :=
    QuadraticAlgebra.ext (re_mul_eq x.c0 x.c1 y.c0 y.c1) (im_mul_eq x.c0 x.c1 y.c0 y.c1)
  map_add' _ _ := rfl

namespace Fp2

@[simp] theorem re_toField (x : Fp2) : (toField x).re = (x.c0 : ZMod Fp.modulus) := rfl

@[simp] theorem im_toField (x : Fp2) : (toField x).im = (x.c1 : ZMod Fp.modulus) := rfl

@[simp] theorem toField_symm_apply (z : Fp2Field) : toField.symm z = ⟨z.re, z.im⟩ := rfl

/-- Matches the literals the spec builds, such as `⟨s, Fp.zero⟩` in `Fp2.sqrt`. -/
@[simp] theorem toField_mk (a b : Fp) :
    toField ⟨a, b⟩ = ⟨(a : ZMod Fp.modulus), (b : ZMod Fp.modulus)⟩ := rfl

theorem toField_i : toField Fp2.i = QuadraticAlgebra.omega := rfl

@[simp] theorem toField_zero : toField Fp2.zero = 0 := rfl

@[simp] theorem toField_one : toField Fp2.one = 1 := rfl

@[simp] theorem toField_neg (x : Fp2) : toField (-x) = -toField x := rfl

@[simp] theorem toField_sub (x y : Fp2) : toField (x - y) = toField x - toField y := rfl

@[simp] theorem toField_ofFp (a : Fp) :
    toField (Fp2.ofFp a) = algebraMap (ZMod Fp.modulus) Fp2Field a := rfl

private theorem inv_mk (a b : ZMod Fp.modulus) :
    (⟨a, b⟩ : Fp2Field)⁻¹ = ⟨a * (a * a + b * b)⁻¹, -(b * (a * a + b * b)⁻¹)⟩ := by
  have hn : QuadraticAlgebra.norm (⟨a, b⟩ : Fp2Field) = a * a + b * b := by
    rw [QuadraticAlgebra.norm_def]
    ring
  show (QuadraticAlgebra.norm (⟨a, b⟩ : Fp2Field))⁻¹ • star (⟨a, b⟩ : Fp2Field) = _
  rw [hn, QuadraticAlgebra.star_mk, QuadraticAlgebra.smul_mk]
  ext <;> simp <;> ring

/-- Both sides send 0 to 0: the spec inverts the norm by a Fermat power, and 0 ^ (p − 2) = 0. -/
theorem toField_inverse (x : Fp2) : toField x.inverse = (toField x)⁻¹ := by
  have h : ∀ n : ZMod Fp.modulus, Fp.inverse n = n⁻¹ := Fp.inverse_eq_inv
  rw [show toField x = ⟨x.c0, x.c1⟩ from rfl, inv_mk, ← h]
  rfl

theorem isZero_iff (x : Fp2) : x.isZero = true ↔ toField x = 0 := by
  rw [Fp2.isZero, Bool.and_eq_true, Fp.isZero_iff, Fp.isZero_iff, QuadraticAlgebra.ext_iff]
  rfl

theorem beq_iff (x y : Fp2) : x.beq y = true ↔ toField x = toField y := by
  rw [Fp2.beq, Bool.and_eq_true, Fp.beq_iff, Fp.beq_iff, QuadraticAlgebra.ext_iff]
  rfl

theorem toField_conjugate (x : Fp2) : toField x.conjugate = star (toField x) := by
  ext
  · simp [Fp2.conjugate]
  · rfl

/-- The right side is the spec's own expression for the norm in `Fp2.inverse` and `Fp2.sqrt`, in
`Fp` arithmetic, so `rw` matches it there. -/
theorem norm_toField (x : Fp2) :
    (toField x).norm = (x.c0 * x.c0 + x.c1 * x.c1 : ZMod Fp.modulus) := by
  rw [QuadraticAlgebra.norm_def, re_toField, im_toField]
  have h (a b : ZMod Fp.modulus) : a * a + 0 * a * b - -1 * b * b = a * a + b * b := by ring
  exact h x.c0 x.c1

end Fp2

end LeanBlsSimd
