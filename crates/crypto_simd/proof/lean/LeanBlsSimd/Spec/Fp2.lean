import LeanBlsSimd.Constants
import EthLib.Cryptography.Proofs.Bls.Fp2
import Mathlib.Algebra.QuadraticAlgebra.Basic

/-!
# The spec's `Fp2` as a field

`Fp2.toField` identifies EthLib's field with Mathlib's
`QuadraticAlgebra (ZMod Fp.modulus) (-1) 0`. The latter supplies the algebra,
conjugation and norm interfaces used by the quotient tower.

Zero, one, addition, negation and subtraction agree definitionally.
Multiplication agrees only propositionally: the spec computes
re·re′ − im·im′, while `QuadraticAlgebra` computes re·re′ + (−1)·im·im′.
-/

namespace LeanBlsSimd

open EthLib.Cryptography EthLib.Cryptography.Bls

abbrev Fp2Field : Type := QuadraticAlgebra (ZMod Fp.modulus) (-1) 0

/-- X² + 1 has no root in Fp, which is the hypothesis of `Field Fp2Field`. -/
instance instFactNegOneNotSquare : Fact (∀ r : ZMod Fp.modulus, r ^ 2 ≠ -1 + 0 * r) :=
  ⟨fun r => by simpa using neg_one_not_square r⟩

theorem Fp2Field.omega_sq : (QuadraticAlgebra.omega : Fp2Field) ^ 2 = -1 := by
  rw [sq, QuadraticAlgebra.omega_mul_omega_eq_mk]
  ext <;> simp [QuadraticAlgebra.re_one, QuadraticAlgebra.im_one]

theorem Fp2Field.natCast_modulus : (Fp.modulus : Fp2Field) = 0 := by
  rw [← map_natCast (algebraMap (ZMod Fp.modulus) Fp2Field), ZMod.natCast_self, map_zero]

theorem Fp.isZero_iff {a : Fp} : a.isZero = true ↔ (a : ZMod Fp.modulus) = 0 :=
  EthLib.Cryptography.Bls.G1.isZero_iff

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

@[simp] theorem toField_zero : toField Fp2.zero = 0 := rfl

@[simp] theorem toField_one : toField Fp2.one = 1 := rfl

@[simp] theorem toField_neg (x : Fp2) : toField (-x) = -toField x := rfl

@[simp] theorem toField_sub (x y : Fp2) : toField (x - y) = toField x - toField y := rfl

@[simp] theorem toField_ofFp (a : Fp) :
    toField (Fp2.ofFp a) = algebraMap (ZMod Fp.modulus) Fp2Field a := rfl

theorem toField_inverse (x : Fp2) : toField x.inverse = (toField x)⁻¹ := map_inv₀ toField x

theorem isZero_iff (x : Fp2) : x.isZero = true ↔ toField x = 0 := by
  rw [EthLib.Cryptography.Bls.Fp2.isZero_iff, ← map_zero toField, toField.injective.eq_iff]

theorem beq_iff (x y : Fp2) : x.beq y = true ↔ toField x = toField y := by
  rw [EthLib.Cryptography.Bls.Fp2.beq_iff_eq, toField.injective.eq_iff]

end Fp2

end LeanBlsSimd
