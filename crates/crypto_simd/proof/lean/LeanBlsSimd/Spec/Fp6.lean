import LeanBlsSimd.Spec.Fp6Noncube
import EthLib.Cryptography.Bls.Fp6
import Mathlib.FieldTheory.KummerPolynomial
import Mathlib.LinearAlgebra.Basis.Basic

/-! A cubic quotient field and its three coordinates over Fp2. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

open Module

noncomputable section

namespace Fp6Field

open Polynomial

def polynomial : Polynomial Fp2Field := X ^ 3 - C xi

theorem polynomial_monic : polynomial.Monic := monic_X_pow_sub_C _ (by decide)

theorem polynomial_natDegree : polynomial.natDegree = 3 := natDegree_X_pow_sub_C

theorem polynomial_irreducible : Irreducible polynomial :=
  X_pow_sub_C_irreducible_of_prime Nat.prime_three xi_not_cube

instance instFactIrreducible : Fact (Irreducible polynomial) := ⟨polynomial_irreducible⟩

end Fp6Field

abbrev Fp6Field : Type := AdjoinRoot Fp6Field.polynomial

namespace Fp6Field

abbrev of : Fp2Field →+* Fp6Field := AdjoinRoot.of polynomial

def v : Fp6Field := AdjoinRoot.root polynomial

theorem v_cube : v ^ 3 = of xi := root_X_pow_sub_C_pow 3 xi

def basis : Basis (Fin 3) Fp2Field Fp6Field :=
  (AdjoinRoot.powerBasis' polynomial_monic).basis.reindex (finCongr polynomial_natDegree)

theorem basis_apply (i : Fin 3) : basis i = v ^ (i : ℕ) := by
  rw [basis, Basis.reindex_apply, (AdjoinRoot.powerBasis' polynomial_monic).basis_eq_pow]
  rfl

def assemble (a b c : Fp2Field) : Fp6Field := of a + of b * v + of c * v ^ 2

theorem basis_assemble (a b c : Fp2Field) :
    basis.equivFun.symm ![a, b, c] = assemble a b c := by
  rw [Basis.equivFun_symm_apply]
  simp [Fin.sum_univ_succ, basis_apply, assemble, Algebra.smul_def, add_assoc]

theorem coeffs_assemble (a b c : Fp2Field) :
    basis.equivFun (assemble a b c) = ![a, b, c] := by
  rw [← basis_assemble, LinearEquiv.apply_symm_apply]

theorem assemble_eq_zero_iff (a b c : Fp2Field) :
    assemble a b c = 0 ↔ a = 0 ∧ b = 0 ∧ c = 0 := by
  constructor
  · intro h
    have he := congrArg basis.equivFun h
    rw [coeffs_assemble, map_zero] at he
    exact ⟨congrFun he 0, congrFun he 1, congrFun he 2⟩
  · rintro ⟨rfl, rfl, rfl⟩
    simp [assemble]

theorem assemble_mul (a b c d e f : Fp2Field) :
    assemble a b c * assemble d e f =
      assemble (a * d + xi * (b * f + c * e))
        (a * e + b * d + xi * (c * f)) (a * f + b * e + c * d) := by
  simp only [assemble, map_add, map_mul]
  linear_combination (of b * of f + of c * of e + of c * of f * v) * v_cube

end Fp6Field

namespace Fp6

open EthLib.Cryptography.Bls.Fp6

open Fp6Field

/-- The spec's three coordinates form the power-basis coordinates of the quotient field. -/
def toField : Fp6 ≃+* Fp6Field where
  toFun a := assemble (Fp2.toField a.c0) (Fp2.toField a.c1) (Fp2.toField a.c2)
  invFun x := ⟨Fp2.toField.symm (basis.equivFun x 0),
    Fp2.toField.symm (basis.equivFun x 1), Fp2.toField.symm (basis.equivFun x 2)⟩
  left_inv a := by
    simp only [coeffs_assemble, Matrix.cons_val_zero, Matrix.cons_val_one,
      Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, RingEquiv.symm_apply_apply]
  right_inv x := by
    simp only [RingEquiv.apply_symm_apply]
    rw [← basis_assemble]
    convert basis.equivFun.symm_apply_apply x using 1
    congr 1
    funext i
    fin_cases i <;> rfl
  map_add' a b := by
    change assemble (Fp2.toField (a.c0 + b.c0)) (Fp2.toField (a.c1 + b.c1))
      (Fp2.toField (a.c2 + b.c2)) = _
    simp only [map_add, assemble]
    ring
  map_mul' a b := by
    change assemble (Fp2.toField (mul a b).c0) (Fp2.toField (mul a b).c1)
      (Fp2.toField (mul a b).c2) = _
    simp only [Fp6.mul, map_add, map_mul, Fp2.toField_sub, Fp2.toField_mulByOnePlusI]
    rw [assemble_mul]
    congr 1 <;> dsimp only [xi] <;> ring

@[simp] theorem toField_mk (a b c : Fp2) :
    toField ⟨a, b, c⟩ = assemble (Fp2.toField a) (Fp2.toField b) (Fp2.toField c) := rfl

@[simp] theorem toField_zero : toField zero = 0 := by
  change assemble 0 0 0 = 0
  simp [assemble]

@[simp] theorem toField_one : toField one = 1 := by
  change assemble 1 0 0 = 1
  simp [assemble]

theorem toField_mul (a b : Fp6) : toField (mul a b) = toField a * toField b :=
  toField.map_mul a b

end Fp6

end

end LeanBlsSimd
