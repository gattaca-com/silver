import LeanBlsSimd.Spec.Fp6Nonsquare

/-! The quadratic field, with an explicit equivalence to the polynomial quotient. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

abbrev Fp12Field : Type := QuadraticAlgebra Fp6Field Fp6Field.v 0

instance instFactVNotSquare : Fact (∀ a : Fp6Field, a ^ 2 ≠ Fp6Field.v + 0 * a) :=
  ⟨fun a => by simpa using Fp6Field.v_not_square a⟩

noncomputable section

namespace Fp12Field

def w : Fp12Field := QuadraticAlgebra.omega

theorem w_sq : w ^ 2 = algebraMap Fp6Field Fp12Field Fp6Field.v := by
  rw [sq, w, QuadraticAlgebra.omega_mul_omega_eq_mk]
  rfl

open Polynomial

def polynomial : Polynomial Fp6Field := X ^ 2 - C Fp6Field.v

theorem polynomial_irreducible : Irreducible polynomial :=
  X_pow_sub_C_irreducible_of_prime Nat.prime_two Fp6Field.v_not_square

instance instFactIrreducible : Fact (Irreducible polynomial) := ⟨polynomial_irreducible⟩

def fromQuotient : AdjoinRoot polynomial →ₐ[Fp6Field] Fp12Field :=
  AdjoinRoot.liftAlgHom polynomial (Algebra.ofId Fp6Field Fp12Field) w
    (by simp [polynomial, w_sq])

def toQuotient : Fp12Field →ₐ[Fp6Field] AdjoinRoot polynomial := by
  refine QuadraticAlgebra.lift ⟨AdjoinRoot.root polynomial, ?_⟩
  simpa only [Algebra.smul_def, map_zero, zero_mul, mul_one, add_zero, pow_two] using
    (root_X_pow_sub_C_pow 2 Fp6Field.v)

def quotientEquiv : AdjoinRoot polynomial ≃ₐ[Fp6Field] Fp12Field :=
  AlgEquiv.ofAlgHom fromQuotient toQuotient
    (by
      apply QuadraticAlgebra.algHom_ext
      simp [fromQuotient, toQuotient, QuadraticAlgebra.lift, w])
    (by
      apply AdjoinRoot.algHom_ext
      simp [fromQuotient, toQuotient, QuadraticAlgebra.lift, w])

theorem quotientEquiv_root : quotientEquiv (AdjoinRoot.root polynomial) = w := by
  change fromQuotient (AdjoinRoot.root polynomial) = w
  simp [fromQuotient]

instance instFintype : Fintype Fp12Field :=
  Fintype.ofEquiv (Fp6Field × Fp6Field) (QuadraticAlgebra.equivProd Fp6Field.v 0).symm

theorem card_eq : Fintype.card Fp12Field = Fp.modulus ^ 12 := by
  rw [Fintype.card_congr (QuadraticAlgebra.equivProd Fp6Field.v 0), Fintype.card_prod,
    Fp6Field.card_eq, ← pow_add]

instance instCharP : CharP Fp12Field Fp.modulus :=
  charP_of_injective_algebraMap (algebraMap Fp6Field Fp12Field).injective Fp.modulus

end Fp12Field

end

end LeanBlsSimd
