import LeanBlsSimd.Spec.G2Curve
import Mathlib.NumberTheory.LegendreSymbol.QuadraticChar.Basic
import Mathlib.Data.Fintype.Option
import Mathlib.Data.Fintype.Sigma
import Mathlib.Logic.Equiv.Prod

/-! Counting affine solutions by the quadratic character. -/

namespace LeanBlsSimd
open EthCryptographySpecs.Bls WeierstrassCurve

noncomputable instance Fp2Field.instFintype : Fintype Fp2Field :=
  Fintype.ofEquiv (ZMod Fp.modulus × ZMod Fp.modulus)
    (QuadraticAlgebra.equivProd (-1) 0).symm

theorem Fp2Field.card_eq : Fintype.card Fp2Field = Fp.modulus ^ 2 := by
  rw [Fintype.card_congr (QuadraticAlgebra.equivProd (-1) 0), Fintype.card_prod]
  simp [ZMod.card, pow_two]

theorem card_solution_pairs {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    (hF : ringChar F ≠ 2) (b : F) :
    (Nat.card {xy : F × F // xy.2 ^ 2 = xy.1 ^ 3 + b} : ℤ) =
      Fintype.card F + ∑ x : F, quadraticChar F (x ^ 3 + b) := by
  classical
  rw [Nat.card_congr (Equiv.subtypeProdEquivSigmaSubtype (fun x y : F => y ^ 2 = x ^ 3 + b)),
    Nat.card_eq_fintype_card, Fintype.card_sigma, Nat.cast_sum]
  have hroot (x : F) : (Fintype.card {y : F // y ^ 2 = x ^ 3 + b} : ℤ) =
      quadraticChar F (x ^ 3 + b) + 1 := by
    simpa only [Set.toFinset_card, Nat.card_eq_fintype_card] using
      quadraticChar_card_sqrts hF (x ^ 3 + b)
  simp only [hroot, Finset.sum_add_distrib, Finset.sum_const, Finset.card_univ,
    nsmul_eq_mul, mul_one]
  ring

instance Fp2Field.instCharP : CharP Fp2Field Fp.modulus :=
  charP_of_injective_algebraMap (algebraMap (ZMod Fp.modulus) Fp2Field).injective Fp.modulus

theorem Fp2Field.char_ne_two : ringChar Fp2Field ≠ 2 := by
  rw [ringChar.eq Fp2Field Fp.modulus]
  decide +kernel

theorem E'.card_eq_character_sum :
    (Nat.card E'.Point : ℤ) = (Fp.modulus : ℤ) ^ 2 + 1 +
      ∑ x : Fp2Field, quadraticChar Fp2Field (x ^ 3 + bTwist) := by
  classical
  have he : E'.Point ≃ Option {xy : Fp2Field × Fp2Field // xy.2 ^ 2 = xy.1 ^ 3 + bTwist} :=
    E'.nonsingularPointEquiv.trans
      (Equiv.subtypeEquivRight
        (fun xy : Fp2Field × Fp2Field => E'.nonsingular_iff xy.1 xy.2)).optionCongr
  rw [Nat.card_congr he, Nat.card_eq_fintype_card, Fintype.card_option, Nat.cast_add,
    Nat.cast_one, ← Nat.card_eq_fintype_card,
    card_solution_pairs Fp2Field.char_ne_two, Fp2Field.card_eq]
  push_cast
  ring
end LeanBlsSimd
