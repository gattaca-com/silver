import LeanBlsSimd.Spec.G2Curve

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable instance Fp2Field.instFintype : Fintype Fp2Field :=
  Fintype.ofEquiv (ZMod Fp.modulus × ZMod Fp.modulus)
    (QuadraticAlgebra.equivProd (-1) 0).symm

theorem Fp2Field.card_eq : Fintype.card Fp2Field = Fp.modulus ^ 2 := by
  rw [Fintype.card_congr (QuadraticAlgebra.equivProd (-1) 0), Fintype.card_prod]
  simp [ZMod.card, pow_two]

instance Fp2Field.instCharP : CharP Fp2Field Fp.modulus :=
  charP_of_injective_algebraMap (algebraMap (ZMod Fp.modulus) Fp2Field).injective Fp.modulus

namespace Fp2

@[simp] theorem toField_mulByOnePlusI (a : Fp2) :
    toField a.mulByOnePlusI = toField a * (1 + QuadraticAlgebra.omega) := by
  apply QuadraticAlgebra.ext <;>
    simp [EthLib.Cryptography.Bls.Fp2.mulByOnePlusI, QuadraticAlgebra.re_mul,
      QuadraticAlgebra.im_mul, QuadraticAlgebra.re_one, QuadraticAlgebra.im_one, sub_eq_add_neg]
  · exact (by intro x y; ring : ∀ x y : ZMod Fp.modulus, x + -y = x * 1 + -1 * y) a.c0 a.c1
  · exact (by intro x y; ring : ∀ x y : ZMod Fp.modulus, x + y = x * 1 + y * 1 + 0 * y) a.c0 a.c1

@[simp] theorem toField_powNat (a : Fp2) (n : Nat) :
    toField (Fp2.powNat a n) = toField a ^ n := by
  rw [EthLib.Cryptography.Bls.Fp2.powNat_eq_pow, map_pow]

end Fp2

end LeanBlsSimd
