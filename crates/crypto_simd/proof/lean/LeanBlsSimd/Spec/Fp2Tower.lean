import LeanBlsSimd.Spec.PointCount

namespace LeanBlsSimd.Fp2

open EthLib.Cryptography.Bls

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

end LeanBlsSimd.Fp2
