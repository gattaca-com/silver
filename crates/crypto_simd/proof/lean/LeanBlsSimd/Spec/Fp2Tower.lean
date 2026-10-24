import LeanBlsSimd.Spec.PointCount
import LeanBlsSimd.Spec.PairingEquations

namespace LeanBlsSimd.Fp2

open EthLib.Cryptography.Bls

@[simp] theorem toField_mulByOnePlusI (a : Fp2) :
    toField a.mulByOnePlusI = toField a * (1 + QuadraticAlgebra.omega) := by
  apply QuadraticAlgebra.ext <;>
    simp [EthLib.Cryptography.Bls.Fp2.mulByOnePlusI, QuadraticAlgebra.re_mul,
      QuadraticAlgebra.im_mul, QuadraticAlgebra.re_one, QuadraticAlgebra.im_one, sub_eq_add_neg] <;> rfl

@[simp] theorem toField_powNat (a : Fp2) (n : Nat) :
    toField (Fp2.powNat a n) = toField a ^ n := by
  induction n using Nat.strongRecOn generalizing a with
  | _ n ih =>
    by_cases hzero : n = 0
    · subst n
      simp only [SpecPairing.fp2_powNat_zero, toField_one, pow_zero]
    · rw [SpecPairing.fp2_powNat_step a n hzero]
      have half := ih (n / 2) (by omega) (a * a)
      split_ifs with hodd
      · rw [map_mul, half, map_mul, ← pow_two, ← pow_mul, ← pow_succ']
        congr 1
        omega
      · rw [half, map_mul, ← pow_two, ← pow_mul]
        congr 1
        omega

end LeanBlsSimd.Fp2
