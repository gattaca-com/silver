import LeanBlsSimd.Spec.TowerConstants
import LeanBlsSimd.Spec.Fp2Tower

/-! The cubic-extension coefficient is not a cube: its quadratic norm is 2. -/

namespace LeanBlsSimd.Fp6Field

open EthLib.Cryptography.Bls

def xi : Fp2Field := 1 + QuadraticAlgebra.omega

theorem norm_xi : QuadraticAlgebra.norm xi = (2 : ZMod Fp.modulus) := by
  decide +kernel

theorem xi_not_cube (a : Fp2Field) : a ^ 3 ≠ xi := by
  intro h
  apply two_not_cube (QuadraticAlgebra.norm a)
  rw [← map_pow, h, norm_xi]

end LeanBlsSimd.Fp6Field
