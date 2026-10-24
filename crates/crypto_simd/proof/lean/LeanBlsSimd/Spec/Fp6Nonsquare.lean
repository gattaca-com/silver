import LeanBlsSimd.Spec.Fp6Operations
import Mathlib.RingTheory.Norm.Basic

/-! Two successive norm maps rule out a square root of the cubic generator. -/

namespace LeanBlsSimd.Fp6Field

open EthLib.Cryptography.Bls

theorem xi_not_square (a : Fp2Field) : a ^ 2 ≠ xi := by
  intro h
  apply two_not_square (QuadraticAlgebra.norm a)
  rw [← map_pow, h, norm_xi]

theorem norm_v : Algebra.norm Fp2Field v = xi := by
  change Algebra.norm Fp2Field (AdjoinRoot.powerBasis polynomial_monic.ne_zero).gen = _
  rw [Algebra.PowerBasis.norm_gen_eq_coeff_zero_minpoly,
    AdjoinRoot.minpoly_powerBasis_gen_of_monic polynomial_monic,
    AdjoinRoot.powerBasis_dim, polynomial_natDegree]
  norm_num [polynomial]

theorem v_not_square (a : Fp6Field) : a ^ 2 ≠ v := by
  intro h
  apply xi_not_square (Algebra.norm Fp2Field a)
  rw [← map_pow, h, norm_v]

end LeanBlsSimd.Fp6Field
