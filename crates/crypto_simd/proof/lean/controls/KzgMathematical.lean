import LeanBlsSimd.Kzg.CosetPolynomial

open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr BigOperators

open private getElem!_reversedRoots getElem!_map_mul
  from EthCryptographySpecs.Proofs.Kzg.FftInverse

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Controls

theorem bit_reversal_moves_index_one :
    (bitReversalPermutation (Array.range 64))[1]! = 32 := by
  decide +kernel

theorem omitting_bit_reversal_changes_input :
    bitReversalPermutation (Array.range 64) ≠ Array.range 64 := by
  intro h
  have hi : (32 : Nat) = 1 := bit_reversal_moves_index_one.symm.trans
    ((congrArg (fun a : Array Nat => a[1]!) h).trans (by decide +kernel))
  omega

theorem coset_shift_64 : Model.cosetShift 64 = domainRoot 8192 := by
  unfold Model.cosetShift
  rw [getElem!_rootsOfUnityBrp_pow 8192 13 (64 * 64) rfl (by decide)]
  rw [show reverseBits (64 * 64) 8192 = 1 by decide +kernel, pow_one]

theorem coset_shift_direction_matters :
    Model.cosetShift 64 ≠ (Model.cosetShift 64).inverse := by
  rw [coset_shift_64, Fr.inverse_eq_inv]
  intro h
  apply domainRoot_8192_primitive.pow_ne_one_of_pos_of_lt (by decide : 2 ≠ 0)
    (by decide : 2 < 8192)
  calc
    domainRoot 8192 ^ (2 : Nat) = domainRoot 8192 * domainRoot 8192 := pow_two _
    _ = domainRoot 8192 * (domainRoot 8192)⁻¹ := congrArg (domainRoot 8192 * ·) h
    _ = 1 := mul_inv_cancel₀ (domainRoot_8192_primitive.ne_zero (by decide))

theorem forward_shift_changes_linear_coefficients :
    shiftVals #[0, 1] (Model.cosetShift 64) ≠
      shiftVals #[0, 1] (Model.cosetShift 64).inverse := by
  intro h
  apply coset_shift_direction_matters
  have hc (s : Fr) : (shiftVals #[0, 1] s)[1]! = s := by
    rw [getElem!_pos _ 1 (by simp), getElem_shiftVals]
    simp only [Fr.powNat_eq_pow, pow_one]
    exact one_mul s
  exact (hc _).symm.trans ((congrArg (fun a : Array Fr => a[1]!) h).trans (hc _))

def unscaledInverse (values : Array Fr) : Array Fr :=
  fftFieldAux values (Model.inverseRoots (computeRootsOfUnity 64))

theorem unscaled_constant_coefficient :
    (unscaledInverse (Array.replicate 64 (1 : Fr)))[0]! = 64 := by
  unfold unscaledInverse
  have hd := getElem!_fftFieldAux_dft (k := 6) domainRoot_64_primitive.inv
    (Array.replicate 64 (1 : Fr)) (Model.inverseRoots (computeRootsOfUnity 64))
    (by simp) (by simp [Model.inverseRoots])
    (fun i hi => getElem!_reversedRoots (k := 6) domainRoot_64_primitive
      (computeRootsOfUnity 64) (size_computeRootsOfUnity 64)
      (fun j hj => getElem!_computeRootsOfUnity_pow 64 j hj) i hi) 0 (by decide)
  rw [hd]
  simp only [Nat.mul_zero, pow_zero]
  calc
    (∑ i ∈ Finset.range (2 ^ 6), (Array.replicate 64 (1 : Fr))[i]!) =
        ∑ _i ∈ Finset.range (2 ^ 6), (1 : Fr) := by
      apply Finset.sum_congr rfl
      intro i hi
      simp [getElem!_pos (Array.replicate 64 (1 : Fr)) i
        (by simpa using Finset.mem_range.mp hi)]
    _ = 64 := by
      simp only [Finset.sum_const, Finset.card_range]
      exact (nsmul_eq_mul 64 (1 : Fr)).trans (mul_one _)

theorem scaled_constant_coefficient :
    (fftField (Array.replicate 64 (1 : Fr)) (computeRootsOfUnity 64) true)[0]! = 1 := by
  rw [fftField_def]
  change ((unscaledInverse (Array.replicate 64 (1 : Fr))).map
    (· * (Fr.ofNat 64).inverse))[0]! = 1
  rw [getElem!_map_mul _ _ 0 (by simp [unscaledInverse]), unscaled_constant_coefficient,
    Fr.inverse_eq_inv, Fr.ofNat_eq_natCast]
  exact mul_inv_cancel₀ (by decide : (64 : Fr) ≠ 0)

theorem omitting_inverse_scaling_changes_transform :
    unscaledInverse (Array.replicate 64 (1 : Fr)) ≠
      fftField (Array.replicate 64 (1 : Fr)) (computeRootsOfUnity 64) true := by
  intro h
  have hi : (64 : Fr) = 1 := unscaled_constant_coefficient.symm.trans
    ((congrArg (fun a : Array Fr => a[0]!) h).trans scaled_constant_coefficient)
  exact (by decide : (64 : Fr) ≠ 1) hi

end LeanBlsSimd.Kzg.Controls

#print axioms LeanBlsSimd.Kzg.Controls.omitting_bit_reversal_changes_input
#print axioms LeanBlsSimd.Kzg.Controls.coset_shift_direction_matters
#print axioms LeanBlsSimd.Kzg.Controls.forward_shift_changes_linear_coefficients
#print axioms LeanBlsSimd.Kzg.Controls.omitting_inverse_scaling_changes_transform
