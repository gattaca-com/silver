import LeanBlsSimd.Kzg.Extender.SpecMath

open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr BigOperators

open private getElem!_reversedRoots getElem!_map_mul
  from EthCryptographySpecs.Proofs.Kzg.FftInverse

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Controls

private theorem roots4096 (i : Nat) (hi : i < 2 ^ 12) :
    (computeRootsOfUnity 4096)[i]! = domainRoot 4096 ^ i :=
  getElem!_computeRootsOfUnity_pow 4096 i hi

def inverse4096 (values : Array Fr) : Array Fr :=
  Kzg.Model.inverseFft values (Kzg.Model.inverseRoots (Kzg.Model.roots 12))
    (Fr.ofNat 4096).inverse

private theorem inverse4096_eq (values : Array Fr) (hs : values.size = 4096) :
    inverse4096 values = fftField values (computeRootsOfUnity 4096) true := by
  simp only [inverse4096, Kzg.Model.inverseFft, Kzg.Model.inverseRoots, Kzg.Model.roots,
    fftField_def, if_true, hs]

def inputWitness : Array Fr := Array.ofFn (fun i : Fin 4096 => Fr.ofNat i.val)

private theorem inputWitness_size : inputWitness.size = 4096 := by
  simp only [inputWitness, Array.size_ofFn]

private theorem inputWitness_get (i : Nat) (hi : i < 4096) :
    inputWitness[i]! = Fr.ofNat i := by
  rw [getElem!_pos inputWitness i (by rw [inputWitness_size]; exact hi)]
  simp only [inputWitness, Array.getElem_ofFn]

theorem omitting_input_bit_reversal_changes_coefficients :
    inverse4096 (bitReversalPermutation inputWitness) ≠ inverse4096 inputWitness := by
  intro h
  rw [inverse4096_eq _ (by rw [size_bitReversalPermutation, inputWitness_size]),
    inverse4096_eq _ inputWitness_size] at h
  have hround (a : Array Fr) (ha : a.size = 4096) :
      fftField (fftField a (computeRootsOfUnity 4096) true)
        (computeRootsOfUnity 4096) false = a :=
    fftField_inv_fftField (k := 12) domainRoot_4096_primitive a
      (computeRootsOfUnity 4096) ha (size_computeRootsOfUnity 4096) roots4096
  have he := congrArg (fun a => fftField a (computeRootsOfUnity 4096) false) h
  dsimp only at he
  rw [hround _ (by rw [size_bitReversalPermutation, inputWitness_size]),
    hround _ inputWitness_size] at he
  have hi := congrArg (fun a : Array Fr => a[1]!) he
  dsimp only at hi
  rw [getElem!_pos (bitReversalPermutation inputWitness) 1
      (by rw [size_bitReversalPermutation, inputWitness_size]; decide),
    getElem_bitReversalPermutation, inputWitness_size,
    show reverseBits 1 4096 = 2048 by decide +kernel,
    inputWitness_get 2048 (by decide), inputWitness_get 1 (by decide)] at hi
  exact (by decide : Fr.ofNat 2048 ≠ Fr.ofNat 1) hi

def linearCoefficients : Array Fr :=
  Array.ofFn (fun i : Fin 4096 => if i.val = 1 then (1 : Fr) else 0)

private theorem linearCoefficients_size : linearCoefficients.size = 4096 := by
  simp only [linearCoefficients, Array.size_ofFn]

private theorem linearCoefficients_eval (z : Fr) :
    (coeffPolynomial linearCoefficients).eval z = z := by
  rw [coeffPolynomial_eval, linearCoefficients_size]
  trans ∑ i ∈ Finset.range 4096, (if i = 1 then (1 : Fr) else 0) * z ^ i
  · apply Finset.sum_congr rfl
    intro i hi
    rw [getElem!_pos linearCoefficients i (by
      rw [linearCoefficients_size]; exact Finset.mem_range.mp hi)]
    simp only [linearCoefficients, Array.getElem_ofFn]
  · simp only [ite_mul, zero_mul, Finset.sum_ite_eq', Finset.mem_range,
      show 1 < 4096 by decide, if_true, pow_one]
    exact one_mul z

def linearInput : Array Fr :=
  bitReversalPermutation (fftField linearCoefficients (computeRootsOfUnity 4096) false)

private theorem linearInput_size : linearInput.size = 4096 := by
  rw [linearInput, size_bitReversalPermutation, size_fftField, linearCoefficients_size]

private theorem linearInput_coefficients : polynomialEvalToCoeff linearInput = linearCoefficients := by
  unfold polynomialEvalToCoeff linearInput
  rw [bitReversalPermutation_bitReversalPermutation _ (k := 12)
    (by rw [size_fftField, linearCoefficients_size])]
  exact fftField_fftField_inv (k := 12) domainRoot_4096_primitive linearCoefficients
    (computeRootsOfUnity 4096) linearCoefficients_size (size_computeRootsOfUnity 4096) roots4096

private theorem shifted_linear_get (factor : Fr) (j : Nat) (hj : j < 4096) :
    (fftField (shiftVals linearCoefficients factor) (computeRootsOfUnity 4096) false)[j]! =
      factor * domainRoot 4096 ^ j := by
  rw [← fftField_coeffPolynomial_eval (k := 12) domainRoot_4096_primitive
    (shiftVals linearCoefficients factor) (computeRootsOfUnity 4096)
    (by rw [size_shiftVals, linearCoefficients_size]; rfl)
    (size_computeRootsOfUnity 4096) roots4096 j hj,
    coeffPolynomial_shiftVals_eval, linearCoefficients_eval]

private theorem linear_extension_get (j : Nat) (hj : j < 4096) :
    (Model.extension linearInput)[j]! = domainRoot 8192 * domainRoot 4096 ^ j := by
  rw [extension_eq linearInput linearInput_size, linearInput_coefficients,
    shifted_linear_get _ j hj]

private theorem shift_ne_one : domainRoot 8192 ≠ (1 : Fr) := by
  simpa only [pow_one] using
    domainRoot_8192_primitive.pow_ne_one_of_pos_of_lt (by decide : 1 ≠ 0)
      (by decide : 1 < 8192)

theorem omitting_coset_shift_changes_extension :
    Model.extension linearInput ≠ fftField linearCoefficients (computeRootsOfUnity 4096) false := by
  intro h
  have hi := congrArg (fun a : Array Fr => a[0]!) h
  dsimp only at hi
  rw [linear_extension_get 0 (by decide),
    ← fftField_coeffPolynomial_eval (k := 12) domainRoot_4096_primitive
      linearCoefficients (computeRootsOfUnity 4096) linearCoefficients_size
      (size_computeRootsOfUnity 4096) roots4096 0 (by decide),
    linearCoefficients_eval, pow_zero] at hi
  exact shift_ne_one ((mul_one _).symm.trans hi)

private theorem shift_ne_inverse : domainRoot 8192 ≠ (domainRoot 8192).inverse := by
  rw [Fr.inverse_eq_inv]
  intro h
  apply domainRoot_8192_primitive.pow_ne_one_of_pos_of_lt (by decide : 2 ≠ 0)
    (by decide : 2 < 8192)
  calc
    domainRoot 8192 ^ (2 : Nat) = domainRoot 8192 * domainRoot 8192 := pow_two _
    _ = domainRoot 8192 * (domainRoot 8192)⁻¹ := congrArg (domainRoot 8192 * ·) h
    _ = 1 := mul_inv_cancel₀ (domainRoot_8192_primitive.ne_zero (by decide))

theorem reversing_coset_shift_changes_extension :
    Model.extension linearInput ≠
      fftField (shiftVals linearCoefficients (domainRoot 8192).inverse)
        (computeRootsOfUnity 4096) false := by
  intro h
  have hi := congrArg (fun a : Array Fr => a[0]!) h
  dsimp only at hi
  rw [linear_extension_get 0 (by decide), shifted_linear_get _ 0 (by decide), pow_zero] at hi
  exact shift_ne_inverse ((mul_one _).symm.trans (hi.trans (mul_one _)))

private theorem shifted_linear_inverse_get (factor : Fr) (j : Nat) (hj : j < 4096) :
    (fftFieldAux (shiftVals linearCoefficients factor)
      (Kzg.Model.inverseRoots (Kzg.Model.roots 12)))[j]! =
      factor * (domainRoot 4096)⁻¹ ^ j := by
  unfold Kzg.Model.roots
  simp only [show (2 : Nat) ^ 12 = 4096 by decide]
  have h := fftField_coeffPolynomial_eval (k := 12) domainRoot_4096_primitive.inv
    (shiftVals linearCoefficients factor) (Kzg.Model.inverseRoots (computeRootsOfUnity 4096))
    (by rw [size_shiftVals, linearCoefficients_size]; rfl)
    (by simp [Kzg.Model.inverseRoots])
    (fun i hi => getElem!_reversedRoots (k := 12) domainRoot_4096_primitive
      (computeRootsOfUnity 4096) (size_computeRootsOfUnity 4096) roots4096 i hi) j hj
  rw [coeffPolynomial_shiftVals_eval, linearCoefficients_eval] at h
  simp only [fftField_def, Bool.false_eq_true, if_false] at h
  exact h.symm

theorem reversing_forward_fft_roots_changes_extension :
    Model.extension linearInput ≠
      fftFieldAux (shiftVals linearCoefficients (domainRoot 8192))
        (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) := by
  intro h
  have hi := congrArg (fun a : Array Fr => a[1]!) h
  dsimp only at hi
  rw [linear_extension_get 1 (by decide), shifted_linear_inverse_get _ 1 (by decide)] at hi
  simp only [pow_one] at hi
  have hnz := domainRoot_8192_primitive.ne_zero (by decide : 8192 ≠ 0)
  have hr : domainRoot 4096 = (domainRoot 4096)⁻¹ := by
    calc
      _ = (domainRoot 8192)⁻¹ * (domainRoot 8192 * domainRoot 4096) :=
        (inv_mul_cancel_left₀ hnz _).symm
      _ = (domainRoot 8192)⁻¹ * (domainRoot 8192 * (domainRoot 4096)⁻¹) :=
        congrArg (fun x : Fr => (domainRoot 8192)⁻¹ * x) hi
      _ = _ := inv_mul_cancel_left₀ hnz _
  apply domainRoot_4096_primitive.pow_ne_one_of_pos_of_lt (by decide : 2 ≠ 0)
    (by decide : 2 < 4096)
  calc
    domainRoot 4096 ^ (2 : Nat) = domainRoot 4096 * domainRoot 4096 := pow_two _
    _ = domainRoot 4096 * (domainRoot 4096)⁻¹ := congrArg (domainRoot 4096 * ·) hr
    _ = 1 := mul_inv_cancel₀ (domainRoot_4096_primitive.ne_zero (by decide))

theorem omitting_output_bit_reversal_changes_extension_order :
    bitReversalPermutation (Model.extension linearInput) ≠ Model.extension linearInput := by
  intro h
  have hi := congrArg (fun a : Array Fr => a[1]!) h
  dsimp only at hi
  rw [getElem!_pos (bitReversalPermutation (Model.extension linearInput)) 1
      (by rw [size_bitReversalPermutation, extension_size linearInput linearInput_size]; decide),
    getElem_bitReversalPermutation, extension_size linearInput linearInput_size,
    show reverseBits 1 4096 = 2048 by decide +kernel,
    linear_extension_get 2048 (by decide), linear_extension_get 1 (by decide)] at hi
  have hnz := domainRoot_8192_primitive.ne_zero (by decide : 8192 ≠ 0)
  have hp : domainRoot 4096 ^ (2048 : Nat) = domainRoot 4096 ^ (1 : Nat) := by
    calc
      _ = (domainRoot 8192)⁻¹ * (domainRoot 8192 * domainRoot 4096 ^ (2048 : Nat)) :=
        (inv_mul_cancel_left₀ hnz _).symm
      _ = (domainRoot 8192)⁻¹ * (domainRoot 8192 * domainRoot 4096 ^ (1 : Nat)) :=
        congrArg (fun x : Fr => (domainRoot 8192)⁻¹ * x) hi
      _ = _ := inv_mul_cancel_left₀ hnz _
  have hn := domainRoot_4096_primitive.pow_inj (by decide : 2048 < 4096)
    (by decide : 1 < 4096) hp
  omega

def unscaledInverse4096 (values : Array Fr) : Array Fr :=
  fftFieldAux values (Kzg.Model.inverseRoots (Kzg.Model.roots 12))

private theorem unscaled_constant_coefficient :
    (unscaledInverse4096 (Array.replicate 4096 (1 : Fr)))[0]! = 4096 := by
  unfold unscaledInverse4096 Kzg.Model.roots
  simp only [show (2 : Nat) ^ 12 = 4096 by decide]
  have hd := getElem!_fftFieldAux_dft (k := 12) domainRoot_4096_primitive.inv
    (Array.replicate 4096 (1 : Fr)) (Kzg.Model.inverseRoots (computeRootsOfUnity 4096))
    (by simp) (by simp [Kzg.Model.inverseRoots])
    (fun i hi => getElem!_reversedRoots (k := 12) domainRoot_4096_primitive
      (computeRootsOfUnity 4096) (size_computeRootsOfUnity 4096) roots4096 i hi) 0 (by decide)
  rw [hd]
  simp only [Nat.mul_zero, pow_zero]
  trans ∑ _i ∈ Finset.range (2 ^ 12), (1 : Fr)
  · apply Finset.sum_congr rfl
    intro i hi
    rw [getElem!_pos (Array.replicate 4096 (1 : Fr)) i
      (by simpa using Finset.mem_range.mp hi)]
    simp only [Array.getElem_replicate]
    exact mul_one 1
  · simp only [Finset.sum_const, Finset.card_range]
    exact (nsmul_eq_mul 4096 (1 : Fr)).trans (mul_one _)

private theorem scaled_constant_coefficient :
    (inverse4096 (Array.replicate 4096 (1 : Fr)))[0]! = 1 := by
  unfold inverse4096 Kzg.Model.inverseFft
  change ((unscaledInverse4096 (Array.replicate 4096 (1 : Fr))).map
    (· * (Fr.ofNat 4096).inverse))[0]! = 1
  rw [getElem!_map_mul _ _ 0 (by simp [unscaledInverse4096]), unscaled_constant_coefficient,
    Fr.inverse_eq_inv, Fr.ofNat_eq_natCast]
  exact mul_inv_cancel₀ (by decide : (4096 : Fr) ≠ 0)

theorem omitting_inverse_scaling_changes_coefficients :
    unscaledInverse4096 (Array.replicate 4096 (1 : Fr)) ≠
      inverse4096 (Array.replicate 4096 (1 : Fr)) := by
  intro h
  have hi : (4096 : Fr) = 1 := unscaled_constant_coefficient.symm.trans
    ((congrArg (fun a : Array Fr => a[0]!) h).trans scaled_constant_coefficient)
  exact (by decide : (4096 : Fr) ≠ 1) hi

end LeanBlsSimd.Kzg.Extender.Controls

#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitting_input_bit_reversal_changes_coefficients
#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitting_output_bit_reversal_changes_extension_order
#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitting_coset_shift_changes_extension
#print axioms LeanBlsSimd.Kzg.Extender.Controls.reversing_coset_shift_changes_extension
#print axioms LeanBlsSimd.Kzg.Extender.Controls.reversing_forward_fft_roots_changes_extension
#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitting_inverse_scaling_changes_coefficients
