import LeanBlsSimd.Kzg.Extender.Model
import LeanBlsSimd.Kzg.CosetPolynomial
import Mathlib.Algebra.BigOperators.Intervals

open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr BigOperators

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender

private theorem horner_fold (f : Nat → Fr) (z : Fr) (n : Nat) :
    (List.range n).foldl (fun y i => y * z + f i) 0 =
      ∑ i ∈ Finset.range n, f i * z ^ (n - 1 - i) := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, ih,
      Finset.sum_range_succ, Finset.sum_mul]
    simp only [Nat.add_sub_cancel, Nat.sub_self, pow_zero]
    congr 1
    · apply Finset.sum_congr rfl
      intro i hi
      have hi' := Finset.mem_range.mp hi
      rw [show n - i = (n - 1 - i) + 1 by omega, pow_succ, mul_assoc]
      rfl
    · exact (mul_one _).symm

theorem evaluatePolynomialcoeff_eq (a : Array Fr) (z : Fr) :
    evaluatePolynomialcoeff a z = (coeffPolynomial a).eval z := by
  unfold evaluatePolynomialcoeff
  rw [← Array.foldl_toList]
  simp only [Array.toList_range]
  change (List.range a.size).foldl (fun y i => y * z + a[a.size - 1 - i]!) 0 = _
  rw [horner_fold, coeffPolynomial_eval]
  exact Finset.sum_range_reflect (fun i => a[i]! * z ^ i) a.size

theorem domainRoot_8192_sq : domainRoot 8192 ^ (2 : Nat) = domainRoot 4096 := by
  unfold domainRoot
  rw [Fr.hpow_ofNat_eq_pow _ (by decide), Fr.hpow_ofNat_eq_pow _ (by decide),
    ← pow_mul]
  congr 1

theorem domainRoot_4096_primitive : IsPrimitiveRoot (domainRoot 4096) 4096 :=
  isPrimitiveRoot_domainRoot (Nat.dvd_of_mod_eq_zero (by decide))

theorem reverseBits_half_split (b j : Nat) (hb : b < 2) (hj : j < 4096) :
    reverseBits (4096 * b + j) 8192 = 2 * reverseBits j 4096 + b := by
  change reverseBits (2 ^ 12 * b + j) (2 ^ 13) =
    2 ^ 1 * reverseBits j (2 ^ 12) + b
  have hj' : j < 2 ^ 12 := hj
  have hb' : b < 2 ^ 1 := hb
  apply Nat.eq_of_testBit_eq
  intro i
  rw [testBit_reverseBits, Nat.testBit_two_pow_mul_add _ hb']
  by_cases hi : i = 0
  · subst i
    simp only [show 0 < 13 by decide, if_true, Nat.sub_zero,
      show 0 < 1 by decide]
    rw [Nat.testBit_two_pow_mul_add _ hj']
    simp
  · by_cases hi13 : i < 13
    · rw [if_pos hi13, if_neg (by omega : ¬i < 1),
        Nat.testBit_two_pow_mul_add _ hj', if_pos (by omega : 13 - 1 - i < 12),
        testBit_reverseBits, if_pos (by omega : i - 1 < 12)]
      congr 1
      omega
    · rw [if_neg hi13, if_neg (by omega : ¬i < 1), testBit_reverseBits,
        if_neg (by omega : ¬i - 1 < 12)]

theorem coeff_size (a : Array Fr) (ha : a.size = 4096) :
    (polynomialEvalToCoeff a).size = 4096 := by
  simpa only [polynomialEvalToCoeff, size_fftField, size_bitReversalPermutation] using ha

theorem inverseFft_eq_coeff (a : Array Fr) (ha : a.size = 4096) :
    Kzg.Model.inverseFft (bitReversalPermutation a)
      (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) (Fr.ofNat 4096).inverse =
      polynomialEvalToCoeff a := by
  simp only [polynomialEvalToCoeff, fftField_def, if_true,
    size_bitReversalPermutation, ha, Kzg.Model.inverseFft, Kzg.Model.inverseRoots,
    Kzg.Model.roots, Constants.FIELD_ELEMENTS_PER_BLOB]

theorem extension_eq (a : Array Fr) (ha : a.size = 4096) :
    Model.extension a =
      fftField (shiftVals (polynomialEvalToCoeff a) (domainRoot 8192))
        (computeRootsOfUnity 4096) false := by
  unfold Model.extension
  rw [inverseFft_eq_coeff a ha]
  dsimp only
  have hshift : (Array.ofFn (n := 4096) fun i =>
      (polynomialEvalToCoeff a)[i.val]! * (Kzg.Model.roots 13)[i.val]!) =
      shiftVals (polynomialEvalToCoeff a) (domainRoot 8192) := by
    apply Array.ext
    · simp only [Array.size_ofFn, size_shiftVals, coeff_size a ha]
    · intro i hi hi'
      rw [Array.getElem_ofFn, getElem_shiftVals, Fr.powNat_eq_pow]
      simp only [Kzg.Model.roots]
      rw [getElem!_computeRootsOfUnity_pow 8192 i (by simp only [Array.size_ofFn] at hi; omega)]
      rw [getElem!_pos _ i (by simpa only [size_shiftVals] using hi')]
  rw [hshift, fftField_def]
  rfl

theorem extension_size (a : Array Fr) (ha : a.size = 4096) :
    (Model.extension a).size = 4096 := by
  rw [extension_eq a ha, size_fftField, size_shiftVals, coeff_size a ha]

theorem coeff_eval_original (a : Array Fr) (ha : a.size = 4096)
    (j : Nat) (hj : j < 4096) :
    evaluatePolynomialcoeff (polynomialEvalToCoeff a)
      ((rootsOfUnityBrp 8192)[j]!) = a[j]! := by
  have hroots : ∀ i, i < 2 ^ 12 →
      (computeRootsOfUnity 4096)[i]! = domainRoot 4096 ^ i :=
    fun i hi => getElem!_computeRootsOfUnity_pow 4096 i hi
  have hrev : reverseBits j 4096 < 2 ^ 12 := reverseBits_lt_two_pow j 12
  have hnode : (rootsOfUnityBrp 8192)[j]! = domainRoot 4096 ^ reverseBits j 4096 := by
    rw [getElem!_rootsOfUnityBrp_pow 8192 13 j rfl (by omega)]
    have hr := reverseBits_half_split 0 j (by decide) hj
    simp only [Nat.mul_zero, Nat.zero_add, Nat.add_zero] at hr
    rw [hr, pow_mul, domainRoot_8192_sq]
  rw [hnode, evaluatePolynomialcoeff_eq,
    fftField_coeffPolynomial_eval (k := 12) domainRoot_4096_primitive
      (polynomialEvalToCoeff a) (computeRootsOfUnity 4096)
      (coeff_size a ha) (size_computeRootsOfUnity 4096) hroots _ hrev]
  have hround : fftField (polynomialEvalToCoeff a) (computeRootsOfUnity 4096) false =
      bitReversalPermutation a := by
    exact fftField_inv_fftField (k := 12) domainRoot_4096_primitive
      (bitReversalPermutation a) (computeRootsOfUnity 4096)
      (by simpa only [size_bitReversalPermutation] using ha)
      (size_computeRootsOfUnity 4096) hroots
  rw [hround, getElem!_pos _ _ (by simpa only [size_bitReversalPermutation, ha] using hrev),
    getElem_bitReversalPermutation, ha, reverseBits_reverseBits (k := 12) hj]

theorem coeff_eval_extension (a : Array Fr) (ha : a.size = 4096)
    (j : Nat) (hj : j < 4096) :
    evaluatePolynomialcoeff (polynomialEvalToCoeff a)
      ((rootsOfUnityBrp 8192)[4096 + j]!) =
        (bitReversalPermutation (Model.extension a))[j]! := by
  have hroots : ∀ i, i < 2 ^ 12 →
      (computeRootsOfUnity 4096)[i]! = domainRoot 4096 ^ i :=
    fun i hi => getElem!_computeRootsOfUnity_pow 4096 i hi
  have hrev : reverseBits j 4096 < 2 ^ 12 := reverseBits_lt_two_pow j 12
  have hnode : (rootsOfUnityBrp 8192)[4096 + j]! =
      domainRoot 8192 * domainRoot 4096 ^ reverseBits j 4096 := by
    rw [getElem!_rootsOfUnityBrp_pow 8192 13 (4096 + j) rfl (by omega)]
    have hr := reverseBits_half_split 1 j (by decide) hj
    simp only [Nat.mul_one] at hr
    rw [hr, pow_add, pow_mul, domainRoot_8192_sq, pow_one, mul_comm]
    rfl
  rw [hnode, evaluatePolynomialcoeff_eq, ← coeffPolynomial_shiftVals_eval,
    fftField_coeffPolynomial_eval (k := 12) domainRoot_4096_primitive
      (shiftVals (polynomialEvalToCoeff a) (domainRoot 8192)) (computeRootsOfUnity 4096)
      (by rw [size_shiftVals]; exact coeff_size a ha)
      (size_computeRootsOfUnity 4096) hroots _ hrev,
    ← extension_eq a ha,
    getElem!_pos (bitReversalPermutation (Model.extension a)) j
      (by simpa only [size_bitReversalPermutation, extension_size a ha] using hj),
    getElem_bitReversalPermutation, extension_size a ha]

end LeanBlsSimd.Kzg.Extender
