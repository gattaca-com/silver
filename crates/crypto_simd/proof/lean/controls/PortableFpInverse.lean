import LeanBlsSimd.Portable.Fp.BatchInverse

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp
open LeanBlsSimd.Word64

namespace LeanBlsSimd.Portable.Fp.Controls
set_option exponentiation.threshold 4096

private def ordinaryOne : portable.fp.Fp :=
  Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)

private theorem zero_value : value (Array.repeat 6#usize 0#u64) = 0 := rfl
private theorem one_value : value ordinaryOne = 1 := by decide +kernel

theorem halving_retains_incoming_bit :
    portable.fp.halve (Array.repeat 6#usize 0#u64) 1#u64 ≠
      ok (Array.repeat 6#usize 0#u64) := by
  intro h
  obtain ⟨out,he,hv⟩ := halve_refines (Array.repeat 6#usize 0#u64) 1#u64 (by decide)
  rw [Result.ok.inj (he.symm.trans h),zero_value] at hv
  norm_num [radix] at hv

theorem odd_coefficient_requires_modulus :
    portable.fp.halve_mod_p ordinaryOne ≠ ok (Array.repeat 6#usize 0#u64) := by
  intro h
  obtain ⟨out,he,hb,hv⟩ := halve_mod_p_refines ordinaryOne
    (by rw [one_value]; decide)
  rw [Result.ok.inj (he.symm.trans h),zero_value,one_value] at hv
  norm_num [Bls.Fp.modulus] at hv

theorem one_test_checks_upper_words :
    portable.fp.is_one
      (Array.make 6#usize [1#u64,1#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)) ≠
      ok true := by
  rw [is_one_refines]
  norm_num [value,wordsValue,Array.make,radix]

#print axioms halve_refines
#print axioms halve_mod_p_refines
#print axioms coefficientSub_refines

theorem inverse_zero_is_zero [RuntimeFeatures] :
    portable.fp.Fp.inverse (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l =
      ok (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l := inverse_zero

theorem inverse_one_is_one [RuntimeFeatures] :
    portable.fp.Fp.inverse (Kzg.fpEncode (1 : ZMod Bls.Fp.modulus)).l =
      ok (Kzg.fpEncode (1 : ZMod Bls.Fp.modulus)).l := by
  simpa only [inv_one] using inverse_encoded (1 : ZMod Bls.Fp.modulus)

theorem inverse_two_is_not_unchanged [RuntimeFeatures] :
    portable.fp.Fp.inverse (Kzg.fpEncode (2 : ZMod Bls.Fp.modulus)).l ≠
      ok (Kzg.fpEncode (2 : ZMod Bls.Fp.modulus)).l := by
  rw [inverse_encoded]
  intro h
  have he := (encoded_eq_iff _ _).mp (congrArg Subtype.val (Result.ok.inj h))
  have hn : (2 : ZMod Bls.Fp.modulus)⁻¹ ≠ 2 := by decide +kernel
  exact hn he

theorem batch_zero_factor_is_not_skipped [RuntimeFeatures] :
    portable.msm.pairs.batch_inverse (encodeFour 0 1 1 1) ≠ ok (encodeFour 0 1 1 1) := by
  rw [batch_inverse_zero_product 0 1 1 1 (by simp)]
  intro h
  have he := congrArg (fun a : Array portable.fp.Fp 4#usize =>
    a.val[1]'(by rw [a.property]; decide)) (Result.ok.inj h)
  have hf : (0 : ZMod Bls.Fp.modulus) = 1 := (encoded_eq_iff _ _).mp (congrArg Subtype.val he)
  exact zero_ne_one hf

theorem batch_four_ones [RuntimeFeatures] :
    portable.msm.pairs.batch_inverse (encodeFour 1 1 1 1) = ok (encodeFour 1 1 1 1) := by
  simpa only [inv_one] using batch_inverse_nonzero 1 1 1 1 one_ne_zero one_ne_zero one_ne_zero one_ne_zero

#print axioms inverse_words_refines
#print axioms inverse_encoded
#print axioms inverse_zero
#print axioms batch_inverse_nonzero
#print axioms batch_inverse_zero_product

end LeanBlsSimd.Portable.Fp.Controls
