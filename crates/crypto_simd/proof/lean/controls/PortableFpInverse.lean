import LeanBlsSimd.Portable.Fp.InverseWords

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open LeanBlsSimd.Word64

namespace LeanBlsSimd.Portable.Fp.Controls

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

end LeanBlsSimd.Portable.Fp.Controls
