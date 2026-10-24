import LeanBlsSimd.Portable.Fp.Reduction
import LeanBlsSimd.Portable.Fp.MultiplyAdd

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open LeanBlsSimd.Word64

namespace LeanBlsSimd.Portable.Fp.Controls

theorem modulus_is_not_a_canonical_result :
    portable.fp.below_p bls.constants.P_U64 ≠ ok bls.constants.P_U64 := by
  intro h
  obtain ⟨out,he,hv⟩ := below_p_refines bls.constants.P_U64 (by rw [modulus_words]; norm_num [EthLib.Cryptography.Bls.Fp.modulus])
  have hout := Result.ok.inj (he.symm.trans h)
  rw [hout,modulus_words] at hv
  norm_num [EthLib.Cryptography.Bls.Fp.modulus] at hv

theorem shifted_high_product_is_not_discarded :
    portable.fp.mul_add (Array.repeat 7#usize 0#u64)
      (Array.make 6#usize [0#u64,0#u64,0#u64,0#u64,0#u64,9223372036854775808#u64] (by rfl)) 2#u64 ≠
      ok (Array.repeat 7#usize 0#u64) := by
  intro h
  obtain ⟨out,he,hv⟩ := mul_add_refines (Array.repeat 7#usize 0#u64)
    (Array.make 6#usize [0#u64,0#u64,0#u64,0#u64,0#u64,9223372036854775808#u64] (by rfl)) 2#u64
  have hout := Result.ok.inj (he.symm.trans h)
  rw [hout] at hv
  norm_num [value,wordsValue,Array.make,Array.repeat,radix] at hv
  rw [wordsValue_repeat_zero] at hv
  norm_num at hv

#print axioms negative_mask_refines
#print axioms below_p_refines
#print axioms mul_add_refines

end LeanBlsSimd.Portable.Fp.Controls
