import LeanBlsSimd.Portable.Fp.Sqrt
import LeanBlsSimd.Portable.Fp.PairSqrt

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp.Controls
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem to_plain_does_not_keep_montgomery_one [RuntimeFeatures] :
    portable.fp.Fp.to_plain (Kzg.fpEncode 1).l ≠ ok (Kzg.fpEncode 1).l := by
  rw [to_plain_encoded]
  intro h
  have hv := congrArg Word64.value (Result.ok.inj h)
  have hn : Word64.value (Kzg.words 6#usize (1 : Bls.Fp).val) ≠ Word64.value (Kzg.fpEncode 1).l := by decide +kernel
  exact hn hv

theorem one_is_not_the_larger_root [RuntimeFeatures] :
    portable.fp.Fp.is_larger_root (Kzg.fpEncode 1).l ≠ ok true := by
  rw [is_larger_root_refines]
  change ok false ≠ ok true
  intro h
  cases h

theorem minus_one_is_the_larger_root [RuntimeFeatures] :
    portable.fp.Fp.is_larger_root (Kzg.fpEncode (-1)).l = ok true := by
  rw [is_larger_root_refines]
  rfl

theorem scalar_sqrt_zero [RuntimeFeatures] :
    portable.fp.Fp.sqrt (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l = ok (some (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l) := by
  rw [sqrt_refines]
  simp [Kernel.sqrtCandidate,Kernel.powPMinus3Over4,show (Bls.Fp.modulus-3)/4 ≠ 0 by decide]

theorem zero_root_is_not_rejected [RuntimeFeatures] :
    portable.fp.Fp.sqrt (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l ≠ ok none := by
  rw [scalar_sqrt_zero]
  simp

theorem pair_sqrt_zero_one [RuntimeFeatures] :
    portable.fp.Fp.sqrt_pair (pairEncode 0 1) =
      ok (pairEncode 0 1,Array.make 2#usize [true,true] (by rfl)) := by
  rw [sqrt_pair_refines]
  simp [Kernel.sqrtCandidate,Kernel.powPMinus3Over4,show (Bls.Fp.modulus-3)/4 ≠ 0 by decide]

theorem one_validity_bit_cannot_be_dropped [RuntimeFeatures] :
    portable.fp.Fp.sqrt_pair (pairEncode 0 1) ≠
      ok (pairEncode 0 1,Array.make 2#usize [true,false] (by rfl)) := by
  rw [pair_sqrt_zero_one]
  intro h
  have hb := (Prod.mk.inj (Result.ok.inj h)).2
  have hl := congrArg Subtype.val hb
  cases hl

#print axioms to_plain_encoded
#print axioms is_larger_root_refines
#print axioms pow_p_minus_3_over_4_refines
#print axioms pow_p_minus_3_over_4_pair_refines
#print axioms sqrt_refines
#print axioms sqrt_eq_spec
#print axioms sqrt_pair_refines

end LeanBlsSimd.Portable.Fp.Controls
