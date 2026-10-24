import LeanBlsSimd.Portable.Fp.PairPowers
import LeanBlsSimd.Portable.Fp.Equality
import LeanBlsSimd.Spec.Sqrt

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp
set_option maxRecDepth 4096

private theorem eq_field_encoded (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.Insts.CoreCmpPartialEqFp.eq (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (decide (x=y)) :=
  eq_encoded x y

theorem sqrt_pair_refines [RuntimeFeatures] (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.sqrt_pair (pairEncode x y) =
      ok (pairEncode (Kernel.sqrtCandidate x) (Kernel.sqrtCandidate y),
        Array.make 2#usize [decide (Kernel.sqrtCandidate x ^ 2 = x),
          decide (Kernel.sqrtCandidate y ^ 2 = y)] (by rfl)) := by
  simp only [portable.fp.Fp.sqrt_pair,pow_p_minus_3_over_4_pair_refines,bind_tc_ok,
    mul_pair_encoded,pair_index_zero,pair_index_one,eq_field_encoded]
  change ok (pairEncode (Kernel.sqrtCandidate x) (Kernel.sqrtCandidate y),
    Array.make 2#usize [decide (Kernel.sqrtCandidate x * Kernel.sqrtCandidate x = x),
      decide (Kernel.sqrtCandidate y * Kernel.sqrtCandidate y = y)] (by rfl)) = _
  rw [←sq,←sq]

end LeanBlsSimd.Portable.Fp
