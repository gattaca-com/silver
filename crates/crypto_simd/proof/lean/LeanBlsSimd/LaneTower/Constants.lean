import LeanBlsSimd.Refines.FrobeniusConstants
import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Proofs.Fp8Lazy

open Aeneas Aeneas.Std
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrobeniusConstants

open LeanBlsSimd.Fp6Field (xi)

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 4096

def laneLimbs (j : Fin 6) (i : Fin 2) : Limbs := ofArray ofU64 (laneRow j i)

theorem lane_radix : R = 2 ^ 416 := rfl

theorem lane_value (j : Fin 6) (i : Fin 2) :
    val (laneLimbs j i) = limbValue 52 (laneRow j i) := by
  fin_cases j <;> fin_cases i <;> decide +kernel

theorem lane_entry_bounds (j : Fin 6) (i : Fin 2) :
    SignedLimbs.Normalized (laneLimbs j i) ∧ val (laneLimbs j i) < Fp.modulus := by
  constructor
  · unfold SignedLimbs.Normalized
    fin_cases j <;> fin_cases i <;> decide +kernel
  · rw [lane_value]
    exact (table_bounds j i).2.1

theorem lane_entry_decodes (j : Fin 6) :
    (⟨decode (laneLimbs j 0), decode (laneLimbs j 1)⟩ : Fp2Field) =
      xi ^ (j.val * ((Fp.modulus - 1) / 6)) := by
  rw [← words_spec]
  have h0 : val (laneLimbs j 0) = (words j).1 * R % Fp.modulus := by
    rw [lane_value, lane_radix]
    exact (table_certificates j).2.2.1
  have h1 : val (laneLimbs j 1) = (words j).2 * R % Fp.modulus := by
    rw [lane_value, lane_radix]
    exact (table_certificates j).2.2.2
  rw [decode_of_val h0, decode_of_val h1]
  ext <;> simp [toFp2]

end LeanBlsSimd.FrobeniusConstants

namespace LeanBlsSimd.LaneTower

set_option exponentiation.threshold 4096

theorem product_capacity : 80 * 256 ^ 2 * Fp.modulus < R := by decide +kernel

theorem normalization_capacity : 5121 * Fp.modulus < R := by decide +kernel

theorem power_of_lane (h : Fin 2) (k : Fin 3) :
    (silver_crypto_simd.bls.fp12.POWER_OF_LANE.val[3 * h.val + k.val]!).val =
      2 * k.val + h.val := by
  fin_cases h <;> fin_cases k <;> decide +kernel

end LeanBlsSimd.LaneTower
