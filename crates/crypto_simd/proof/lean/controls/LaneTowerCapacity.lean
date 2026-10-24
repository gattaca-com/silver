import LeanBlsSimd.LaneTower.Vectors

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Controls.LaneTowerCapacity

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

private def left : Fp8 := Fp8.splat_limbs (.ofList (limbs52 (8 * (256 * Fp.modulus - 1))))
private def right : Fp8 := Fp8.splat_limbs (.ofList (limbs52 (10 * (256 * Fp.modulus - 1))))

-- The square schedule reaches this range, outside the old 1024p normalization rule.
example : 1024 * Fp.modulus < val (left.lane 0) ∧
    1024 * Fp.modulus < val (right.lane 0) ∧
    val (left.lane 0) * val (right.lane 0) < R * Fp.modulus := by decide +kernel

private theorem left_rep : LaneTower.Normal (fun _ => 2048) (toFp8 left)
    (fun l => decode (left.lane l)) := by
  intro l
  simp only [ofFp8_toFp8]
  refine ⟨?_, ?_, rfl⟩
  · unfold SignedLimbs.Normalized
    fin_cases l <;> decide +kernel
  · fin_cases l <;> decide +kernel

private theorem right_rep : LaneTower.Normal (fun _ => 2560) (toFp8 right)
    (fun l => decode (right.lane l)) := by
  intro l
  simp only [ofFp8_toFp8]
  refine ⟨?_, ?_, rfl⟩
  · unfold SignedLimbs.Normalized
    fin_cases l <;> decide +kernel
  · fin_cases l <;> decide +kernel

example : ∃ out, fp8.Fp8.mul (toFp8 left) (toFp8 right) = ok out ∧
    LaneTower.Normal (fun _ => 2) out
      (fun l => decode (left.lane l) * decode (right.lane l)) :=
  LaneTower.raw_mul left_rep right_rep (by intro l; decide)

-- An insufficient subtraction offset is a concrete negative value, not a timeout control.
example : SignedLimbs.val ((Fp8.zero.sub_raw right (Fp8.multiple_of_p 2048)).lane 0) < 0 := by
  decide +kernel

example : True := by
  fail_if_success
    have : 0 ≤ SignedLimbs.val ((Fp8.zero.sub_raw right (Fp8.multiple_of_p 2048)).lane 0) := by
      decide +kernel
  trivial

end LeanBlsSimd.Controls.LaneTowerCapacity
