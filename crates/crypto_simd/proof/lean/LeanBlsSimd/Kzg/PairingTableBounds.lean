import LeanBlsSimd.Kzg.PairingTable

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

/-- A lane in the extracted fixed table, before changing Montgomery radix. -/
def pairingRaw (step : Fin 68) (lane : Fin 8) : Aeneas.Std.Array U64 8#usize :=
  (pairing_lines.PAIRING_LINES.val[step.val]'(by simp)).val[lane.val]'(by simp)

def pairingRawValue (raw : Aeneas.Std.Array U64 8#usize) : Nat :=
  raw.val.foldr (fun word acc => word.val + 2^52 * acc) 0

/-- Normal radix-2^52 limbs and a canonical value; the latter prevents pack64 truncation. -/
def PairingLaneBounds (raw : Aeneas.Std.Array U64 8#usize) : Prop :=
  (∀ word ∈ raw.val, word.val < 2^52) ∧ pairingRawValue raw < Fp.modulus

set_option maxRecDepth 8000
set_option maxHeartbeats 4000000

private theorem bounds_0_0 : PairingLaneBounds (pairingRaw 0 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_1 : PairingLaneBounds (pairingRaw 0 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_2 : PairingLaneBounds (pairingRaw 0 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_3 : PairingLaneBounds (pairingRaw 0 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_4 : PairingLaneBounds (pairingRaw 0 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_5 : PairingLaneBounds (pairingRaw 0 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_6 : PairingLaneBounds (pairingRaw 0 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0_7 : PairingLaneBounds (pairingRaw 0 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_0 (lane : Fin 8) : PairingLaneBounds (pairingRaw 0 lane) := by
  fin_cases lane
  · exact bounds_0_0
  · exact bounds_0_1
  · exact bounds_0_2
  · exact bounds_0_3
  · exact bounds_0_4
  · exact bounds_0_5
  · exact bounds_0_6
  · exact bounds_0_7

private theorem bounds_1_0 : PairingLaneBounds (pairingRaw 1 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_1 : PairingLaneBounds (pairingRaw 1 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_2 : PairingLaneBounds (pairingRaw 1 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_3 : PairingLaneBounds (pairingRaw 1 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_4 : PairingLaneBounds (pairingRaw 1 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_5 : PairingLaneBounds (pairingRaw 1 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_6 : PairingLaneBounds (pairingRaw 1 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1_7 : PairingLaneBounds (pairingRaw 1 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_1 (lane : Fin 8) : PairingLaneBounds (pairingRaw 1 lane) := by
  fin_cases lane
  · exact bounds_1_0
  · exact bounds_1_1
  · exact bounds_1_2
  · exact bounds_1_3
  · exact bounds_1_4
  · exact bounds_1_5
  · exact bounds_1_6
  · exact bounds_1_7

private theorem bounds_2_0 : PairingLaneBounds (pairingRaw 2 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_1 : PairingLaneBounds (pairingRaw 2 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_2 : PairingLaneBounds (pairingRaw 2 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_3 : PairingLaneBounds (pairingRaw 2 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_4 : PairingLaneBounds (pairingRaw 2 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_5 : PairingLaneBounds (pairingRaw 2 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_6 : PairingLaneBounds (pairingRaw 2 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2_7 : PairingLaneBounds (pairingRaw 2 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_2 (lane : Fin 8) : PairingLaneBounds (pairingRaw 2 lane) := by
  fin_cases lane
  · exact bounds_2_0
  · exact bounds_2_1
  · exact bounds_2_2
  · exact bounds_2_3
  · exact bounds_2_4
  · exact bounds_2_5
  · exact bounds_2_6
  · exact bounds_2_7

private theorem bounds_3_0 : PairingLaneBounds (pairingRaw 3 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_1 : PairingLaneBounds (pairingRaw 3 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_2 : PairingLaneBounds (pairingRaw 3 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_3 : PairingLaneBounds (pairingRaw 3 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_4 : PairingLaneBounds (pairingRaw 3 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_5 : PairingLaneBounds (pairingRaw 3 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_6 : PairingLaneBounds (pairingRaw 3 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3_7 : PairingLaneBounds (pairingRaw 3 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_3 (lane : Fin 8) : PairingLaneBounds (pairingRaw 3 lane) := by
  fin_cases lane
  · exact bounds_3_0
  · exact bounds_3_1
  · exact bounds_3_2
  · exact bounds_3_3
  · exact bounds_3_4
  · exact bounds_3_5
  · exact bounds_3_6
  · exact bounds_3_7

private theorem bounds_4_0 : PairingLaneBounds (pairingRaw 4 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_1 : PairingLaneBounds (pairingRaw 4 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_2 : PairingLaneBounds (pairingRaw 4 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_3 : PairingLaneBounds (pairingRaw 4 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_4 : PairingLaneBounds (pairingRaw 4 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_5 : PairingLaneBounds (pairingRaw 4 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_6 : PairingLaneBounds (pairingRaw 4 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4_7 : PairingLaneBounds (pairingRaw 4 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_4 (lane : Fin 8) : PairingLaneBounds (pairingRaw 4 lane) := by
  fin_cases lane
  · exact bounds_4_0
  · exact bounds_4_1
  · exact bounds_4_2
  · exact bounds_4_3
  · exact bounds_4_4
  · exact bounds_4_5
  · exact bounds_4_6
  · exact bounds_4_7

private theorem bounds_5_0 : PairingLaneBounds (pairingRaw 5 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_1 : PairingLaneBounds (pairingRaw 5 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_2 : PairingLaneBounds (pairingRaw 5 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_3 : PairingLaneBounds (pairingRaw 5 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_4 : PairingLaneBounds (pairingRaw 5 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_5 : PairingLaneBounds (pairingRaw 5 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_6 : PairingLaneBounds (pairingRaw 5 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5_7 : PairingLaneBounds (pairingRaw 5 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_5 (lane : Fin 8) : PairingLaneBounds (pairingRaw 5 lane) := by
  fin_cases lane
  · exact bounds_5_0
  · exact bounds_5_1
  · exact bounds_5_2
  · exact bounds_5_3
  · exact bounds_5_4
  · exact bounds_5_5
  · exact bounds_5_6
  · exact bounds_5_7

private theorem bounds_6_0 : PairingLaneBounds (pairingRaw 6 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_1 : PairingLaneBounds (pairingRaw 6 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_2 : PairingLaneBounds (pairingRaw 6 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_3 : PairingLaneBounds (pairingRaw 6 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_4 : PairingLaneBounds (pairingRaw 6 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_5 : PairingLaneBounds (pairingRaw 6 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_6 : PairingLaneBounds (pairingRaw 6 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6_7 : PairingLaneBounds (pairingRaw 6 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_6 (lane : Fin 8) : PairingLaneBounds (pairingRaw 6 lane) := by
  fin_cases lane
  · exact bounds_6_0
  · exact bounds_6_1
  · exact bounds_6_2
  · exact bounds_6_3
  · exact bounds_6_4
  · exact bounds_6_5
  · exact bounds_6_6
  · exact bounds_6_7

private theorem bounds_7_0 : PairingLaneBounds (pairingRaw 7 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_1 : PairingLaneBounds (pairingRaw 7 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_2 : PairingLaneBounds (pairingRaw 7 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_3 : PairingLaneBounds (pairingRaw 7 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_4 : PairingLaneBounds (pairingRaw 7 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_5 : PairingLaneBounds (pairingRaw 7 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_6 : PairingLaneBounds (pairingRaw 7 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7_7 : PairingLaneBounds (pairingRaw 7 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_7 (lane : Fin 8) : PairingLaneBounds (pairingRaw 7 lane) := by
  fin_cases lane
  · exact bounds_7_0
  · exact bounds_7_1
  · exact bounds_7_2
  · exact bounds_7_3
  · exact bounds_7_4
  · exact bounds_7_5
  · exact bounds_7_6
  · exact bounds_7_7

private theorem bounds_8_0 : PairingLaneBounds (pairingRaw 8 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_1 : PairingLaneBounds (pairingRaw 8 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_2 : PairingLaneBounds (pairingRaw 8 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_3 : PairingLaneBounds (pairingRaw 8 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_4 : PairingLaneBounds (pairingRaw 8 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_5 : PairingLaneBounds (pairingRaw 8 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_6 : PairingLaneBounds (pairingRaw 8 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8_7 : PairingLaneBounds (pairingRaw 8 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_8 (lane : Fin 8) : PairingLaneBounds (pairingRaw 8 lane) := by
  fin_cases lane
  · exact bounds_8_0
  · exact bounds_8_1
  · exact bounds_8_2
  · exact bounds_8_3
  · exact bounds_8_4
  · exact bounds_8_5
  · exact bounds_8_6
  · exact bounds_8_7

private theorem bounds_9_0 : PairingLaneBounds (pairingRaw 9 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_1 : PairingLaneBounds (pairingRaw 9 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_2 : PairingLaneBounds (pairingRaw 9 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_3 : PairingLaneBounds (pairingRaw 9 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_4 : PairingLaneBounds (pairingRaw 9 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_5 : PairingLaneBounds (pairingRaw 9 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_6 : PairingLaneBounds (pairingRaw 9 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9_7 : PairingLaneBounds (pairingRaw 9 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_9 (lane : Fin 8) : PairingLaneBounds (pairingRaw 9 lane) := by
  fin_cases lane
  · exact bounds_9_0
  · exact bounds_9_1
  · exact bounds_9_2
  · exact bounds_9_3
  · exact bounds_9_4
  · exact bounds_9_5
  · exact bounds_9_6
  · exact bounds_9_7

private theorem bounds_10_0 : PairingLaneBounds (pairingRaw 10 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_1 : PairingLaneBounds (pairingRaw 10 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_2 : PairingLaneBounds (pairingRaw 10 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_3 : PairingLaneBounds (pairingRaw 10 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_4 : PairingLaneBounds (pairingRaw 10 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_5 : PairingLaneBounds (pairingRaw 10 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_6 : PairingLaneBounds (pairingRaw 10 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10_7 : PairingLaneBounds (pairingRaw 10 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_10 (lane : Fin 8) : PairingLaneBounds (pairingRaw 10 lane) := by
  fin_cases lane
  · exact bounds_10_0
  · exact bounds_10_1
  · exact bounds_10_2
  · exact bounds_10_3
  · exact bounds_10_4
  · exact bounds_10_5
  · exact bounds_10_6
  · exact bounds_10_7

private theorem bounds_11_0 : PairingLaneBounds (pairingRaw 11 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_1 : PairingLaneBounds (pairingRaw 11 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_2 : PairingLaneBounds (pairingRaw 11 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_3 : PairingLaneBounds (pairingRaw 11 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_4 : PairingLaneBounds (pairingRaw 11 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_5 : PairingLaneBounds (pairingRaw 11 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_6 : PairingLaneBounds (pairingRaw 11 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11_7 : PairingLaneBounds (pairingRaw 11 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_11 (lane : Fin 8) : PairingLaneBounds (pairingRaw 11 lane) := by
  fin_cases lane
  · exact bounds_11_0
  · exact bounds_11_1
  · exact bounds_11_2
  · exact bounds_11_3
  · exact bounds_11_4
  · exact bounds_11_5
  · exact bounds_11_6
  · exact bounds_11_7

private theorem bounds_12_0 : PairingLaneBounds (pairingRaw 12 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_1 : PairingLaneBounds (pairingRaw 12 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_2 : PairingLaneBounds (pairingRaw 12 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_3 : PairingLaneBounds (pairingRaw 12 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_4 : PairingLaneBounds (pairingRaw 12 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_5 : PairingLaneBounds (pairingRaw 12 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_6 : PairingLaneBounds (pairingRaw 12 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12_7 : PairingLaneBounds (pairingRaw 12 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_12 (lane : Fin 8) : PairingLaneBounds (pairingRaw 12 lane) := by
  fin_cases lane
  · exact bounds_12_0
  · exact bounds_12_1
  · exact bounds_12_2
  · exact bounds_12_3
  · exact bounds_12_4
  · exact bounds_12_5
  · exact bounds_12_6
  · exact bounds_12_7

private theorem bounds_13_0 : PairingLaneBounds (pairingRaw 13 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_1 : PairingLaneBounds (pairingRaw 13 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_2 : PairingLaneBounds (pairingRaw 13 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_3 : PairingLaneBounds (pairingRaw 13 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_4 : PairingLaneBounds (pairingRaw 13 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_5 : PairingLaneBounds (pairingRaw 13 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_6 : PairingLaneBounds (pairingRaw 13 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13_7 : PairingLaneBounds (pairingRaw 13 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_13 (lane : Fin 8) : PairingLaneBounds (pairingRaw 13 lane) := by
  fin_cases lane
  · exact bounds_13_0
  · exact bounds_13_1
  · exact bounds_13_2
  · exact bounds_13_3
  · exact bounds_13_4
  · exact bounds_13_5
  · exact bounds_13_6
  · exact bounds_13_7

private theorem bounds_14_0 : PairingLaneBounds (pairingRaw 14 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_1 : PairingLaneBounds (pairingRaw 14 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_2 : PairingLaneBounds (pairingRaw 14 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_3 : PairingLaneBounds (pairingRaw 14 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_4 : PairingLaneBounds (pairingRaw 14 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_5 : PairingLaneBounds (pairingRaw 14 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_6 : PairingLaneBounds (pairingRaw 14 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14_7 : PairingLaneBounds (pairingRaw 14 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_14 (lane : Fin 8) : PairingLaneBounds (pairingRaw 14 lane) := by
  fin_cases lane
  · exact bounds_14_0
  · exact bounds_14_1
  · exact bounds_14_2
  · exact bounds_14_3
  · exact bounds_14_4
  · exact bounds_14_5
  · exact bounds_14_6
  · exact bounds_14_7

private theorem bounds_15_0 : PairingLaneBounds (pairingRaw 15 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_1 : PairingLaneBounds (pairingRaw 15 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_2 : PairingLaneBounds (pairingRaw 15 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_3 : PairingLaneBounds (pairingRaw 15 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_4 : PairingLaneBounds (pairingRaw 15 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_5 : PairingLaneBounds (pairingRaw 15 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_6 : PairingLaneBounds (pairingRaw 15 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15_7 : PairingLaneBounds (pairingRaw 15 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_15 (lane : Fin 8) : PairingLaneBounds (pairingRaw 15 lane) := by
  fin_cases lane
  · exact bounds_15_0
  · exact bounds_15_1
  · exact bounds_15_2
  · exact bounds_15_3
  · exact bounds_15_4
  · exact bounds_15_5
  · exact bounds_15_6
  · exact bounds_15_7

private theorem bounds_16_0 : PairingLaneBounds (pairingRaw 16 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_1 : PairingLaneBounds (pairingRaw 16 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_2 : PairingLaneBounds (pairingRaw 16 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_3 : PairingLaneBounds (pairingRaw 16 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_4 : PairingLaneBounds (pairingRaw 16 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_5 : PairingLaneBounds (pairingRaw 16 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_6 : PairingLaneBounds (pairingRaw 16 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16_7 : PairingLaneBounds (pairingRaw 16 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_16 (lane : Fin 8) : PairingLaneBounds (pairingRaw 16 lane) := by
  fin_cases lane
  · exact bounds_16_0
  · exact bounds_16_1
  · exact bounds_16_2
  · exact bounds_16_3
  · exact bounds_16_4
  · exact bounds_16_5
  · exact bounds_16_6
  · exact bounds_16_7

private theorem bounds_17_0 : PairingLaneBounds (pairingRaw 17 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_1 : PairingLaneBounds (pairingRaw 17 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_2 : PairingLaneBounds (pairingRaw 17 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_3 : PairingLaneBounds (pairingRaw 17 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_4 : PairingLaneBounds (pairingRaw 17 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_5 : PairingLaneBounds (pairingRaw 17 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_6 : PairingLaneBounds (pairingRaw 17 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17_7 : PairingLaneBounds (pairingRaw 17 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_17 (lane : Fin 8) : PairingLaneBounds (pairingRaw 17 lane) := by
  fin_cases lane
  · exact bounds_17_0
  · exact bounds_17_1
  · exact bounds_17_2
  · exact bounds_17_3
  · exact bounds_17_4
  · exact bounds_17_5
  · exact bounds_17_6
  · exact bounds_17_7

private theorem bounds_18_0 : PairingLaneBounds (pairingRaw 18 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_1 : PairingLaneBounds (pairingRaw 18 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_2 : PairingLaneBounds (pairingRaw 18 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_3 : PairingLaneBounds (pairingRaw 18 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_4 : PairingLaneBounds (pairingRaw 18 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_5 : PairingLaneBounds (pairingRaw 18 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_6 : PairingLaneBounds (pairingRaw 18 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18_7 : PairingLaneBounds (pairingRaw 18 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_18 (lane : Fin 8) : PairingLaneBounds (pairingRaw 18 lane) := by
  fin_cases lane
  · exact bounds_18_0
  · exact bounds_18_1
  · exact bounds_18_2
  · exact bounds_18_3
  · exact bounds_18_4
  · exact bounds_18_5
  · exact bounds_18_6
  · exact bounds_18_7

private theorem bounds_19_0 : PairingLaneBounds (pairingRaw 19 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_1 : PairingLaneBounds (pairingRaw 19 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_2 : PairingLaneBounds (pairingRaw 19 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_3 : PairingLaneBounds (pairingRaw 19 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_4 : PairingLaneBounds (pairingRaw 19 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_5 : PairingLaneBounds (pairingRaw 19 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_6 : PairingLaneBounds (pairingRaw 19 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19_7 : PairingLaneBounds (pairingRaw 19 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_19 (lane : Fin 8) : PairingLaneBounds (pairingRaw 19 lane) := by
  fin_cases lane
  · exact bounds_19_0
  · exact bounds_19_1
  · exact bounds_19_2
  · exact bounds_19_3
  · exact bounds_19_4
  · exact bounds_19_5
  · exact bounds_19_6
  · exact bounds_19_7

private theorem bounds_20_0 : PairingLaneBounds (pairingRaw 20 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_1 : PairingLaneBounds (pairingRaw 20 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_2 : PairingLaneBounds (pairingRaw 20 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_3 : PairingLaneBounds (pairingRaw 20 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_4 : PairingLaneBounds (pairingRaw 20 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_5 : PairingLaneBounds (pairingRaw 20 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_6 : PairingLaneBounds (pairingRaw 20 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20_7 : PairingLaneBounds (pairingRaw 20 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_20 (lane : Fin 8) : PairingLaneBounds (pairingRaw 20 lane) := by
  fin_cases lane
  · exact bounds_20_0
  · exact bounds_20_1
  · exact bounds_20_2
  · exact bounds_20_3
  · exact bounds_20_4
  · exact bounds_20_5
  · exact bounds_20_6
  · exact bounds_20_7

private theorem bounds_21_0 : PairingLaneBounds (pairingRaw 21 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_1 : PairingLaneBounds (pairingRaw 21 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_2 : PairingLaneBounds (pairingRaw 21 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_3 : PairingLaneBounds (pairingRaw 21 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_4 : PairingLaneBounds (pairingRaw 21 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_5 : PairingLaneBounds (pairingRaw 21 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_6 : PairingLaneBounds (pairingRaw 21 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21_7 : PairingLaneBounds (pairingRaw 21 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_21 (lane : Fin 8) : PairingLaneBounds (pairingRaw 21 lane) := by
  fin_cases lane
  · exact bounds_21_0
  · exact bounds_21_1
  · exact bounds_21_2
  · exact bounds_21_3
  · exact bounds_21_4
  · exact bounds_21_5
  · exact bounds_21_6
  · exact bounds_21_7

private theorem bounds_22_0 : PairingLaneBounds (pairingRaw 22 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_1 : PairingLaneBounds (pairingRaw 22 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_2 : PairingLaneBounds (pairingRaw 22 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_3 : PairingLaneBounds (pairingRaw 22 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_4 : PairingLaneBounds (pairingRaw 22 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_5 : PairingLaneBounds (pairingRaw 22 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_6 : PairingLaneBounds (pairingRaw 22 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22_7 : PairingLaneBounds (pairingRaw 22 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_22 (lane : Fin 8) : PairingLaneBounds (pairingRaw 22 lane) := by
  fin_cases lane
  · exact bounds_22_0
  · exact bounds_22_1
  · exact bounds_22_2
  · exact bounds_22_3
  · exact bounds_22_4
  · exact bounds_22_5
  · exact bounds_22_6
  · exact bounds_22_7

private theorem bounds_23_0 : PairingLaneBounds (pairingRaw 23 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_1 : PairingLaneBounds (pairingRaw 23 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_2 : PairingLaneBounds (pairingRaw 23 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_3 : PairingLaneBounds (pairingRaw 23 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_4 : PairingLaneBounds (pairingRaw 23 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_5 : PairingLaneBounds (pairingRaw 23 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_6 : PairingLaneBounds (pairingRaw 23 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23_7 : PairingLaneBounds (pairingRaw 23 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_23 (lane : Fin 8) : PairingLaneBounds (pairingRaw 23 lane) := by
  fin_cases lane
  · exact bounds_23_0
  · exact bounds_23_1
  · exact bounds_23_2
  · exact bounds_23_3
  · exact bounds_23_4
  · exact bounds_23_5
  · exact bounds_23_6
  · exact bounds_23_7

private theorem bounds_24_0 : PairingLaneBounds (pairingRaw 24 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_1 : PairingLaneBounds (pairingRaw 24 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_2 : PairingLaneBounds (pairingRaw 24 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_3 : PairingLaneBounds (pairingRaw 24 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_4 : PairingLaneBounds (pairingRaw 24 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_5 : PairingLaneBounds (pairingRaw 24 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_6 : PairingLaneBounds (pairingRaw 24 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24_7 : PairingLaneBounds (pairingRaw 24 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_24 (lane : Fin 8) : PairingLaneBounds (pairingRaw 24 lane) := by
  fin_cases lane
  · exact bounds_24_0
  · exact bounds_24_1
  · exact bounds_24_2
  · exact bounds_24_3
  · exact bounds_24_4
  · exact bounds_24_5
  · exact bounds_24_6
  · exact bounds_24_7

private theorem bounds_25_0 : PairingLaneBounds (pairingRaw 25 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_1 : PairingLaneBounds (pairingRaw 25 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_2 : PairingLaneBounds (pairingRaw 25 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_3 : PairingLaneBounds (pairingRaw 25 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_4 : PairingLaneBounds (pairingRaw 25 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_5 : PairingLaneBounds (pairingRaw 25 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_6 : PairingLaneBounds (pairingRaw 25 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25_7 : PairingLaneBounds (pairingRaw 25 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_25 (lane : Fin 8) : PairingLaneBounds (pairingRaw 25 lane) := by
  fin_cases lane
  · exact bounds_25_0
  · exact bounds_25_1
  · exact bounds_25_2
  · exact bounds_25_3
  · exact bounds_25_4
  · exact bounds_25_5
  · exact bounds_25_6
  · exact bounds_25_7

private theorem bounds_26_0 : PairingLaneBounds (pairingRaw 26 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_1 : PairingLaneBounds (pairingRaw 26 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_2 : PairingLaneBounds (pairingRaw 26 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_3 : PairingLaneBounds (pairingRaw 26 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_4 : PairingLaneBounds (pairingRaw 26 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_5 : PairingLaneBounds (pairingRaw 26 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_6 : PairingLaneBounds (pairingRaw 26 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26_7 : PairingLaneBounds (pairingRaw 26 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_26 (lane : Fin 8) : PairingLaneBounds (pairingRaw 26 lane) := by
  fin_cases lane
  · exact bounds_26_0
  · exact bounds_26_1
  · exact bounds_26_2
  · exact bounds_26_3
  · exact bounds_26_4
  · exact bounds_26_5
  · exact bounds_26_6
  · exact bounds_26_7

private theorem bounds_27_0 : PairingLaneBounds (pairingRaw 27 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_1 : PairingLaneBounds (pairingRaw 27 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_2 : PairingLaneBounds (pairingRaw 27 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_3 : PairingLaneBounds (pairingRaw 27 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_4 : PairingLaneBounds (pairingRaw 27 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_5 : PairingLaneBounds (pairingRaw 27 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_6 : PairingLaneBounds (pairingRaw 27 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27_7 : PairingLaneBounds (pairingRaw 27 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_27 (lane : Fin 8) : PairingLaneBounds (pairingRaw 27 lane) := by
  fin_cases lane
  · exact bounds_27_0
  · exact bounds_27_1
  · exact bounds_27_2
  · exact bounds_27_3
  · exact bounds_27_4
  · exact bounds_27_5
  · exact bounds_27_6
  · exact bounds_27_7

private theorem bounds_28_0 : PairingLaneBounds (pairingRaw 28 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_1 : PairingLaneBounds (pairingRaw 28 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_2 : PairingLaneBounds (pairingRaw 28 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_3 : PairingLaneBounds (pairingRaw 28 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_4 : PairingLaneBounds (pairingRaw 28 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_5 : PairingLaneBounds (pairingRaw 28 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_6 : PairingLaneBounds (pairingRaw 28 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28_7 : PairingLaneBounds (pairingRaw 28 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_28 (lane : Fin 8) : PairingLaneBounds (pairingRaw 28 lane) := by
  fin_cases lane
  · exact bounds_28_0
  · exact bounds_28_1
  · exact bounds_28_2
  · exact bounds_28_3
  · exact bounds_28_4
  · exact bounds_28_5
  · exact bounds_28_6
  · exact bounds_28_7

private theorem bounds_29_0 : PairingLaneBounds (pairingRaw 29 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_1 : PairingLaneBounds (pairingRaw 29 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_2 : PairingLaneBounds (pairingRaw 29 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_3 : PairingLaneBounds (pairingRaw 29 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_4 : PairingLaneBounds (pairingRaw 29 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_5 : PairingLaneBounds (pairingRaw 29 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_6 : PairingLaneBounds (pairingRaw 29 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29_7 : PairingLaneBounds (pairingRaw 29 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_29 (lane : Fin 8) : PairingLaneBounds (pairingRaw 29 lane) := by
  fin_cases lane
  · exact bounds_29_0
  · exact bounds_29_1
  · exact bounds_29_2
  · exact bounds_29_3
  · exact bounds_29_4
  · exact bounds_29_5
  · exact bounds_29_6
  · exact bounds_29_7

private theorem bounds_30_0 : PairingLaneBounds (pairingRaw 30 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_1 : PairingLaneBounds (pairingRaw 30 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_2 : PairingLaneBounds (pairingRaw 30 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_3 : PairingLaneBounds (pairingRaw 30 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_4 : PairingLaneBounds (pairingRaw 30 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_5 : PairingLaneBounds (pairingRaw 30 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_6 : PairingLaneBounds (pairingRaw 30 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30_7 : PairingLaneBounds (pairingRaw 30 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_30 (lane : Fin 8) : PairingLaneBounds (pairingRaw 30 lane) := by
  fin_cases lane
  · exact bounds_30_0
  · exact bounds_30_1
  · exact bounds_30_2
  · exact bounds_30_3
  · exact bounds_30_4
  · exact bounds_30_5
  · exact bounds_30_6
  · exact bounds_30_7

private theorem bounds_31_0 : PairingLaneBounds (pairingRaw 31 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_1 : PairingLaneBounds (pairingRaw 31 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_2 : PairingLaneBounds (pairingRaw 31 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_3 : PairingLaneBounds (pairingRaw 31 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_4 : PairingLaneBounds (pairingRaw 31 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_5 : PairingLaneBounds (pairingRaw 31 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_6 : PairingLaneBounds (pairingRaw 31 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31_7 : PairingLaneBounds (pairingRaw 31 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_31 (lane : Fin 8) : PairingLaneBounds (pairingRaw 31 lane) := by
  fin_cases lane
  · exact bounds_31_0
  · exact bounds_31_1
  · exact bounds_31_2
  · exact bounds_31_3
  · exact bounds_31_4
  · exact bounds_31_5
  · exact bounds_31_6
  · exact bounds_31_7

private theorem bounds_32_0 : PairingLaneBounds (pairingRaw 32 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_1 : PairingLaneBounds (pairingRaw 32 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_2 : PairingLaneBounds (pairingRaw 32 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_3 : PairingLaneBounds (pairingRaw 32 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_4 : PairingLaneBounds (pairingRaw 32 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_5 : PairingLaneBounds (pairingRaw 32 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_6 : PairingLaneBounds (pairingRaw 32 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32_7 : PairingLaneBounds (pairingRaw 32 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_32 (lane : Fin 8) : PairingLaneBounds (pairingRaw 32 lane) := by
  fin_cases lane
  · exact bounds_32_0
  · exact bounds_32_1
  · exact bounds_32_2
  · exact bounds_32_3
  · exact bounds_32_4
  · exact bounds_32_5
  · exact bounds_32_6
  · exact bounds_32_7

private theorem bounds_33_0 : PairingLaneBounds (pairingRaw 33 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_1 : PairingLaneBounds (pairingRaw 33 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_2 : PairingLaneBounds (pairingRaw 33 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_3 : PairingLaneBounds (pairingRaw 33 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_4 : PairingLaneBounds (pairingRaw 33 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_5 : PairingLaneBounds (pairingRaw 33 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_6 : PairingLaneBounds (pairingRaw 33 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33_7 : PairingLaneBounds (pairingRaw 33 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_33 (lane : Fin 8) : PairingLaneBounds (pairingRaw 33 lane) := by
  fin_cases lane
  · exact bounds_33_0
  · exact bounds_33_1
  · exact bounds_33_2
  · exact bounds_33_3
  · exact bounds_33_4
  · exact bounds_33_5
  · exact bounds_33_6
  · exact bounds_33_7

private theorem bounds_34_0 : PairingLaneBounds (pairingRaw 34 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_1 : PairingLaneBounds (pairingRaw 34 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_2 : PairingLaneBounds (pairingRaw 34 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_3 : PairingLaneBounds (pairingRaw 34 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_4 : PairingLaneBounds (pairingRaw 34 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_5 : PairingLaneBounds (pairingRaw 34 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_6 : PairingLaneBounds (pairingRaw 34 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34_7 : PairingLaneBounds (pairingRaw 34 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_34 (lane : Fin 8) : PairingLaneBounds (pairingRaw 34 lane) := by
  fin_cases lane
  · exact bounds_34_0
  · exact bounds_34_1
  · exact bounds_34_2
  · exact bounds_34_3
  · exact bounds_34_4
  · exact bounds_34_5
  · exact bounds_34_6
  · exact bounds_34_7

private theorem bounds_35_0 : PairingLaneBounds (pairingRaw 35 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_1 : PairingLaneBounds (pairingRaw 35 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_2 : PairingLaneBounds (pairingRaw 35 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_3 : PairingLaneBounds (pairingRaw 35 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_4 : PairingLaneBounds (pairingRaw 35 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_5 : PairingLaneBounds (pairingRaw 35 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_6 : PairingLaneBounds (pairingRaw 35 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35_7 : PairingLaneBounds (pairingRaw 35 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_35 (lane : Fin 8) : PairingLaneBounds (pairingRaw 35 lane) := by
  fin_cases lane
  · exact bounds_35_0
  · exact bounds_35_1
  · exact bounds_35_2
  · exact bounds_35_3
  · exact bounds_35_4
  · exact bounds_35_5
  · exact bounds_35_6
  · exact bounds_35_7

private theorem bounds_36_0 : PairingLaneBounds (pairingRaw 36 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_1 : PairingLaneBounds (pairingRaw 36 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_2 : PairingLaneBounds (pairingRaw 36 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_3 : PairingLaneBounds (pairingRaw 36 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_4 : PairingLaneBounds (pairingRaw 36 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_5 : PairingLaneBounds (pairingRaw 36 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_6 : PairingLaneBounds (pairingRaw 36 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36_7 : PairingLaneBounds (pairingRaw 36 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_36 (lane : Fin 8) : PairingLaneBounds (pairingRaw 36 lane) := by
  fin_cases lane
  · exact bounds_36_0
  · exact bounds_36_1
  · exact bounds_36_2
  · exact bounds_36_3
  · exact bounds_36_4
  · exact bounds_36_5
  · exact bounds_36_6
  · exact bounds_36_7

private theorem bounds_37_0 : PairingLaneBounds (pairingRaw 37 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_1 : PairingLaneBounds (pairingRaw 37 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_2 : PairingLaneBounds (pairingRaw 37 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_3 : PairingLaneBounds (pairingRaw 37 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_4 : PairingLaneBounds (pairingRaw 37 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_5 : PairingLaneBounds (pairingRaw 37 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_6 : PairingLaneBounds (pairingRaw 37 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37_7 : PairingLaneBounds (pairingRaw 37 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_37 (lane : Fin 8) : PairingLaneBounds (pairingRaw 37 lane) := by
  fin_cases lane
  · exact bounds_37_0
  · exact bounds_37_1
  · exact bounds_37_2
  · exact bounds_37_3
  · exact bounds_37_4
  · exact bounds_37_5
  · exact bounds_37_6
  · exact bounds_37_7

private theorem bounds_38_0 : PairingLaneBounds (pairingRaw 38 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_1 : PairingLaneBounds (pairingRaw 38 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_2 : PairingLaneBounds (pairingRaw 38 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_3 : PairingLaneBounds (pairingRaw 38 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_4 : PairingLaneBounds (pairingRaw 38 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_5 : PairingLaneBounds (pairingRaw 38 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_6 : PairingLaneBounds (pairingRaw 38 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38_7 : PairingLaneBounds (pairingRaw 38 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_38 (lane : Fin 8) : PairingLaneBounds (pairingRaw 38 lane) := by
  fin_cases lane
  · exact bounds_38_0
  · exact bounds_38_1
  · exact bounds_38_2
  · exact bounds_38_3
  · exact bounds_38_4
  · exact bounds_38_5
  · exact bounds_38_6
  · exact bounds_38_7

private theorem bounds_39_0 : PairingLaneBounds (pairingRaw 39 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_1 : PairingLaneBounds (pairingRaw 39 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_2 : PairingLaneBounds (pairingRaw 39 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_3 : PairingLaneBounds (pairingRaw 39 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_4 : PairingLaneBounds (pairingRaw 39 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_5 : PairingLaneBounds (pairingRaw 39 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_6 : PairingLaneBounds (pairingRaw 39 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39_7 : PairingLaneBounds (pairingRaw 39 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_39 (lane : Fin 8) : PairingLaneBounds (pairingRaw 39 lane) := by
  fin_cases lane
  · exact bounds_39_0
  · exact bounds_39_1
  · exact bounds_39_2
  · exact bounds_39_3
  · exact bounds_39_4
  · exact bounds_39_5
  · exact bounds_39_6
  · exact bounds_39_7

private theorem bounds_40_0 : PairingLaneBounds (pairingRaw 40 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_1 : PairingLaneBounds (pairingRaw 40 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_2 : PairingLaneBounds (pairingRaw 40 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_3 : PairingLaneBounds (pairingRaw 40 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_4 : PairingLaneBounds (pairingRaw 40 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_5 : PairingLaneBounds (pairingRaw 40 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_6 : PairingLaneBounds (pairingRaw 40 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40_7 : PairingLaneBounds (pairingRaw 40 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_40 (lane : Fin 8) : PairingLaneBounds (pairingRaw 40 lane) := by
  fin_cases lane
  · exact bounds_40_0
  · exact bounds_40_1
  · exact bounds_40_2
  · exact bounds_40_3
  · exact bounds_40_4
  · exact bounds_40_5
  · exact bounds_40_6
  · exact bounds_40_7

private theorem bounds_41_0 : PairingLaneBounds (pairingRaw 41 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_1 : PairingLaneBounds (pairingRaw 41 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_2 : PairingLaneBounds (pairingRaw 41 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_3 : PairingLaneBounds (pairingRaw 41 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_4 : PairingLaneBounds (pairingRaw 41 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_5 : PairingLaneBounds (pairingRaw 41 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_6 : PairingLaneBounds (pairingRaw 41 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41_7 : PairingLaneBounds (pairingRaw 41 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_41 (lane : Fin 8) : PairingLaneBounds (pairingRaw 41 lane) := by
  fin_cases lane
  · exact bounds_41_0
  · exact bounds_41_1
  · exact bounds_41_2
  · exact bounds_41_3
  · exact bounds_41_4
  · exact bounds_41_5
  · exact bounds_41_6
  · exact bounds_41_7

private theorem bounds_42_0 : PairingLaneBounds (pairingRaw 42 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_1 : PairingLaneBounds (pairingRaw 42 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_2 : PairingLaneBounds (pairingRaw 42 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_3 : PairingLaneBounds (pairingRaw 42 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_4 : PairingLaneBounds (pairingRaw 42 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_5 : PairingLaneBounds (pairingRaw 42 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_6 : PairingLaneBounds (pairingRaw 42 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42_7 : PairingLaneBounds (pairingRaw 42 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_42 (lane : Fin 8) : PairingLaneBounds (pairingRaw 42 lane) := by
  fin_cases lane
  · exact bounds_42_0
  · exact bounds_42_1
  · exact bounds_42_2
  · exact bounds_42_3
  · exact bounds_42_4
  · exact bounds_42_5
  · exact bounds_42_6
  · exact bounds_42_7

private theorem bounds_43_0 : PairingLaneBounds (pairingRaw 43 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_1 : PairingLaneBounds (pairingRaw 43 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_2 : PairingLaneBounds (pairingRaw 43 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_3 : PairingLaneBounds (pairingRaw 43 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_4 : PairingLaneBounds (pairingRaw 43 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_5 : PairingLaneBounds (pairingRaw 43 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_6 : PairingLaneBounds (pairingRaw 43 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43_7 : PairingLaneBounds (pairingRaw 43 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_43 (lane : Fin 8) : PairingLaneBounds (pairingRaw 43 lane) := by
  fin_cases lane
  · exact bounds_43_0
  · exact bounds_43_1
  · exact bounds_43_2
  · exact bounds_43_3
  · exact bounds_43_4
  · exact bounds_43_5
  · exact bounds_43_6
  · exact bounds_43_7

private theorem bounds_44_0 : PairingLaneBounds (pairingRaw 44 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_1 : PairingLaneBounds (pairingRaw 44 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_2 : PairingLaneBounds (pairingRaw 44 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_3 : PairingLaneBounds (pairingRaw 44 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_4 : PairingLaneBounds (pairingRaw 44 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_5 : PairingLaneBounds (pairingRaw 44 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_6 : PairingLaneBounds (pairingRaw 44 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44_7 : PairingLaneBounds (pairingRaw 44 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_44 (lane : Fin 8) : PairingLaneBounds (pairingRaw 44 lane) := by
  fin_cases lane
  · exact bounds_44_0
  · exact bounds_44_1
  · exact bounds_44_2
  · exact bounds_44_3
  · exact bounds_44_4
  · exact bounds_44_5
  · exact bounds_44_6
  · exact bounds_44_7

private theorem bounds_45_0 : PairingLaneBounds (pairingRaw 45 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_1 : PairingLaneBounds (pairingRaw 45 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_2 : PairingLaneBounds (pairingRaw 45 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_3 : PairingLaneBounds (pairingRaw 45 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_4 : PairingLaneBounds (pairingRaw 45 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_5 : PairingLaneBounds (pairingRaw 45 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_6 : PairingLaneBounds (pairingRaw 45 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45_7 : PairingLaneBounds (pairingRaw 45 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_45 (lane : Fin 8) : PairingLaneBounds (pairingRaw 45 lane) := by
  fin_cases lane
  · exact bounds_45_0
  · exact bounds_45_1
  · exact bounds_45_2
  · exact bounds_45_3
  · exact bounds_45_4
  · exact bounds_45_5
  · exact bounds_45_6
  · exact bounds_45_7

private theorem bounds_46_0 : PairingLaneBounds (pairingRaw 46 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_1 : PairingLaneBounds (pairingRaw 46 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_2 : PairingLaneBounds (pairingRaw 46 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_3 : PairingLaneBounds (pairingRaw 46 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_4 : PairingLaneBounds (pairingRaw 46 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_5 : PairingLaneBounds (pairingRaw 46 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_6 : PairingLaneBounds (pairingRaw 46 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46_7 : PairingLaneBounds (pairingRaw 46 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_46 (lane : Fin 8) : PairingLaneBounds (pairingRaw 46 lane) := by
  fin_cases lane
  · exact bounds_46_0
  · exact bounds_46_1
  · exact bounds_46_2
  · exact bounds_46_3
  · exact bounds_46_4
  · exact bounds_46_5
  · exact bounds_46_6
  · exact bounds_46_7

private theorem bounds_47_0 : PairingLaneBounds (pairingRaw 47 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_1 : PairingLaneBounds (pairingRaw 47 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_2 : PairingLaneBounds (pairingRaw 47 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_3 : PairingLaneBounds (pairingRaw 47 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_4 : PairingLaneBounds (pairingRaw 47 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_5 : PairingLaneBounds (pairingRaw 47 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_6 : PairingLaneBounds (pairingRaw 47 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47_7 : PairingLaneBounds (pairingRaw 47 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_47 (lane : Fin 8) : PairingLaneBounds (pairingRaw 47 lane) := by
  fin_cases lane
  · exact bounds_47_0
  · exact bounds_47_1
  · exact bounds_47_2
  · exact bounds_47_3
  · exact bounds_47_4
  · exact bounds_47_5
  · exact bounds_47_6
  · exact bounds_47_7

private theorem bounds_48_0 : PairingLaneBounds (pairingRaw 48 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_1 : PairingLaneBounds (pairingRaw 48 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_2 : PairingLaneBounds (pairingRaw 48 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_3 : PairingLaneBounds (pairingRaw 48 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_4 : PairingLaneBounds (pairingRaw 48 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_5 : PairingLaneBounds (pairingRaw 48 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_6 : PairingLaneBounds (pairingRaw 48 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48_7 : PairingLaneBounds (pairingRaw 48 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_48 (lane : Fin 8) : PairingLaneBounds (pairingRaw 48 lane) := by
  fin_cases lane
  · exact bounds_48_0
  · exact bounds_48_1
  · exact bounds_48_2
  · exact bounds_48_3
  · exact bounds_48_4
  · exact bounds_48_5
  · exact bounds_48_6
  · exact bounds_48_7

private theorem bounds_49_0 : PairingLaneBounds (pairingRaw 49 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_1 : PairingLaneBounds (pairingRaw 49 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_2 : PairingLaneBounds (pairingRaw 49 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_3 : PairingLaneBounds (pairingRaw 49 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_4 : PairingLaneBounds (pairingRaw 49 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_5 : PairingLaneBounds (pairingRaw 49 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_6 : PairingLaneBounds (pairingRaw 49 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49_7 : PairingLaneBounds (pairingRaw 49 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_49 (lane : Fin 8) : PairingLaneBounds (pairingRaw 49 lane) := by
  fin_cases lane
  · exact bounds_49_0
  · exact bounds_49_1
  · exact bounds_49_2
  · exact bounds_49_3
  · exact bounds_49_4
  · exact bounds_49_5
  · exact bounds_49_6
  · exact bounds_49_7

private theorem bounds_50_0 : PairingLaneBounds (pairingRaw 50 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_1 : PairingLaneBounds (pairingRaw 50 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_2 : PairingLaneBounds (pairingRaw 50 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_3 : PairingLaneBounds (pairingRaw 50 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_4 : PairingLaneBounds (pairingRaw 50 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_5 : PairingLaneBounds (pairingRaw 50 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_6 : PairingLaneBounds (pairingRaw 50 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50_7 : PairingLaneBounds (pairingRaw 50 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_50 (lane : Fin 8) : PairingLaneBounds (pairingRaw 50 lane) := by
  fin_cases lane
  · exact bounds_50_0
  · exact bounds_50_1
  · exact bounds_50_2
  · exact bounds_50_3
  · exact bounds_50_4
  · exact bounds_50_5
  · exact bounds_50_6
  · exact bounds_50_7

private theorem bounds_51_0 : PairingLaneBounds (pairingRaw 51 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_1 : PairingLaneBounds (pairingRaw 51 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_2 : PairingLaneBounds (pairingRaw 51 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_3 : PairingLaneBounds (pairingRaw 51 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_4 : PairingLaneBounds (pairingRaw 51 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_5 : PairingLaneBounds (pairingRaw 51 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_6 : PairingLaneBounds (pairingRaw 51 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51_7 : PairingLaneBounds (pairingRaw 51 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_51 (lane : Fin 8) : PairingLaneBounds (pairingRaw 51 lane) := by
  fin_cases lane
  · exact bounds_51_0
  · exact bounds_51_1
  · exact bounds_51_2
  · exact bounds_51_3
  · exact bounds_51_4
  · exact bounds_51_5
  · exact bounds_51_6
  · exact bounds_51_7

private theorem bounds_52_0 : PairingLaneBounds (pairingRaw 52 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_1 : PairingLaneBounds (pairingRaw 52 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_2 : PairingLaneBounds (pairingRaw 52 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_3 : PairingLaneBounds (pairingRaw 52 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_4 : PairingLaneBounds (pairingRaw 52 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_5 : PairingLaneBounds (pairingRaw 52 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_6 : PairingLaneBounds (pairingRaw 52 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52_7 : PairingLaneBounds (pairingRaw 52 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_52 (lane : Fin 8) : PairingLaneBounds (pairingRaw 52 lane) := by
  fin_cases lane
  · exact bounds_52_0
  · exact bounds_52_1
  · exact bounds_52_2
  · exact bounds_52_3
  · exact bounds_52_4
  · exact bounds_52_5
  · exact bounds_52_6
  · exact bounds_52_7

private theorem bounds_53_0 : PairingLaneBounds (pairingRaw 53 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_1 : PairingLaneBounds (pairingRaw 53 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_2 : PairingLaneBounds (pairingRaw 53 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_3 : PairingLaneBounds (pairingRaw 53 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_4 : PairingLaneBounds (pairingRaw 53 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_5 : PairingLaneBounds (pairingRaw 53 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_6 : PairingLaneBounds (pairingRaw 53 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53_7 : PairingLaneBounds (pairingRaw 53 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_53 (lane : Fin 8) : PairingLaneBounds (pairingRaw 53 lane) := by
  fin_cases lane
  · exact bounds_53_0
  · exact bounds_53_1
  · exact bounds_53_2
  · exact bounds_53_3
  · exact bounds_53_4
  · exact bounds_53_5
  · exact bounds_53_6
  · exact bounds_53_7

private theorem bounds_54_0 : PairingLaneBounds (pairingRaw 54 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_1 : PairingLaneBounds (pairingRaw 54 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_2 : PairingLaneBounds (pairingRaw 54 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_3 : PairingLaneBounds (pairingRaw 54 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_4 : PairingLaneBounds (pairingRaw 54 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_5 : PairingLaneBounds (pairingRaw 54 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_6 : PairingLaneBounds (pairingRaw 54 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54_7 : PairingLaneBounds (pairingRaw 54 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_54 (lane : Fin 8) : PairingLaneBounds (pairingRaw 54 lane) := by
  fin_cases lane
  · exact bounds_54_0
  · exact bounds_54_1
  · exact bounds_54_2
  · exact bounds_54_3
  · exact bounds_54_4
  · exact bounds_54_5
  · exact bounds_54_6
  · exact bounds_54_7

private theorem bounds_55_0 : PairingLaneBounds (pairingRaw 55 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_1 : PairingLaneBounds (pairingRaw 55 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_2 : PairingLaneBounds (pairingRaw 55 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_3 : PairingLaneBounds (pairingRaw 55 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_4 : PairingLaneBounds (pairingRaw 55 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_5 : PairingLaneBounds (pairingRaw 55 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_6 : PairingLaneBounds (pairingRaw 55 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55_7 : PairingLaneBounds (pairingRaw 55 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_55 (lane : Fin 8) : PairingLaneBounds (pairingRaw 55 lane) := by
  fin_cases lane
  · exact bounds_55_0
  · exact bounds_55_1
  · exact bounds_55_2
  · exact bounds_55_3
  · exact bounds_55_4
  · exact bounds_55_5
  · exact bounds_55_6
  · exact bounds_55_7

private theorem bounds_56_0 : PairingLaneBounds (pairingRaw 56 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_1 : PairingLaneBounds (pairingRaw 56 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_2 : PairingLaneBounds (pairingRaw 56 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_3 : PairingLaneBounds (pairingRaw 56 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_4 : PairingLaneBounds (pairingRaw 56 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_5 : PairingLaneBounds (pairingRaw 56 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_6 : PairingLaneBounds (pairingRaw 56 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56_7 : PairingLaneBounds (pairingRaw 56 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_56 (lane : Fin 8) : PairingLaneBounds (pairingRaw 56 lane) := by
  fin_cases lane
  · exact bounds_56_0
  · exact bounds_56_1
  · exact bounds_56_2
  · exact bounds_56_3
  · exact bounds_56_4
  · exact bounds_56_5
  · exact bounds_56_6
  · exact bounds_56_7

private theorem bounds_57_0 : PairingLaneBounds (pairingRaw 57 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_1 : PairingLaneBounds (pairingRaw 57 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_2 : PairingLaneBounds (pairingRaw 57 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_3 : PairingLaneBounds (pairingRaw 57 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_4 : PairingLaneBounds (pairingRaw 57 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_5 : PairingLaneBounds (pairingRaw 57 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_6 : PairingLaneBounds (pairingRaw 57 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57_7 : PairingLaneBounds (pairingRaw 57 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_57 (lane : Fin 8) : PairingLaneBounds (pairingRaw 57 lane) := by
  fin_cases lane
  · exact bounds_57_0
  · exact bounds_57_1
  · exact bounds_57_2
  · exact bounds_57_3
  · exact bounds_57_4
  · exact bounds_57_5
  · exact bounds_57_6
  · exact bounds_57_7

private theorem bounds_58_0 : PairingLaneBounds (pairingRaw 58 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_1 : PairingLaneBounds (pairingRaw 58 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_2 : PairingLaneBounds (pairingRaw 58 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_3 : PairingLaneBounds (pairingRaw 58 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_4 : PairingLaneBounds (pairingRaw 58 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_5 : PairingLaneBounds (pairingRaw 58 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_6 : PairingLaneBounds (pairingRaw 58 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58_7 : PairingLaneBounds (pairingRaw 58 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_58 (lane : Fin 8) : PairingLaneBounds (pairingRaw 58 lane) := by
  fin_cases lane
  · exact bounds_58_0
  · exact bounds_58_1
  · exact bounds_58_2
  · exact bounds_58_3
  · exact bounds_58_4
  · exact bounds_58_5
  · exact bounds_58_6
  · exact bounds_58_7

private theorem bounds_59_0 : PairingLaneBounds (pairingRaw 59 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_1 : PairingLaneBounds (pairingRaw 59 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_2 : PairingLaneBounds (pairingRaw 59 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_3 : PairingLaneBounds (pairingRaw 59 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_4 : PairingLaneBounds (pairingRaw 59 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_5 : PairingLaneBounds (pairingRaw 59 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_6 : PairingLaneBounds (pairingRaw 59 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59_7 : PairingLaneBounds (pairingRaw 59 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_59 (lane : Fin 8) : PairingLaneBounds (pairingRaw 59 lane) := by
  fin_cases lane
  · exact bounds_59_0
  · exact bounds_59_1
  · exact bounds_59_2
  · exact bounds_59_3
  · exact bounds_59_4
  · exact bounds_59_5
  · exact bounds_59_6
  · exact bounds_59_7

private theorem bounds_60_0 : PairingLaneBounds (pairingRaw 60 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_1 : PairingLaneBounds (pairingRaw 60 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_2 : PairingLaneBounds (pairingRaw 60 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_3 : PairingLaneBounds (pairingRaw 60 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_4 : PairingLaneBounds (pairingRaw 60 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_5 : PairingLaneBounds (pairingRaw 60 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_6 : PairingLaneBounds (pairingRaw 60 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60_7 : PairingLaneBounds (pairingRaw 60 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_60 (lane : Fin 8) : PairingLaneBounds (pairingRaw 60 lane) := by
  fin_cases lane
  · exact bounds_60_0
  · exact bounds_60_1
  · exact bounds_60_2
  · exact bounds_60_3
  · exact bounds_60_4
  · exact bounds_60_5
  · exact bounds_60_6
  · exact bounds_60_7

private theorem bounds_61_0 : PairingLaneBounds (pairingRaw 61 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_1 : PairingLaneBounds (pairingRaw 61 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_2 : PairingLaneBounds (pairingRaw 61 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_3 : PairingLaneBounds (pairingRaw 61 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_4 : PairingLaneBounds (pairingRaw 61 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_5 : PairingLaneBounds (pairingRaw 61 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_6 : PairingLaneBounds (pairingRaw 61 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61_7 : PairingLaneBounds (pairingRaw 61 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_61 (lane : Fin 8) : PairingLaneBounds (pairingRaw 61 lane) := by
  fin_cases lane
  · exact bounds_61_0
  · exact bounds_61_1
  · exact bounds_61_2
  · exact bounds_61_3
  · exact bounds_61_4
  · exact bounds_61_5
  · exact bounds_61_6
  · exact bounds_61_7

private theorem bounds_62_0 : PairingLaneBounds (pairingRaw 62 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_1 : PairingLaneBounds (pairingRaw 62 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_2 : PairingLaneBounds (pairingRaw 62 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_3 : PairingLaneBounds (pairingRaw 62 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_4 : PairingLaneBounds (pairingRaw 62 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_5 : PairingLaneBounds (pairingRaw 62 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_6 : PairingLaneBounds (pairingRaw 62 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62_7 : PairingLaneBounds (pairingRaw 62 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_62 (lane : Fin 8) : PairingLaneBounds (pairingRaw 62 lane) := by
  fin_cases lane
  · exact bounds_62_0
  · exact bounds_62_1
  · exact bounds_62_2
  · exact bounds_62_3
  · exact bounds_62_4
  · exact bounds_62_5
  · exact bounds_62_6
  · exact bounds_62_7

private theorem bounds_63_0 : PairingLaneBounds (pairingRaw 63 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_1 : PairingLaneBounds (pairingRaw 63 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_2 : PairingLaneBounds (pairingRaw 63 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_3 : PairingLaneBounds (pairingRaw 63 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_4 : PairingLaneBounds (pairingRaw 63 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_5 : PairingLaneBounds (pairingRaw 63 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_6 : PairingLaneBounds (pairingRaw 63 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63_7 : PairingLaneBounds (pairingRaw 63 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_63 (lane : Fin 8) : PairingLaneBounds (pairingRaw 63 lane) := by
  fin_cases lane
  · exact bounds_63_0
  · exact bounds_63_1
  · exact bounds_63_2
  · exact bounds_63_3
  · exact bounds_63_4
  · exact bounds_63_5
  · exact bounds_63_6
  · exact bounds_63_7

private theorem bounds_64_0 : PairingLaneBounds (pairingRaw 64 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_1 : PairingLaneBounds (pairingRaw 64 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_2 : PairingLaneBounds (pairingRaw 64 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_3 : PairingLaneBounds (pairingRaw 64 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_4 : PairingLaneBounds (pairingRaw 64 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_5 : PairingLaneBounds (pairingRaw 64 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_6 : PairingLaneBounds (pairingRaw 64 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64_7 : PairingLaneBounds (pairingRaw 64 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_64 (lane : Fin 8) : PairingLaneBounds (pairingRaw 64 lane) := by
  fin_cases lane
  · exact bounds_64_0
  · exact bounds_64_1
  · exact bounds_64_2
  · exact bounds_64_3
  · exact bounds_64_4
  · exact bounds_64_5
  · exact bounds_64_6
  · exact bounds_64_7

private theorem bounds_65_0 : PairingLaneBounds (pairingRaw 65 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_1 : PairingLaneBounds (pairingRaw 65 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_2 : PairingLaneBounds (pairingRaw 65 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_3 : PairingLaneBounds (pairingRaw 65 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_4 : PairingLaneBounds (pairingRaw 65 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_5 : PairingLaneBounds (pairingRaw 65 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_6 : PairingLaneBounds (pairingRaw 65 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65_7 : PairingLaneBounds (pairingRaw 65 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_65 (lane : Fin 8) : PairingLaneBounds (pairingRaw 65 lane) := by
  fin_cases lane
  · exact bounds_65_0
  · exact bounds_65_1
  · exact bounds_65_2
  · exact bounds_65_3
  · exact bounds_65_4
  · exact bounds_65_5
  · exact bounds_65_6
  · exact bounds_65_7

private theorem bounds_66_0 : PairingLaneBounds (pairingRaw 66 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_1 : PairingLaneBounds (pairingRaw 66 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_2 : PairingLaneBounds (pairingRaw 66 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_3 : PairingLaneBounds (pairingRaw 66 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_4 : PairingLaneBounds (pairingRaw 66 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_5 : PairingLaneBounds (pairingRaw 66 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_6 : PairingLaneBounds (pairingRaw 66 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66_7 : PairingLaneBounds (pairingRaw 66 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_66 (lane : Fin 8) : PairingLaneBounds (pairingRaw 66 lane) := by
  fin_cases lane
  · exact bounds_66_0
  · exact bounds_66_1
  · exact bounds_66_2
  · exact bounds_66_3
  · exact bounds_66_4
  · exact bounds_66_5
  · exact bounds_66_6
  · exact bounds_66_7

private theorem bounds_67_0 : PairingLaneBounds (pairingRaw 67 0) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_1 : PairingLaneBounds (pairingRaw 67 1) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_2 : PairingLaneBounds (pairingRaw 67 2) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_3 : PairingLaneBounds (pairingRaw 67 3) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_4 : PairingLaneBounds (pairingRaw 67 4) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_5 : PairingLaneBounds (pairingRaw 67 5) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_6 : PairingLaneBounds (pairingRaw 67 6) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67_7 : PairingLaneBounds (pairingRaw 67 7) := by
  unfold PairingLaneBounds
  decide +kernel

private theorem bounds_67 (lane : Fin 8) : PairingLaneBounds (pairingRaw 67 lane) := by
  fin_cases lane
  · exact bounds_67_0
  · exact bounds_67_1
  · exact bounds_67_2
  · exact bounds_67_3
  · exact bounds_67_4
  · exact bounds_67_5
  · exact bounds_67_6
  · exact bounds_67_7

/-- Kernel-checked bounds for each of the 544 fixed table lanes. -/
theorem pairingRaw_bounds (step : Fin 68) (lane : Fin 8) :
    PairingLaneBounds (pairingRaw step lane) := by
  fin_cases step
  · exact bounds_0 lane
  · exact bounds_1 lane
  · exact bounds_2 lane
  · exact bounds_3 lane
  · exact bounds_4 lane
  · exact bounds_5 lane
  · exact bounds_6 lane
  · exact bounds_7 lane
  · exact bounds_8 lane
  · exact bounds_9 lane
  · exact bounds_10 lane
  · exact bounds_11 lane
  · exact bounds_12 lane
  · exact bounds_13 lane
  · exact bounds_14 lane
  · exact bounds_15 lane
  · exact bounds_16 lane
  · exact bounds_17 lane
  · exact bounds_18 lane
  · exact bounds_19 lane
  · exact bounds_20 lane
  · exact bounds_21 lane
  · exact bounds_22 lane
  · exact bounds_23 lane
  · exact bounds_24 lane
  · exact bounds_25 lane
  · exact bounds_26 lane
  · exact bounds_27 lane
  · exact bounds_28 lane
  · exact bounds_29 lane
  · exact bounds_30 lane
  · exact bounds_31 lane
  · exact bounds_32 lane
  · exact bounds_33 lane
  · exact bounds_34 lane
  · exact bounds_35 lane
  · exact bounds_36 lane
  · exact bounds_37 lane
  · exact bounds_38 lane
  · exact bounds_39 lane
  · exact bounds_40 lane
  · exact bounds_41 lane
  · exact bounds_42 lane
  · exact bounds_43 lane
  · exact bounds_44 lane
  · exact bounds_45 lane
  · exact bounds_46 lane
  · exact bounds_47 lane
  · exact bounds_48 lane
  · exact bounds_49 lane
  · exact bounds_50 lane
  · exact bounds_51 lane
  · exact bounds_52 lane
  · exact bounds_53 lane
  · exact bounds_54 lane
  · exact bounds_55 lane
  · exact bounds_56 lane
  · exact bounds_57 lane
  · exact bounds_58 lane
  · exact bounds_59 lane
  · exact bounds_60 lane
  · exact bounds_61 lane
  · exact bounds_62 lane
  · exact bounds_63 lane
  · exact bounds_64 lane
  · exact bounds_65 lane
  · exact bounds_66 lane
  · exact bounds_67 lane

end LeanBlsSimd.Kzg
