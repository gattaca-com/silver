import LeanBlsSimd.Spec.Sha256

open LeanBlsSimd.Sha256.Spec

namespace LeanBlsSimd.Controls.ShaSpec

theorem wrong_round_constant_rejected :
    round constants[0]! 0 (stateWords initialState) ≠
      round 0 0 (stateWords initialState) := by
  intro h
  have hfirst := congrArg MProd.fst h
  exact (by decide +kernel : (round constants[0]! 0 (stateWords initialState)).fst ≠
    (round 0 0 (stateWords initialState)).fst) hfirst

theorem missing_feed_forward_rejected :
    feedForward initialState (stateWords initialState) ≠ initialState := by decide +kernel

theorem one_padding_block_at_55 : 55+1+paddingZeros 55+8 = 64 := by
  rw [padded_length_eq]
  decide

theorem one_padding_block_at_56_rejected : 56+1+paddingZeros 56+8 ≠ 64 := by
  rw [padded_length_eq]
  decide

theorem bit_length_wraps : UInt64.ofNat (2^61+1) <<< (3 : UInt64) = 8 := by
  rw [bitLength_eq]
  decide

theorem unwrapped_byte_count_rejected : (UInt64.ofNat (2^64+1)).toNat ≠ 2^64+1 := by
  decide

end LeanBlsSimd.Controls.ShaSpec

#print axioms LeanBlsSimd.Sha256.Spec.compressBlock_eq
#print axioms LeanBlsSimd.Sha256.Spec.hash_eq
#print axioms LeanBlsSimd.Sha256.Spec.bitLength_eq
