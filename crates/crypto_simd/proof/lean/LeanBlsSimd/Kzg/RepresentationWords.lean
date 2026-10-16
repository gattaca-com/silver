import LeanBlsSimd.Kzg.Representation
import Aeneas

open Aeneas Aeneas.Std
open EthCryptographySpecs Bls

namespace LeanBlsSimd.Kzg

set_option exponentiation.threshold 512
set_option maxRecDepth 8000
set_option maxHeartbeats 2000000

theorem limbs_words_four (x : Nat) (hx : x < 2^256) :
    limbs (words 4#usize x).val = x := by
  change (x / 2^0 % 2^64 + 2^64 *
    (x / 2^64 % 2^64 + 2^64 *
    (x / 2^128 % 2^64 + 2^64 *
    (x / 2^192 % 2^64 + 2^64 *
    0)))) = x
  norm_num at hx ⊢
  omega

theorem limbs_words_six (x : Nat) (hx : x < 2^384) :
    limbs (words 6#usize x).val = x := by
  change (x / 2^0 % 2^64 + 2^64 *
    (x / 2^64 % 2^64 + 2^64 *
    (x / 2^128 % 2^64 + 2^64 *
    (x / 2^192 % 2^64 + 2^64 *
    (x / 2^256 % 2^64 + 2^64 *
    (x / 2^320 % 2^64 + 2^64 *
    0)))))) = x
  norm_num at hx ⊢
  omega

theorem frEncode_reduced (x : Fr) : FrReduced (frEncode x) := by
  unfold FrReduced frEncode
  rw [limbs_words_four _ (Nat.lt_trans (Nat.mod_lt _ Fr.modulus_pos) (by decide))]
  exact Nat.mod_lt _ Fr.modulus_pos

theorem fpEncode_reduced (x : Fp) : FpReduced (fpEncode x) := by
  unfold FpReduced fpEncode
  rw [limbs_words_six _ (Nat.lt_trans (Nat.mod_lt _ Fp.modulus_pos) (by decide))]
  exact Nat.mod_lt _ Fp.modulus_pos

end LeanBlsSimd.Kzg
