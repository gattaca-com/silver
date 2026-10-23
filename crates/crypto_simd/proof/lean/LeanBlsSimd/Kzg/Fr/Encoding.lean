import LeanBlsSimd.Kzg.Fr.Montgomery
import LeanBlsSimd.Kzg.RepresentationLemmas

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls



namespace LeanBlsSimd.FrScalar
open Word64

theorem encode_value (x : Fr) :
    value (Kzg.frEncode x).l = (((x.val*2^256)%Fr.modulus : Nat) : ℤ) := by
  rw [value_eq_limbs]
  unfold Kzg.frEncode
  rw [Kzg.limbs_words_four _ (Nat.lt_trans (Nat.mod_lt _ Fr.modulus_pos) (by decide))]

theorem encode_bound (x : Fr) : value (Kzg.frEncode x).l < Fr.modulus := by
  rw [encode_value]
  exact_mod_cast Nat.mod_lt (x.val*2^256) Fr.modulus_pos

theorem encode_field (x : Fr) :
    (value (Kzg.frEncode x).l : ZMod Fr.modulus) = Fr.toZMod x*(2^256 : ZMod Fr.modulus) := by
  rw [encode_value]
  push_cast
  have hx : (x.val : ZMod Fr.modulus) = Fr.toZMod x := ZMod.natCast_zmod_val (Fr.toZMod x)
  rw [hx]
  norm_num

theorem eq_encode_of_field (a : Array U64 4#usize) (x : Fr)
    (ha : value a < Fr.modulus)
    (h : (value a : ZMod Fr.modulus) = (value (Kzg.frEncode x).l : ZMod Fr.modulus)) :
    a = (Kzg.frEncode x).l := by
  apply value_injective
  have hval := congrArg (fun z : ZMod Fr.modulus => (z.val : ℤ)) h
  dsimp only at hval
  rw [ZMod.val_intCast,ZMod.val_intCast] at hval
  rw [Int.emod_eq_of_lt (value_bounds a).1 ha,
    Int.emod_eq_of_lt (value_bounds (Kzg.frEncode x).l).1 (encode_bound x)] at hval
  exact hval

end LeanBlsSimd.FrScalar
