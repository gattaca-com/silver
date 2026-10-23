import LeanBlsSimd.Kzg.Extender.Model
import EthLib.Cryptography.Proofs.Kzg.BitReversal

open EthLib.Cryptography Bls Kzg Kzg.BitReversal

namespace LeanBlsSimd.Kzg.Extender

theorem field_bytes_size (x : Fr) : (blsFieldToBytes x).size = 32 := by
  simp only [blsFieldToBytes, Fr.toBytesBE, ByteArray.size, Array.size_ofFn]

private def encodePrefix (a : Array Fr) (n : Nat) : Cell :=
  (List.range n).foldl (fun b i => b ++ blsFieldToBytes a[i]!) ByteArray.empty

private theorem encodePrefix_zero (a : Array Fr) : encodePrefix a 0 = ByteArray.empty := rfl

private theorem encodePrefix_succ (a : Array Fr) (n : Nat) :
    encodePrefix a (n + 1) = encodePrefix a n ++ blsFieldToBytes a[n]! := by
  simp only [encodePrefix, List.range_succ, List.foldl_append, List.foldl_cons,
    List.foldl_nil]

private theorem encodePrefix_size (a : Array Fr) (n : Nat) :
    (encodePrefix a n).size = 32 * n := by
  induction n with
  | zero => rfl
  | succ n ih => rw [encodePrefix_succ, ByteArray.size_append, ih, field_bytes_size]; omega

private theorem encodePrefix_get (a : Array Fr) (n k : Nat) (hk : k < 32 * n) :
    (encodePrefix a n)[k]! = (blsFieldToBytes a[k / 32]!)[k % 32]! := by
  induction n with
  | zero => omega
  | succ n ih =>
    rw [encodePrefix_succ, getElem!_pos _ k (by
      rw [ByteArray.size_append, encodePrefix_size, field_bytes_size]
      omega)]
    by_cases hkn : k < 32 * n
    · rw [ByteArray.getElem_append_left (by rwa [encodePrefix_size]),
        ← getElem!_pos (encodePrefix a n) k (by rwa [encodePrefix_size])]
      exact ih hkn
    · rw [ByteArray.getElem_append_right (by rw [encodePrefix_size]; omega)]
      have hdiv : k / 32 = n := by omega
      have hmod : k % 32 = k - 32 * n := by omega
      rw [hdiv, hmod, getElem!_pos (blsFieldToBytes a[n]!) (k - 32 * n)
        (by rw [field_bytes_size]; omega)]
      simp only [encodePrefix_size]

theorem cosetEvalsToCell_size (a : Array Fr) : (cosetEvalsToCell a).size = 2048 := by
  have he : cosetEvalsToCell a = encodePrefix a 64 := by
    unfold cosetEvalsToCell encodePrefix
    rw [← Array.foldl_toList]
    rfl
  rw [he, encodePrefix_size]

theorem cosetEvalsToCell_get (a : Array Fr) (k : Nat) (hk : k < 2048) :
    (cosetEvalsToCell a)[k]! = (blsFieldToBytes a[k / 32]!)[k % 32]! := by
  have he : cosetEvalsToCell a = encodePrefix a 64 := by
    unfold cosetEvalsToCell encodePrefix
    rw [← Array.foldl_toList]
    rfl
  rw [he]
  exact encodePrefix_get a 64 k hk

theorem extension_cell_get (values : Array Fr) (hsize : values.size = 4096)
    (i k : Nat) (hi : i < 64) (hk : k < 2048) :
    (cosetEvalsToCell ((bitReversalPermutation values).extract
      (i * 64) (i * 64 + 64)))[k]! =
        (blsFieldToBytes values[reverseBits (i * 64 + k / 32) 4096]!)[k % 32]! := by
  rw [cosetEvalsToCell_get _ k hk]
  have hchunk : k / 32 < ((bitReversalPermutation values).extract
      (i * 64) (i * 64 + 64)).size := by
    simp only [Array.size_extract, size_bitReversalPermutation, hsize]
    omega
  rw [getElem!_pos ((bitReversalPermutation values).extract
      (i * 64) (i * 64 + 64)) (k / 32) hchunk, Array.getElem_extract,
    getElem_bitReversalPermutation, hsize]

end LeanBlsSimd.Kzg.Extender
