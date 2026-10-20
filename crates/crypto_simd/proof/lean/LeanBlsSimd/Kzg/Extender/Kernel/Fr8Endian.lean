import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Swap
import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

private theorem get_reverse {α : Type} [Inhabited α] (xs : List α) (i : Nat)
    (hi : i < xs.length) : xs.reverse[i]! = xs[xs.length-1-i]! := by
  simp only [List.getElem!_eq_getElem?_getD, List.getElem?_reverse hi]

theorem to_le_bytes_swapWord (word : UInt64) :
    core.num.U64.to_le_bytes (toU64 (swapWord word)) =
      core.num.U64.to_be_bytes (toU64 word) := by
  apply Subtype.ext
  change (swapWord word).toBitVec.toLEBytes.map _ = word.toBitVec.toBEBytes.map _
  apply congrArg (List.map (@UScalar.mk .U8))
  apply List.ext_getElem
  · simp [BitVec.toBEBytes_length, BitVec.toLEBytes_length]
  · intro i hi hi'
    have hi8 : i < 8 := by simpa [BitVec.toLEBytes_length] using hi
    apply (Byte.eq_iff _ _).mpr
    intro j hj
    rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi']
    simp only [BitVec.toBEBytes]
    rw [get_reverse _ i (by simpa using hi8)]
    simp only [BitVec.toLEBytes_length word.toBitVec (by decide)]
    rw [BitVec.toLEBytes_getElem!_testBit _ _ _ hj,
      BitVec.toLEBytes_getElem!_testBit _ _ _ hj]
    simp only [BitVec.getElem!_eq_testBit_toNat, UInt64.toNat_toBitVec, Nat.reduceDiv]
    rw [swapWord_testBit word (8*i+j) (by omega)]
    congr 1
    omega

theorem swapWord_from_le_bytes (bytes : Vector UInt8 8) :
    swapWord (ofU64 (core.num.U64.from_le_bytes (toArray toU8 bytes))) =
      DecompressG2.u64_from_be_bytes bytes := by
  have hbe := DecompressG2.from_be_bytes_refines (toArray toU8 bytes)
  rw [ofArray_toArray (fun _ => rfl)] at hbe
  rw [← hbe]
  apply UInt64.toNat_inj.mp
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < 64
  · rw [swapWord_testBit _ i hi]
    simp only [ofU64, UInt64.toNat_ofBitVec]
    rw [← BitVec.getElem!_eq_testBit_toNat, ← BitVec.getElem!_eq_testBit_toNat]
    simp only [core.num.U64.from_le_bytes, core.num.U64.from_be_bytes, U64.bv,
      BitVec.fromBEBytes]
    conv_lhs =>
      erw [BitVec.getElem!_cast]
      rw [BitVec.fromLEBytes_getElem!]
    conv_rhs =>
      erw [BitVec.getElem!_cast]
      erw [BitVec.getElem!_cast]
      rw [BitVec.fromLEBytes_getElem!]
    rw [get_reverse _ _ (by simp [toArray]; omega)]
    simp only [toArray_val, List.length_map, Vector.length_toList]
    have hindex : (8 * (7 - i / 8) + i % 8) / 8 = 8 - 1 - i / 8 := by omega
    have hbit : (8 * (7 - i / 8) + i % 8) % 8 = i % 8 := by omega
    rw [hindex, hbit]
  · have hp : 2^64 ≤ 2^i := Nat.pow_le_pow_right (by decide) (by omega)
    rw [Nat.testBit_eq_false_of_lt (lt_of_lt_of_le (UInt64.toNat_lt _) hp),
      Nat.testBit_eq_false_of_lt (lt_of_lt_of_le (UInt64.toNat_lt _) hp)]

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
