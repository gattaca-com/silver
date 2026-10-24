import LeanBlsSimd.Sha256.GeneratedSlices

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd.Sha256.Generated

theorem be_byte {w : Nat} (x : BitVec w) (hw : w%8=0) (i : Nat) (hi : i < w/8) :
    x.toBEBytes[i]! = BitVec.ofNat 8 (x.toNat >>> (8*(w/8-1-i))) := by
  apply (Byte.eq_iff _ _).mpr
  intro j hj
  have hil : i < x.toLEBytes.length := by simpa only [BitVec.toLEBytes_length x hw] using hi
  simp only [BitVec.toBEBytes,List.getElem!_eq_getElem?_getD,List.getElem?_reverse hil,
    BitVec.toLEBytes_length x hw]
  rw [← List.getElem!_eq_getElem?_getD]
  rw [BitVec.toLEBytes_getElem!_testBit _ _ _ hj]
  simp only [BitVec.getElem!_eq_testBit_toNat,Byte.testBit,BitVec.toNat_ofNat,
    Nat.testBit_mod_two_pow,Nat.testBit_shiftRight,hj,decide_true,Bool.true_and]

theorem be_u32 (x : U32) (i : Nat) (hi : i < 4) :
    ofU8 (core.num.U32.to_be_bytes x).val[i]! =
      UInt8.ofNat (x.bv.toNat >>> (8*(3-i))) := by
  have hlen : (core.num.U32.to_be_bytes x).val.length = 4 := (core.num.U32.to_be_bytes x).property
  rw [getElem!_pos _ i (by omega)]
  change UInt8.ofBitVec ((x.bv.toBEBytes.map (@UScalar.mk .U8))[i]'(by simpa [BitVec.toBEBytes_length] using hi)).bv = _
  rw [List.getElem_map]
  change UInt8.ofBitVec (x.bv.toBEBytes[i]'(by simpa [BitVec.toBEBytes_length] using hi)) = _
  rw [← getElem!_pos x.bv.toBEBytes i (by simpa [BitVec.toBEBytes_length] using hi),be_byte _ (by decide) i hi]
  rfl

theorem be_u64 (x : U64) (i : Nat) (hi : i < 8) :
    ofU8 (core.num.U64.to_be_bytes x).val[i]! = Spec.wordByte (ofU64 x) i := by
  have hlen : (core.num.U64.to_be_bytes x).val.length = 8 := (core.num.U64.to_be_bytes x).property
  rw [getElem!_pos _ i (by omega)]
  change UInt8.ofBitVec ((x.bv.toBEBytes.map (@UScalar.mk .U8))[i]'(by simpa [BitVec.toBEBytes_length] using hi)).bv = _
  rw [List.getElem_map]
  change UInt8.ofBitVec (x.bv.toBEBytes[i]'(by simpa [BitVec.toBEBytes_length] using hi)) = _
  rw [← getElem!_pos x.bv.toBEBytes i (by simpa [BitVec.toBEBytes_length] using hi),be_byte _ (by decide) i hi]
  unfold Spec.wordByte
  have hs : (UInt64.ofNat ((7-i)*8)).toNat % 64 = 8*(7-i) := by
    change (((7-i)*8)%2^64)%64 = _
    rw [Nat.mod_eq_of_lt (by omega),Nat.mod_eq_of_lt (by omega)]
    omega
  simp only [UInt64.toNat_shiftRight,ofU64,UInt64.toNat_ofBitVec,hs]
  rfl

end LeanBlsSimd.Sha256.Generated
