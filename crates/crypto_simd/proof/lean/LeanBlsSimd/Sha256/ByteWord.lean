import LeanBlsSimd.Sha256.Words
import LeanBlsSimd.Sha256.Blocks

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open private EthLib.Cryptography.Bls.Sha256.big32 from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256

private theorem four_bytes (a b c d : BitVec 8) :
    BitVec.fromBEBytes [a,b,c,d] = a ++ b ++ c ++ d := by
  change BitVec.fromLEBytes [d,c,b,a] = a ++ b ++ c ++ d
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  change i < 32 at hi
  change (BitVec.fromLEBytes [d,c,b,a]).getLsbD i = (a ++ b ++ c ++ d).getLsbD i
  simp only [BitVec.fromLEBytes,BitVec.getLsbD_or,BitVec.getLsbD_shiftLeft,
    BitVec.getLsbD_setWidth,BitVec.getLsbD_append]
  interval_cases i <;> simp

theorem from_be_bytes_model (a : Array U8 4#usize) :
    ofWord (core.num.U32.from_be_bytes a) = Spec.big32 (Spec.bytes (a.val.map ofU8)) 0 := by
  rcases a with ⟨xs,hxs⟩
  change xs.length = 4 at hxs
  obtain ⟨a,xs,rfl⟩ := List.exists_cons_of_length_pos (by omega : 0 < xs.length)
  obtain ⟨b,xs,rfl⟩ := List.exists_cons_of_length_pos (by simp only [List.length_cons] at hxs; omega : 0 < xs.length)
  obtain ⟨c,xs,rfl⟩ := List.exists_cons_of_length_pos (by simp only [List.length_cons] at hxs; omega : 0 < xs.length)
  obtain ⟨d,xs,rfl⟩ := List.exists_cons_of_length_pos (by simp only [List.length_cons] at hxs; omega : 0 < xs.length)
  have hnil : xs = [] := List.eq_nil_of_length_eq_zero (by simp only [List.length_cons] at hxs; omega)
  subst xs
  apply UInt32.toBitVec_inj.mp
  simp only [ofWord,core.num.U32.from_be_bytes,UInt32.toBitVec_ofBitVec,
    List.map_cons,List.map_nil,Spec.big32,EthLib.Cryptography.Bls.Sha256.big32,
    UInt32.toBitVec_or,UInt32.toBitVec_shiftLeft,UInt32.toBitVec_ofNat,
    Spec.bytes_get,Nat.zero_add,List.getElem!_cons_zero,List.getElem!_cons_succ]
  simp only [UInt32.toBitVec_ofNat',ofU8,UInt8.toNat_ofBitVec]
  change BitVec.fromBEBytes [a.bv,b.bv,c.bv,d.bv] =
    (BitVec.ofNat 32 a.bv.toNat <<< 24 ||| BitVec.ofNat 32 b.bv.toNat <<< 16 |||
      BitVec.ofNat 32 c.bv.toNat <<< 8 ||| BitVec.ofNat 32 d.bv.toNat)
  have hwidth (x : BitVec 8) : BitVec.ofNat 32 x.toNat = x.setWidth 32 := by
    apply BitVec.eq_of_toNat_eq
    simp only [BitVec.toNat_ofNat,BitVec.toNat_setWidth]
  rw [four_bytes,hwidth,hwidth,hwidth,hwidth]
  simpa using (BitVec.setWidth_append_append_append_eq_shiftLeft_setWidth_or
    (w'''' :=32) (b:=a.bv) (b':=b.bv) (b'':=c.bv) (b''':=d.bv))

end LeanBlsSimd.Sha256
