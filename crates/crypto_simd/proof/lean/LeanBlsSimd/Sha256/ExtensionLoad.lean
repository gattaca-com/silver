import LeanBlsSimd.Sha256.ExtensionBytes
import LeanBlsSimd.Sha256.ByteWord

open Aeneas Aeneas.Std Result
open private LeanBlsSimd.Sha256.four_bytes from LeanBlsSimd.Sha256.ByteWord
open private EthLib.Cryptography.Bls.Sha256.big32 from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Extensions

private theorem appendNat {m n : Nat} (x : BitVec m) (y : BitVec n) :
    (x ++ y).toNat = x.toNat * 2^n + y.toNat := by
  rw [BitVec.toNat_append,← Nat.shiftLeft_add_eq_or_of_lt y.isLt,Nat.shiftLeft_eq]

theorem big32_four (a b c d : UInt8) :
    Spec.big32 (Spec.bytes [a,b,c,d]) 0 = littleWord d c b a := by
  have hr := from_be_bytes_model (Array.make 4#usize [toU8 a,toU8 b,toU8 c,toU8 d] (by rfl))
  simp only [Array.make,List.map_cons,List.map_nil,ofU8_toU8] at hr
  rw [← hr]
  apply UInt32.toNat_inj.mp
  change (BitVec.fromBEBytes [a.toBitVec,b.toBitVec,c.toBitVec,d.toBitVec]).toNat = _
  rw [LeanBlsSimd.Sha256.four_bytes]
  change (a.toBitVec ++ b.toBitVec ++ c.toBitVec ++ d.toBitVec : BitVec 32).toNat = _
  rw [appendNat (a.toBitVec ++ b.toBitVec ++ c.toBitVec) d.toBitVec,
    appendNat (a.toBitVec ++ b.toBitVec) c.toBitVec,appendNat a.toBitVec b.toBitVec]
  have ha := a.toBitVec.isLt
  have hb := b.toBitVec.isLt
  have hc := c.toBitVec.isLt
  have hd := d.toBitVec.isLt
  change a.toNat < 256 at ha
  change b.toNat < 256 at hb
  change c.toNat < 256 at hc
  change d.toNat < 256 at hd
  simp only [UInt8.toNat_toBitVec,littleWord,UInt32.toNat_ofNat']
  norm_num only [Nat.reducePow]
  omega

theorem big32_littleWord (bytes : ByteArray) (off : Nat) :
    Spec.big32 bytes off = littleWord bytes[off+3]! bytes[off+2]! bytes[off+1]! bytes[off]! := by
  rw [← big32_four]
  simp only [Spec.big32,EthLib.Cryptography.Bls.Sha256.big32,Spec.bytes_get,
    List.getElem!_cons_zero,List.getElem!_cons_succ,Nat.zero_add]

def byteSwap : M128 := _mm_set_epi64x 0x0c0d0e0f08090a0b 0x0405060700010203

theorem byteSwap_get (i : Nat) (hi : i < 16) :
    ShaIntrinsics.byte byteSwap i = UInt8.ofNat (4*(i/4)+3-i%4) := by
  interval_cases i <;> decide +kernel

theorem byte_swap_words (x : Vector UInt8 16) :
    _mm_shuffle_epi8 (ShaIntrinsics.loadBytes x) byteSwap =
      #v[littleWord x[3] x[2] x[1] x[0],littleWord x[7] x[6] x[5] x[4],
        littleWord x[11] x[10] x[9] x[8],littleWord x[15] x[14] x[13] x[12]] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_shuffle_epi8,ShaIntrinsics.fromBytes,Vector.getElem_ofFn,
      Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ]
  all_goals
    simp (disch := decide) only [byteSwap_get]
    norm_num only [UInt8.toNat_ofNat',Nat.testBit]
    simp (disch := omega) only [byte_load_get]
    rfl


theorem load_bytes_refines (x : Array U8 16#usize) :
    silver_crypto_simd.sha256.extensions.load_bytes x =
      ok (ShaIntrinsics.loadBytes (ofArray ofU8 x)) := by
  unfold silver_crypto_simd.sha256.extensions.load_bytes
  apply congrArg ok
  apply congrArg ShaIntrinsics.loadBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn,getElem_ofArray]

theorem load_swapped_words (x : Array U8 16#usize) :
    (do let v ← silver_crypto_simd.sha256.extensions.load_bytes x
        core.core_arch.x86.ssse3._mm_shuffle_epi8 v byteSwap) =
      ok #v[Spec.big32 (Spec.bytes (x.val.map ofU8)) 0,
        Spec.big32 (Spec.bytes (x.val.map ofU8)) 4,
        Spec.big32 (Spec.bytes (x.val.map ofU8)) 8,
        Spec.big32 (Spec.bytes (x.val.map ofU8)) 12] := by
  rw [load_bytes_refines]
  simp only [bind_tc_ok,core.core_arch.x86.ssse3._mm_shuffle_epi8,byte_swap_words]
  have hb (i : Nat) (hi : i < 16) :
      (Spec.bytes (x.val.map ofU8))[i]! = (ofArray ofU8 x : Vector UInt8 16)[i] := by
    rw [Spec.bytes_get,getElem!_pos _ i (by simp only [List.length_map,x.property]; exact hi)]
    simp only [List.getElem_map,getElem_ofArray]
  apply congrArg ok
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ,
      big32_littleWord]
  all_goals simp (disch := omega) only [hb]

end LeanBlsSimd.Sha256.Extensions
