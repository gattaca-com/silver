import LeanBlsSimd.Refines.DecompressG1
import LeanBlsSimd.Portable.Fp.Sqrt
import LeanBlsSimd.Kzg.LanePairingInputs

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode
open DecompressG1 DecompressG2
set_option maxRecDepth 4096

abbrev words (b : Encoding) : Array U64 6#usize :=
  toArray toU64 (fp_words (clearFlags b))

def ordinary (b : Encoding) : Option ((Array U64 6#usize) × Bool) :=
  if b[0] &&& 0x80 = 0 then none
  else if b[0] &&& 0x40 ≠ 0 then none
  else if bytesVal (clearFlags b).toList < Bls.Fp.modulus then
    if bytesVal (clearFlags b).toList = 0 then none
    else some (words b, decide (b[0] &&& 0x20 ≠ 0))
  else none

theorem words_value (b : Encoding) : Word64.value (words b) = (bytesVal (clearFlags b).toList : ℤ) := by
  rw [Fp.value_eq_limbs,←Kzg.val64_eq_limbs,ofArray_toArray_ofU64,val64_fp_words]

private theorem words_zero (b : Encoding) :
    (words b).val = (Array.repeat 6#usize 0#u64).val ↔ bytesVal (clearFlags b).toList = 0 := by
  have hz : Word64.value (Array.repeat 6#usize 0#u64) = 0 := by
    rfl
  constructor
  · intro h
    have he := congrArg Word64.value (Subtype.ext h)
    rw [words_value,hz] at he
    exact_mod_cast he
  · intro h
    apply congrArg Subtype.val
    apply Word64.value_injective
    rw [words_value,h,hz]
    rfl

theorem ordinary_refines (b : Encoding) :
    portable.decompress.ordinary (toArray toU8 b) = ok (ordinary b) := by
  simp only [portable.decompress.ordinary]
  simp (disch := decide) only [index_usize_toArray,bind_tc_ok]
  rw [show (224#u8) = toU8 0xe0 from rfl,show (0#u8) = toU8 0 from rfl,
    FLAG_COMPRESSED_refines,FLAG_INFINITY_refines,FLAG_LARGER_ROOT_refines]
  simp only [lift,toU8_and,toU8_inj,bne_iff_ne,ne_eq,bind_tc_ok,
    flag_compressed,flag_infinity,flag_larger_root]
  simp only [show (0#usize).val = 0 from rfl]
  unfold ordinary
  simp only [ne_eq]
  by_cases hc : b[0] &&& 0x80 = 0
  · simp only [hc,if_true]
  simp only [hc,if_false]
  by_cases hi : b[0] &&& 0x40 = 0
  swap
  · simp only [hi,if_true,not_false_eq_true]
  simp only [hi,not_true_eq_false,if_false]
  simp (disch := simp [Array.to_slice,FP_BYTES,G2_COMPRESSED_LEN]) only [fp_words_refines,bind_tc_ok]
  simp only [FP_BYTES,G2_COMPRESSED_LEN,Nat.reduceDiv,ofSlice_toArray]
  rw [show (2305843009213693951#u64) = toU64 0x1fffffffffffffff from rfl]
  simp (disch := first | omega | decide | (simp; omega)) only [index_usize_toArray,
    bind_tc_ok,toU64_and,update_eq,set_toArray,less_than_p_refines]
  simp only [ofArray_toArray_ofU64,show (5#usize).val = 5 from rfl,fp_words_clear_flags,
    less_than_p_iff,val64_fp_words,decide_eq_true_eq]
  simp only [FP_BYTES,G2_COMPRESSED_LEN,Nat.reduceDiv]
  have hs : (toU8 (b[0] &&& 0x20) != toU8 0) = decide (b[0] &&& 0x20 ≠ 0) := by
    apply Bool.eq_iff_iff.mpr
    simp only [bne_iff_ne,ne_eq,toU8_inj,decide_eq_true_eq]
  simp only [Fp.array_eq_refines,bind_tc_ok,hs]
  have hz := words_zero b
  change (if bytesVal (clearFlags b).toList < Bls.Fp.modulus then
      (if decide ((words b).val = (Array.repeat 6#usize 0#u64).val) then ok none else
        ok (some (words b,decide (b[0] &&& 0x20 ≠ 0)))) else ok none) = _
  simp only [hz,decide_eq_true_eq]
  split_ifs <;> simp_all [FP_BYTES,G2_COMPRESSED_LEN]

end LeanBlsSimd.Portable.Decode
