import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

def inputChunk (input : Slice U8) (start : Nat) : Vector UInt8 8 :=
  Vector.ofFn fun i => ofU8 input.val[start + i.val]!

theorem slice_to_chunk (input : Slice U8) (start : Nat) (h : start + 8 ≤ input.val.length) :
    (input.val.slice start (start+8)).map ofU8 = (inputChunk input start).toList := by
  apply List.ext_getElem
  · simp [List.slice_length]
    omega
  · intro i hi hi'
    have hi8 : i < 8 := by simpa using hi'
    simp [inputChunk, List.slice, show start+i < input.val.length by omega]

theorem le_word_refines (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 8 ≤ input.val.length) :
    fr8.u256x8.le_word input offset =
      ok (UScalar.hcast .I64
        (core.num.U64.from_le_bytes (toArray toU8 (inputChunk input offset.val)))) := by
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  simp only [UScalarTy.Usize_numBits_eq] at hm
  unfold fr8.u256x8.le_word
  simp only [lift, bind_tc_ok, Array.to_slice_mut, Function.uncurry_apply_pair]
  simp (disch := (simp; omega)) only [add_ok, bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [slice_index_ok input _ _ (by simp) (by simp; omega)]
  simp only [bind_tc_ok]
  have hslen : (input.val.slice offset.val (offset.val + 8)).length = 8 := by
    rw [List.slice_length]
    omega
  rw [copy_from_slice_ok _ _ _ (by simp [Array.to_slice, hslen])]
  simp only [bind_tc_ok]
  rw [Array.from_slice, dif_pos (by simpa using hslen)]
  simp only [UScalar.ofNatCore_val_eq]
  have heq : (⟨input.val.slice offset.val (offset.val + 8), hslen⟩ : Array U8 8#usize) =
      toArray toU8 (inputChunk input offset.val) := by
    apply Subtype.ext
    apply (List.map_injective_iff.mpr (fun a b h => by simpa using congrArg toU8 h) :
      Function.Injective (List.map ofU8))
    simpa [Function.comp_def] using slice_to_chunk input offset.val hsize
  rw [heq]

def littleBlock (input : Slice U8) (offset : Nat) : M512 :=
  Vector.ofFn fun lane =>
    ofU64 (core.num.U64.from_le_bytes (toArray toU8 (inputChunk input (offset + 8*lane.val))))

theorem load_block_refines (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 64 ≤ input.val.length) :
    fr8.u256x8.load_block input offset = ok (littleBlock input offset.val) := by
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  simp only [UScalarTy.Usize_numBits_eq] at hm
  unfold fr8.u256x8.load_block
  simp (disch := (simp; omega)) only [add_ok, bind_tc_ok, UScalar.ofNatCore_val_eq,
    le_word_refines]
  rw [le_word_refines input offset (by omega)]
  simp only [bind_tc_ok]
  simp only [core.core_arch.x86.avx512f._mm512_set_epi64]
  apply congrArg ok
  ext lane hlane
  interval_cases lane <;>
    simp [littleBlock, LeanBlsSimd._mm512_set_epi64, ofBitVec_hcast_I64]

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
