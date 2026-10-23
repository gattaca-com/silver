import LeanBlsSimd.Kzg.Fr.Conversion
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesDecode

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrScalar
open Word64

def wordChunk (be : Array U8 32#usize) (w : Nat) (hw : w < 4) : Array U8 8#usize :=
  ⟨be.val.slice (8*(3-w)) (8*(4-w)),by simp [List.slice,be.property]; omega⟩

def readWord (be : Array U8 32#usize) (w : Nat) (hw : w < 4) : U64 :=
  core.num.U64.from_be_bytes (wordChunk be w hw)

theorem read_word_step (be : Array U8 32#usize) (words : Array U64 4#usize)
    (w : Usize) (hw : w.val < 4) :
    ∃ next : Usize, next.val = w.val+1 ∧
      fr.words_from_be_bytes_loop.body be words w =
        ok (cont (words.set w (readWord be w.val hw),next)) := by
  let next : Usize := UScalar.ofNatCore (w.val+1) (by scalar_tac)
  let start : Usize := UScalar.ofNatCore (32-8*(w.val+1)) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (32-8*w.val) (by scalar_tac)
  let chunk := wordChunk be w.val hw
  let src := Array.to_slice chunk
  have hindex : core.array.Array.index
      (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) be
      { start, «end» := stop } = ok src := by
    have hstart : 32-8*(w.val+1) = 8*(3-w.val) := by omega
    have hstop : 32-8*w.val = 8*(4-w.val) := by omega
    have hle : 8*(3-w.val) ≤ 8*(4-w.val) := by omega
    have hbound : 8*(4-w.val) ≤ 32 := by omega
    simp [core.array.Array.index,core.ops.index.IndexSlice,core.slice.index.Slice.index,
      core.slice.index.SliceIndexRangeUsizeSlice.index,start,stop,hstart,hstop,
      src,chunk,wordChunk,Array.to_slice,hle,hbound]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 8#usize 0#u8)) src = ok src := by
    simp [core.slice.Slice.copy_from_slice,UScalar.eq_equiv,src,Array.to_slice,chunk.property]
  have hback : Array.from_slice (Array.repeat 8#usize 0#u8) src = chunk := by
    simp [Array.from_slice,src,Array.to_slice,chunk.property]
  refine ⟨next,rfl,?_⟩
  have hw' : w < 4#usize := hw
  simp only [fr.words_from_be_bytes_loop.body,hw',if_true,lift,Array.to_slice_mut,
    bind_tc_ok,Function.uncurry_apply_pair]
  simp (disch := scalar_tac) only [add_ok,mul_ok,sub_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  change (do
    let s1 ← core.array.Array.index
      (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) be
      { start, «end» := stop }
    let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 8#usize 0#u8)) s1
    let out ← Array.update words w
      (core.num.U64.from_be_bytes (Array.from_slice (Array.repeat 8#usize 0#u8) s2))
    ok (cont (out,next))) = _
  rw [hindex]
  simp only [bind_tc_ok,hcopy,hback]
  rw [update_eq words w _ hw]
  rfl

def readWords (be : Array U8 32#usize) : Array U64 4#usize :=
  toArray id (Vector.ofFn fun i : Fin 4 => readWord be i.val i.isLt)

theorem readWords_at (be : Array U8 32#usize) (i : Nat) (hi : i < 4) :
    (readWords be).val[i]'(by rw [(readWords be).property]; exact hi) = readWord be i hi := by
  simp [readWords,toArray]

theorem read_words_loop_refines (be : Array U8 32#usize) (words : Array U64 4#usize)
    (w : Usize) (hw : w.val ≤ 4)
    (hprefix : ∀ i (hi : i < 4), i < w.val → words.val[i]'(by rw [words.property]; exact hi) = readWord be i hi) :
    fr.words_from_be_bytes_loop be words w = ok (readWords be) := by
  induction hn : 4-w.val generalizing words w with
  | zero =>
    have hw4 : w.val = 4 := by omega
    have hwords : words = readWords be := by
      apply Subtype.ext
      apply List.ext_getElem
      · rw [words.property,(readWords be).property]
      · intro i hi hi'
        have hi4 : i < 4 := by simpa only [words.property] using hi
        rw [hprefix i hi4 (by omega),readWords_at be i hi4]
    have hstop : ¬w < 4#usize := by change ¬ w.val < 4; omega
    rw [fr.words_from_be_bytes_loop,loop.eq_1]
    simp [fr.words_from_be_bytes_loop.body,hstop,hwords]
  | succ n ih =>
    have hwlt : w.val < 4 := by omega
    obtain ⟨next,hnext,hbody⟩ := read_word_step be words w hwlt
    let words' := words.set w (readWord be w.val hwlt)
    have hprefix' : ∀ i (hi : i < 4), i < next.val →
        words'.val[i]'(by rw [words'.property]; exact hi) = readWord be i hi := by
      intro i hi hiw
      change (words.val.set w.val (readWord be w.val hwlt))[i]'_ = _
      by_cases heq : i = w.val
      · subst i
        rw [List.getElem_set_self]
      · rw [List.getElem_set_ne (by omega)]
        exact hprefix i hi (by omega)
    have hr := ih words' next (by omega) hprefix' (by omega)
    rw [fr.words_from_be_bytes_loop,loop.eq_1]
    simpa only [hbody] using hr

theorem words_from_be_bytes_refines (be : Array U8 32#usize) :
    fr.words_from_be_bytes be = ok (readWords be) := by
  exact read_words_loop_refines be (Array.repeat 4#usize 0#u64) 0#usize (by decide)
    (by intro i hi him; change i < 0 at him; omega)

open Kzg.Extender.Kernel.BytePacking

theorem readWord_model (be : Array U8 32#usize) (w : Nat) (hw : w < 4) :
    readWord be w hw = toU64 (DecompressG2.u64_from_be_bytes
      (inputChunk (Array.to_slice be) (8*(3-w)))) := by
  have hend : 8*(3-w)+8 = 8*(4-w) := by omega
  have hs := slice_to_chunk (Array.to_slice be) (8*(3-w))
    (by change 8*(3-w)+8 ≤ be.val.length; rw [be.property]; change 8*(3-w)+8 ≤ 32; omega)
  have hchunk : wordChunk be w hw = toArray toU8 (inputChunk (Array.to_slice be) (8*(3-w))) := by
    apply Subtype.ext
    apply (List.map_injective_iff.mpr (fun a b h => by simpa using congrArg toU8 h) :
      Function.Injective (List.map ofU8))
    simpa [wordChunk,Array.to_slice,toArray,Function.comp_def,hend] using hs
  unfold readWord
  rw [hchunk]
  have hr := DecompressG2.from_be_bytes_refines (toArray toU8 (inputChunk (Array.to_slice be) (8*(3-w))))
  rw [ofArray_toArray (fun _ => rfl)] at hr
  simpa only [toU64_ofU64] using congrArg toU64 hr

theorem readWords_model (be : Array U8 32#usize) :
    readWords be = toArray toU64 (decodedWords (Array.to_slice be) 0) := by
  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray,readWords]
  · intro i hi hi'
    have hi4 : i < 4 := by simpa only [(readWords be).property] using hi
    rw [readWords_at be i hi4,readWord_model]
    simp [toArray,decodedWords]

theorem value_model_words (words : Vector UInt64 4) :
    value (toArray toU64 words : Array U64 4#usize) = (valWords words : ℤ) := by
  have hl : (toArray toU64 words : Array U64 4#usize).val = [toU64 words[0],toU64 words[1],toU64 words[2],toU64 words[3]] := by
    apply List.ext_getElem
    · simp [toArray]
    · intro i hi hi'
      have hi4 : i < 4 := by simpa [toArray] using hi
      interval_cases i <;> simp [toArray]
  rw [value,hl]
  change (words[0].toNat : ℤ)+(radix : ℤ)*((words[1].toNat : ℤ)+
    (radix : ℤ)*((words[2].toNat : ℤ)+(radix : ℤ)*((words[3].toNat : ℤ)+(radix : ℤ)*0))) =
    (valWords words : ℤ)
  norm_num [valWords,radix]
  ring

theorem readWords_value (be : Array U8 32#usize) :
    value (readWords be) = (Fr.bytesBEToNat (Kzg.arrayBytes be) : ℤ) := by
  rw [readWords_model,value_model_words]
  have h := decodedWords_bytes (Array.to_slice be) 0#usize
    (by simp [Array.to_slice,be.property])
  have hs : (Kzg.bytes be.val).size = 32 := by simp [Kzg.bytes,ByteArray.size,be.property]
  have he : (Kzg.bytes be.val).extract 0 32 = Kzg.bytes be.val := by
    simpa only [hs] using (ByteArray.extract_zero_size (b := Kzg.bytes be.val))
  simpa [Array.to_slice,Kzg.arrayBytes,show (0#usize).val = 0 from rfl,he] using congrArg (fun n : Nat => (n : ℤ)) h

theorem readWords_limbs (be : Array U8 32#usize) :
    Kzg.limbs (readWords be).val = Fr.bytesBEToNat (Kzg.arrayBytes be) := by
  have h := readWords_value be
  rw [value_eq_limbs] at h
  exact_mod_cast h

theorem fr_from_bytes_reduced_refines (be : Array U8 32#usize) :
    fr.fr_from_bytes_reduced be =
      ok (Kzg.frEncode (Fr.ofNat (Fr.bytesBEToNat (Kzg.arrayBytes be)))) := by
  simp only [fr.fr_from_bytes_reduced,words_from_be_bytes_refines,bind_tc_ok,
    reduce_words_refines,readWords_limbs]

theorem fr_from_bytes_refines (be : Array U8 32#usize) :
    fr.fr_from_bytes be =
      ok ((EthLib.Cryptography.Kzg.bytesToBlsField (Kzg.arrayBytes be)).toOption.map Kzg.frEncode) := by
  obtain ⟨difference,hsub,_⟩ := sub_words_refines (readWords be) fr.R
  rw [modulus_words,readWords_value] at hsub
  have hsize : (Kzg.arrayBytes be).size = 32 := by
    simp [Kzg.arrayBytes,Kzg.bytes,ByteArray.size,be.property]
  by_cases hn : Fr.bytesBEToNat (Kzg.arrayBytes be) < Fr.modulus
  · have hcanonical : value (readWords be) < Fr.modulus := by
      rw [readWords_value]
      exact_mod_cast hn
    have hconv := canonical_words_refines (readWords be) hcanonical
    have hfield : Fr.ofNat (Fr.bytesBEToNat (Kzg.arrayBytes be)) =
        (⟨Fr.bytesBEToNat (Kzg.arrayBytes be),hn⟩ : Fr) := by
      apply Fin.ext
      exact Nat.mod_eq_of_lt hn
    simp [fr.fr_from_bytes,words_from_be_bytes_refines,hsub,hconv,readWords_limbs,
      hn,EthLib.Cryptography.Kzg.bytesToBlsField,EthLib.Cryptography.Kzg.Constants.BYTES_PER_FIELD_ELEMENT,
      Fr.fromBytesBE,Except.toOption,hsize,hfield]
  · simp [fr.fr_from_bytes,words_from_be_bytes_refines,hsub,hn,
      EthLib.Cryptography.Kzg.bytesToBlsField,EthLib.Cryptography.Kzg.Constants.BYTES_PER_FIELD_ELEMENT,
      Fr.fromBytesBE,Except.toOption,hsize]

end LeanBlsSimd.FrScalar
