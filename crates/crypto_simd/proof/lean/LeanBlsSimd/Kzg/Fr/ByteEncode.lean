import LeanBlsSimd.Kzg.Fr.ByteDecode
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesSerialize
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8WordStore

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrScalar
open Word64 Kzg.Extender.Kernel.BytePacking

def writtenBytes (words : Array U64 4#usize) : Array U8 32#usize :=
  ⟨wordsBytes (ofArray ofU64 words), wordsBytes_length _⟩

theorem writtenBytes_get (words : Array U64 4#usize) (w b : Nat)
    (hw : w < 4) (hb : b < 8) :
    (writtenBytes words).val[8*(3-w)+b]! =
      (core.num.U64.to_be_bytes words.val[w]!).val[b]! := by
  rw [writtenBytes,wordsBytes_get _ (3-w) b (by omega) hb]
  have he : 3-(3-w) = w := by omega
  simp [he,getElem!_pos (ofArray ofU64 words : Vector UInt64 4) w hw,
    getElem!_pos words.val w (by simpa [words.property] using hw),wordBytes]

theorem write_word_step (words : Array U64 4#usize) (be : Array U8 32#usize)
    (w : Usize) (hw : w.val < 4) :
    ∃ next : Usize, next.val = w.val+1 ∧
      fr.be_bytes_from_words_loop.body words be w =
        ok (cont (be.setSlice! (8*(3-w.val))
          (core.num.U64.to_be_bytes words.val[w.val]!).val,next)) := by
  let next : Usize := UScalar.ofNatCore (w.val+1) (by scalar_tac)
  have hstart : 32-8*(w.val+1) = 8*(3-w.val) := by omega
  have hstop : 32-8*w.val = 8*(4-w.val) := by omega
  have hbounds : 8*(3-w.val) ≤ 8*(4-w.val) ∧ 8*(4-w.val) ≤ 32 := by omega
  have hroom : 8 ≤ 32-8*(3-w.val) := by omega
  have hlen : min (8*(4-w.val)-8*(3-w.val)) (32-8*(3-w.val)) = 8 := by omega
  refine ⟨next,rfl,?_⟩
  have hw' : w < 4#usize := hw
  simp only [fr.be_bytes_from_words_loop.body,hw',if_true]
  simp (disch := scalar_tac) only [add_ok,mul_ok,sub_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  rw [index_usize_eq words w hw]
  simp [core.array.Array.index_mut,core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut,core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
    Array.to_slice,Slice.length,UScalar.le_equiv,hstart,hstop,hbounds,be.property,
    core.slice.Slice.copy_from_slice,Slice.len,List.slice,
    Array.from_slice,lift,bind_tc_ok,hlen,next,
    getElem!_pos words.val w.val (by simpa [words.property] using hw)]
  rfl

theorem write_words_loop_refines (words : Array U64 4#usize) (be : Array U8 32#usize)
    (w : Usize) (hw : w.val ≤ 4)
    (hsuffix : ∀ i, i < 32 → 8*(4-w.val) ≤ i →
      be.val[i]! = (writtenBytes words).val[i]!) :
    fr.be_bytes_from_words_loop words be w = ok (writtenBytes words) := by
  induction hn : 4-w.val generalizing be w with
  | zero =>
    have hw4 : w.val = 4 := by omega
    have hbe : be = writtenBytes words := by
      apply Subtype.ext
      apply List.ext_getElem
      · rw [be.property,(writtenBytes words).property]
      · intro i hi hi'
        rw [← getElem!_pos be.val i hi,← getElem!_pos (writtenBytes words).val i hi']
        exact hsuffix i (by simpa [be.property] using hi) (by simp [hw4])
    have hstop : ¬w < 4#usize := by change ¬w.val < 4; omega
    rw [fr.be_bytes_from_words_loop,loop.eq_1]
    simp [fr.be_bytes_from_words_loop.body,hstop,hbe]
  | succ n ih =>
    have hwlt : w.val < 4 := by omega
    obtain ⟨next,hnext,hbody⟩ := write_word_step words be w hwlt
    let chunk := (core.num.U64.to_be_bytes words.val[w.val]!).val
    have hchunk : chunk.length = 8 := (core.num.U64.to_be_bytes _).property
    let be' := be.setSlice! (8*(3-w.val)) chunk
    have hsuffix' : ∀ i, i < 32 → 8*(4-next.val) ≤ i →
        be'.val[i]! = (writtenBytes words).val[i]! := by
      intro i hi hlow
      change (be.val.setSlice! (8*(3-w.val)) chunk)[i]! = _
      by_cases hold : 8*(4-w.val) ≤ i
      · rw [List.getElem!_setSlice!_same]
        · exact hsuffix i hi hold
        · rw [hchunk]; omega
      · have hm : 8*(3-w.val) ≤ i ∧ i < 8*(3-w.val)+8 := by omega
        rw [List.getElem!_setSlice!_middle]
        · have hb : i-8*(3-w.val) < 8 := by omega
          have he : 8*(3-w.val)+(i-8*(3-w.val)) = i := by omega
          simpa only [he] using (writtenBytes_get words w.val (i-8*(3-w.val)) hwlt hb).symm
        · rw [hchunk,be.property]; change 8*(3-w.val) ≤ i ∧ i-8*(3-w.val) < 8 ∧ i < 32; omega
    have hr := ih be' next (by omega) hsuffix' (by omega)
    rw [fr.be_bytes_from_words_loop,loop.eq_1]
    simpa only [hbody] using hr

theorem be_bytes_from_words_refines (words : Array U64 4#usize) :
    fr.be_bytes_from_words words = ok (writtenBytes words) := by
  exact write_words_loop_refines words (Array.repeat 32#usize 0#u8) 0#usize (by decide)
    (by intro i hi h; change 8*(4-0) ≤ i at h; omega)

theorem writtenBytes_field (x : Fr) :
    Kzg.arrayBytes (writtenBytes (Kzg.words 4#usize x.val)) =
      EthLib.Cryptography.Kzg.blsFieldToBytes x := by
  apply bytes_eq_field
  · exact (writtenBytes (Kzg.words 4#usize x.val)).property
  · change bytesVal ((wordsBytes (ofArray ofU64 (Kzg.words 4#usize x.val))).map ofU8) = _
    rw [wordsBytes_value]
    have h := value_model_words (ofArray ofU64 (Kzg.words 4#usize x.val))
    rw [toArray_ofArray (fun a => toU64_ofU64 a),ordinary_words_value x.val
      (lt_trans x.isLt (by norm_num [Fr.modulus]))] at h
    exact_mod_cast h.symm

theorem fr_to_bytes_refines (x : Fr) :
    ∃ result, fr.fr_to_bytes (Kzg.frEncode x) = ok result ∧
      Kzg.arrayBytes result = EthLib.Cryptography.Kzg.blsFieldToBytes x := by
  refine ⟨writtenBytes (Kzg.words 4#usize x.val),?_,writtenBytes_field x⟩
  simp only [fr.fr_to_bytes,fr_to_words_refines,bind_tc_ok,be_bytes_from_words_refines]

theorem fr_bytes_correct : Kzg.FrBytesCorrect :=
  ⟨fr_from_bytes_refines,fr_from_bytes_reduced_refines,fr_to_bytes_refines,fr_to_words_refines⟩

end LeanBlsSimd.FrScalar
