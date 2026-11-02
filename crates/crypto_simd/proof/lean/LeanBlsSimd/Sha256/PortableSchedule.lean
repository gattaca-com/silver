import LeanBlsSimd.Sha256.ByteWord

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Portable

def loadChunk (data : Slice U8) (start : Nat) (h : start+4 ≤ data.val.length) : Array U8 4#usize :=
  Array.from (data.val.slice start (start+4)) (by simp [List.slice]; omega)

theorem loadChunk_get (data : Slice U8) (start : Nat) (h : start+4 ≤ data.val.length)
    (i : Nat) (hi : i < 4) :
    (Spec.bytes ((loadChunk data start h).val.map ofU8))[i]! =
      (Spec.bytes (data.val.map ofU8))[start+i]! := by
  simp only [Spec.bytes_get]
  rw [getElem!_pos _ i (by simp only [List.length_map,(loadChunk data start h).property]; exact hi),
    getElem!_pos _ (start+i) (by simp only [List.length_map]; omega)]
  simp [loadChunk,List.slice,List.getElem_map,List.getElem_take,List.getElem_drop]

theorem loadChunk_model (data : Slice U8) (start : Nat) (h : start+4 ≤ data.val.length) :
    ofWord (core.num.U32.from_be_bytes (loadChunk data start h)) =
      Spec.big32 (Spec.bytes (data.val.map ofU8)) start := by
  rw [from_be_bytes_model]
  simp only [Spec.big32,EthLib.Cryptography.Hash.Sha256.big32,Nat.zero_add]
  rw [loadChunk_get data start h 0 (by decide),loadChunk_get data start h 1 (by decide),
    loadChunk_get data start h 2 (by decide),loadChunk_get data start h 3 (by decide),Nat.add_zero]

theorem schedule_load_step (data : Slice U8) (offset : Usize) (w : Array U32 64#usize)
    (t : Usize) (ht : t.val < 16) (hdata : offset.val+64 ≤ data.val.length) :
    ∃ out next, sha256.portable.schedule_loop0.body data offset w t = ok (cont (out,next)) ∧
      words out = (words w).set! t.val
        (Spec.big32 (Spec.bytes (data.val.map ofU8)) (offset.val+4*t.val)) ∧
      next.val = t.val+1 := by
  have hbound := data.property
  have hchunk : offset.val+4*t.val+4 ≤ data.val.length := by omega
  let start : Usize := UScalar.ofNatCore (offset.val+4*t.val) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (offset.val+4*t.val+4) (by scalar_tac)
  let next : Usize := UScalar.ofNatCore (t.val+1) (by scalar_tac)
  let chunk := loadChunk data (offset.val+4*t.val) hchunk
  let src := Array.to_slice chunk
  let out := w.set t (core.num.U32.from_be_bytes chunk)
  have hindex : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
      data {start, «end» := stop} = ok src := by
    simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeUsizeSlice.index,
      start,stop,src,chunk,loadChunk,Array.to_slice,hchunk]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 4#usize 0#u8)) src = ok src := by
    simp [core.slice.Slice.copy_from_slice,UScalar.eq_equiv,src,Array.to_slice,chunk.property]
  have hback : Array.from_slice (Array.repeat 4#usize 0#u8) src = chunk := by
    simp [Array.from_slice,src,Array.to_slice,chunk.property]
  refine ⟨out,next,?_,?_,rfl⟩
  · have ht' : t < 16#usize := ht
    simp only [sha256.portable.schedule_loop0.body,ht',ite_true,lift,Array.to_slice_mut, bind_ok, Aeneas.Std.uncurry_apply_pair]
    simp (disch := scalar_tac) only [mul_ok,add_ok, bind_ok,UScalar.ofNatCore_val_eq]
    change (do
      let s1 ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
        data {start, «end» := stop}
      let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8
        (Array.to_slice (Array.repeat 4#usize 0#u8)) s1
      let a ← Array.update w t (core.num.U32.from_be_bytes (Array.from_slice (Array.repeat 4#usize 0#u8) s2))
      ok (cont (a,next))) = _
    rw [hindex]
    simp only [bind_tc_ok,hcopy,hback]
    rw [update_eq _ _ _ (by change t.val < 64; omega)]
    exact bind_ok _ _
  · change words (w.set t _) = _
    rw [words_set,loadChunk_model]


attribute [local irreducible] Spec.scheduleStep

theorem schedule_expand_step (w : Array U32 64#usize) (t : Usize)
    (hlo : 16 ≤ t.val) (hi : t.val < 64) :
    ∃ out next, sha256.portable.schedule_loop1.body w t = ok (cont (out,next)) ∧
      words out = Spec.scheduleStep (words w) t.val ∧ next.val = t.val+1 := by
  let next : Usize := UScalar.ofNatCore (t.val+1) (by scalar_tac)
  let out := w.set t (word ((words w)[t.val-16]! + Spec.smallSigma0 (words w)[t.val-15]! +
    (words w)[t.val-7]! + Spec.smallSigma1 (words w)[t.val-2]!))
  refine ⟨out,next,?_,?_,rfl⟩
  · have ht : t < 64#usize := hi
    simp only [sha256.portable.schedule_loop1.body,ht,ite_true]
    simp (disch := scalar_tac) only [sub_ok, bind_ok,UScalar.ofNatCore_val_eq,index_usize_eq]
    have h16 := words_get w (t.val-16) (by change _ < 64; omega)
    have h15 := words_get w (t.val-15) (by change _ < 64; omega)
    have h7 := words_get w (t.val-7) (by change _ < 64; omega)
    have h2 := words_get w (t.val-2) (by change _ < 64; omega)
    rw [← word_ofWord (w.val[t.val-15]'_), ← h15, smallSigma0_refines]
    simp only [bind_ok,lift]
    rw [← word_ofWord (w.val[t.val-2]'_), ← h2, smallSigma1_refines]
    simp only [bind_ok]
    rw [← word_ofWord (w.val[t.val-16]'_), ← h16,
      ← word_ofWord (w.val[t.val-7]'_), ← h7]
    simp only [wrapping_add_word]
    rw [update_eq _ _ _ hi]
    simp only [bind_ok]
    rw [add_ok _ _ (by scalar_tac)]
    exact bind_ok _ _
  · change words (w.set t _) = _
    rw [words_set,ofWord_word]
    unfold Spec.scheduleStep
    rfl

theorem schedule_expand_refines (w : Array U32 64#usize) (t : Usize)
    (hlo : 16 ≤ t.val) (hi : t.val ≤ 64) :
    ∃ out, sha256.portable.schedule_loop1 w t = ok out ∧
      words out = (List.range' t.val (64-t.val)).foldl Spec.scheduleStep (words w) := by
  induction hn : 64-t.val generalizing w t with
  | zero =>
    have ht : t.val = 64 := by omega
    have hstop : ¬ t < 64#usize := by change ¬ t.val < 64; omega
    refine ⟨w,?_,?_⟩
    · rw [sha256.portable.schedule_loop1,loop.eq_1]
      simp only [sha256.portable.schedule_loop1.body,hstop,ite_false, bind_ok]
    · rfl
  | succ n ih =>
    obtain ⟨out,next,hbody,hout,hnext⟩ := schedule_expand_step w t hlo (by omega)
    obtain ⟨final,hfinal,hmodel⟩ := ih out next (by omega) (by omega) (by omega)
    refine ⟨final,?_,?_⟩
    · rw [sha256.portable.schedule_loop1,loop.eq_1]
      simpa only [hbody, bind_ok] using! hfinal
    · rw [hmodel,hnext,hout,List.range']
      rfl


theorem schedule_load_refines (data : Slice U8) (offset : Usize) (w : Array U32 64#usize)
    (t : Usize) (ht : t.val ≤ 16) (hdata : offset.val+64 ≤ data.val.length) :
    ∃ out, sha256.portable.schedule_loop0 data offset w t = ok (out,16#usize) ∧
      words out = (List.range' t.val (16-t.val)).foldl
        (fun ws i => ws.set! i (Spec.big32 (Spec.bytes (data.val.map ofU8)) (offset.val+4*i)))
        (words w) := by
  induction hn : 16-t.val generalizing w t with
  | zero =>
    have ht16 : t = 16#usize := UScalar.eq_of_val_eq (by change t.val = 16; omega)
    subst t
    refine ⟨w,?_,rfl⟩
    rw [sha256.portable.schedule_loop0,loop.eq_1]
    simp only [sha256.portable.schedule_loop0.body,lt_self_iff_false,ite_false, bind_ok]
  | succ n ih =>
    obtain ⟨out,next,hbody,hout,hnext⟩ := schedule_load_step data offset w t (by omega) hdata
    obtain ⟨final,hfinal,hmodel⟩ := ih out next (by omega) (by omega)
    refine ⟨final,?_,?_⟩
    · rw [sha256.portable.schedule_loop0,loop.eq_1]
      simpa only [hbody, bind_ok] using! hfinal
    · rw [hmodel,hnext,hout,List.range']
      rfl

theorem schedule_refines (data : Slice U8) (offset : Usize)
    (hdata : offset.val+64 ≤ data.val.length) :
    ∃ out, sha256.portable.schedule data offset = ok out ∧
      words out = Spec.schedule (Spec.bytes (data.val.map ofU8)) offset.val := by
  obtain ⟨loaded,hload,hloaded⟩ := schedule_load_refines data offset
    (Array.repeat 64#usize 0#u32) 0#usize (by decide) hdata
  obtain ⟨out,hout,hwords⟩ := schedule_expand_refines loaded 16#usize (by decide) (by decide)
  refine ⟨out,?_,?_⟩
  · rw [sha256.portable.schedule,hload,bind_ok]
    exact hout
  · rw [hwords,hloaded]
    have hz : words (Array.repeat 64#usize 0#u32) = _root_.Array.replicate 64 0 := by
      simp [words,Array.repeat]
      rfl
    rw [hz]
    rfl

end LeanBlsSimd.Sha256.Portable
