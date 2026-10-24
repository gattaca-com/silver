import LeanBlsSimd.Sha256.PortableSchedule
import LeanBlsSimd.Sha256.PortableRounds

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Portable

attribute [local irreducible] Spec.round Spec.rounds Spec.schedule Spec.feedForward

theorem index_word {n : Usize} (a : Array U32 n) (i : Usize) (hi : i.val < n.val) :
    Array.index_usize a i = ok (word (words a)[i.val]!) := by
  rw [index_usize_eq _ _ hi,words_get _ _ hi,word_ofWord]

theorem compress_refines (state : Array U32 8#usize) (data : Slice U8) (offset : Usize)
    (hdata : offset.val+64 ≤ data.val.length) :
    ∃ out, sha256.portable.compress state data offset = ok out ∧
      words out = Spec.compressBlock (words state) (Spec.bytes (data.val.map ofU8)) offset.val := by
  obtain ⟨w,hschedule,hw⟩ := schedule_refines data offset hdata
  rw [sha256.portable.compress,hschedule]
  simp (disch := scalar_tac) only [index_word,bind_tc_ok]
  have hr := rounds_refines w (Spec.stateWords (words state)) 0#usize (by decide)
  dsimp only [Spec.stateWords] at hr
  norm_num only [UScalar.ofNatCore_val_eq] at hr ⊢
  rw [hr]
  simp only [bind_tc_ok,roundArgs,lift]
  refine ⟨_,rfl,?_⟩
  rw [Spec.compressBlock_eq,← hw]
  unfold words Spec.feedForward
  rfl


theorem compress_blocks_step (state : Array U32 8#usize) (data : Slice U8)
    (offset blocks block : Usize) (hblock : block.val < blocks.val)
    (hdata : offset.val+64*blocks.val ≤ data.val.length) :
    ∃ out next, sha256.portable.compress_blocks_loop.body data offset blocks state block =
      ok (cont (out,next)) ∧
      words out = Spec.compressBlock (words state) (Spec.bytes (data.val.map ofU8))
        (offset.val+64*block.val) ∧ next.val = block.val+1 := by
  have hbound := data.property
  let pos : Usize := UScalar.ofNatCore (offset.val+64*block.val) (by scalar_tac)
  let next : Usize := UScalar.ofNatCore (block.val+1) (by scalar_tac)
  obtain ⟨out,hout,hwords⟩ := compress_refines state data pos (by simp only [pos,UScalar.ofNatCore_val_eq]; omega)
  refine ⟨out,next,?_,hwords,rfl⟩
  have hb : block < blocks := hblock
  simp only [sha256.portable.compress_blocks_loop.body,hb,if_true,sha256.BLOCK]
  simp (disch := scalar_tac) only [mul_ok,add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  change (do let s ← sha256.portable.compress state data pos; ok (cont (s,next))) = _
  rw [hout]
  rfl

theorem compress_blocks_loop_refines (state : Array U32 8#usize) (data : Slice U8)
    (offset blocks block : Usize) (hblock : block.val ≤ blocks.val)
    (hdata : offset.val+64*blocks.val ≤ data.val.length) :
    ∃ out, sha256.portable.compress_blocks_loop data offset blocks state block = ok out ∧
      words out = Spec.compressBlocks (words state) (Spec.bytes (data.val.map ofU8))
        (offset.val+64*block.val) (blocks.val-block.val) := by
  induction hn : blocks.val-block.val generalizing state block with
  | zero =>
    have hstop : ¬ block < blocks := by change ¬ block.val < blocks.val; omega
    refine ⟨state,?_,rfl⟩
    rw [sha256.portable.compress_blocks_loop,loop.eq_1]
    simp only [sha256.portable.compress_blocks_loop.body,hstop,if_false]
  | succ n ih =>
    obtain ⟨out,next,hbody,hout,hnext⟩ := compress_blocks_step state data offset blocks block (by omega) hdata
    obtain ⟨final,hfinal,hmodel⟩ := ih out next (by omega) (by omega)
    refine ⟨final,?_,?_⟩
    · rw [sha256.portable.compress_blocks_loop,loop.eq_1]
      simpa only [hbody] using hfinal
    · rw [hmodel,hout,hnext]
      unfold Spec.compressBlocks
      rw [List.range']
      simp only [List.foldl_cons]
      congr 2

theorem compress_blocks_refines (state : Array U32 8#usize) (data : Slice U8)
    (offset blocks : Usize) (hdata : offset.val+64*blocks.val ≤ data.val.length) :
    ∃ out, sha256.portable.compress_blocks state data offset blocks = ok out ∧
      words out = Spec.compressBlocks (words state) (Spec.bytes (data.val.map ofU8))
        offset.val blocks.val := by
  simpa only [sha256.portable.compress_blocks,UScalar.ofNatCore_val_eq,
    Nat.mul_zero,Nat.add_zero,Nat.sub_zero] using
    compress_blocks_loop_refines state data offset blocks 0#usize (by scalar_tac) hdata

end LeanBlsSimd.Sha256.Portable
