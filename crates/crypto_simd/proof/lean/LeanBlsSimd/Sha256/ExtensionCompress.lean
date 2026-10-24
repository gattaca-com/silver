import LeanBlsSimd.Sha256.ExtensionInput

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Extensions

attribute [local irreducible] Spec.rounds Spec.schedule Spec.feedForward Spec.compressBlock abef cdgh
set_option maxRecDepth 2048

theorem block_step (state : _root_.Array UInt32) (data : Slice U8)
    (blocks block : Usize) (hb : block.val < blocks.val)
    (hdata : 64*blocks.val ≤ data.val.length) :
    ∃ next, sha256.extensions.compress_blocks_loop0.body blocks data byteSwap
      (abef (Spec.stateWords state)) (cdgh (Spec.stateWords state)) block =
      ok (cont (abef (Spec.stateWords (Spec.compressBlock state (Spec.bytes (data.val.map ofU8)) (64*block.val))),
        cdgh (Spec.stateWords (Spec.compressBlock state (Spec.bytes (data.val.map ofU8)) (64*block.val))),next)) ∧
      next.val = block.val+1 := by
  let next : Usize := UScalar.ofNatCore (block.val+1) (by scalar_tac)
  have hload := load_loop_refines data block (Array.repeat 4#usize (abef (Spec.stateWords state)))
    0#usize (by decide) (by omega) (by intro j hj; exact (Nat.not_lt_zero j hj).elim)
  have hquad := quad_loop_refines (Spec.bytes (data.val.map ofU8)) (64*block.val)
    (Spec.stateWords state) 0#usize (by decide)
  norm_num only [UScalar.ofNatCore_val_eq,Nat.mul_zero,Nat.sub_zero] at hload hquad
  refine ⟨next,?_,rfl⟩
  have hb' : block < blocks := hb
  simp only [sha256.extensions.compress_blocks_loop0.body,hb',if_true,hload]
  simp only [bind_tc_ok,hquad,core.core_arch.x86.sse2._mm_add_epi32]
  rw [add_ok _ _ (by scalar_tac)]
  simp only [bind_tc_ok]
  rw [Spec.compressBlock_eq]
  exact congrArg (fun p : M128 × M128 => ok (cont (p.1,p.2,next)))
    (feed_forward state (Spec.rounds (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val))
      0 64 (Spec.stateWords state)))

theorem block_loop_refines (state : _root_.Array UInt32) (data : Slice U8)
    (blocks block : Usize) (hb : block.val ≤ blocks.val)
    (hdata : 64*blocks.val ≤ data.val.length) :
    sha256.extensions.compress_blocks_loop0 blocks data byteSwap
      (abef (Spec.stateWords state)) (cdgh (Spec.stateWords state)) block =
      let out := Spec.compressBlocks state (Spec.bytes (data.val.map ofU8)) (64*block.val) (blocks.val-block.val)
      ok (abef (Spec.stateWords out),cdgh (Spec.stateWords out)) := by
  induction hn : blocks.val-block.val generalizing state block with
  | zero =>
    have hstop : ¬ block < blocks := by change ¬ block.val < blocks.val; omega
    rw [sha256.extensions.compress_blocks_loop0,loop.eq_1]
    simp only [sha256.extensions.compress_blocks_loop0.body,hstop,if_false,Spec.compressBlocks_zero]
  | succ n ih =>
    obtain ⟨next,hbody,hnext⟩ := block_step state data blocks block (by omega) hdata
    have hr := ih (Spec.compressBlock state (Spec.bytes (data.val.map ofU8)) (64*block.val))
      next (by omega) (by omega)
    have hm : Spec.compressBlocks
        (Spec.compressBlock state (Spec.bytes (data.val.map ofU8)) (64*block.val))
        (Spec.bytes (data.val.map ofU8)) (64*next.val) (blocks.val-next.val) =
        Spec.compressBlocks state (Spec.bytes (data.val.map ofU8)) (64*block.val) (blocks.val-block.val) := by
      unfold Spec.compressBlocks
      rw [show blocks.val-block.val = (blocks.val-next.val)+1 by omega,List.range']
      simp only [List.foldl_cons]
      congr 2
      omega
    rw [show blocks.val-next.val = n by omega,hn] at hm
    dsimp only at hr ⊢
    rw [hm] at hr
    rw [sha256.extensions.compress_blocks_loop0,loop.eq_1]
    simpa only [hbody] using hr

theorem load_words_four (a b c d : UInt32) :
    sha256.extensions.load_words (Array.make 4#usize [word a,word b,word c,word d] (by rfl)) =
      ok #v[a,b,c,d] := load_words_refines #v[a,b,c,d]

theorem compress_blocks_refines (state : Array U32 8#usize) (data : Slice U8)
    (offset blocks : Usize) (hdata : offset.val+64*blocks.val ≤ data.val.length) :
    ∃ out, sha256.extensions.compress_blocks state data offset blocks = ok out ∧
      words out = Spec.compressBlocks (words state) (Spec.bytes (data.val.map ofU8)) offset.val blocks.val := by
  have hbound := data.property
  let stop : Usize := UScalar.ofNatCore (offset.val+64*blocks.val) (by scalar_tac)
  let input : Slice U8 := ⟨data.val.slice offset.val stop.val,by simp [List.slice]; scalar_tac⟩
  have hinput : 64*blocks.val ≤ input.val.length := by simp [input,List.slice,stop]; omega
  have hindex : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
      data {start := offset, «end» := stop} = ok input := by
    simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeUsizeSlice.index,
      stop,input,hdata]
  have hswap : core.core_arch.x86.sse2._mm_set_epi64x 868365760874482187#i64
      289644378169868803#i64 = ok byteSwap := by
    unfold core.core_arch.x86.sse2._mm_set_epi64x
    apply congrArg ok
    decide +kernel
  have hi := initial_layout (Spec.stateWords (words state))
  dsimp only [Spec.stateWords] at hi
  have hf := block_loop_refines (words state) input blocks 0#usize (by scalar_tac) hinput
  norm_num only [UScalar.ofNatCore_val_eq,Nat.mul_zero,Nat.sub_zero] at hf
  let result := Spec.compressBlocks (words state) (Spec.bytes (input.val.map ofU8)) 0 blocks.val
  have hl := final_layout (Spec.stateWords result)
  dsimp only at hl
  have hilo := congrArg Prod.fst hi
  have hihi := congrArg Prod.snd hi
  have hlow := congrArg Prod.fst hl
  have hhigh := congrArg Prod.snd hl
  dsimp only at hilo hihi hlow hhigh
  dsimp only [Spec.stateWords] at hf hlow hhigh
  rw [sha256.extensions.compress_blocks]
  simp only [sha256.BLOCK]
  simp (disch := scalar_tac) only [mul_ok,add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  rw [hindex]
  simp only [bind_tc_ok,hswap]
  simp (disch := scalar_tac) only [Portable.index_word,bind_tc_ok]
  norm_num only [UScalar.ofNatCore_val_eq]
  simp only [load_words_four,bind_tc_ok,core.core_arch.x86.sse2._mm_shuffle_epi32,
    core.core_arch.x86.ssse3._mm_alignr_epi8,core.core_arch.x86.sse41._mm_blend_epi16]
  simp only [show (I32.bv 177#i32).toNat = 177 by decide +kernel,
    show (I32.bv 27#i32).toNat = 27 by decide +kernel,
    show (I32.bv 8#i32).toNat = 8 by decide +kernel,
    show (I32.bv 240#i32).toNat = 240 by decide +kernel]
  rw [hilo,hihi,hf]
  simp only [bind_tc_ok,Function.uncurry_apply_pair]
  rw [hlow,hhigh]
  simp only [store_words_refines,bind_tc_ok]
  refine ⟨_,rfl,?_⟩
  have hsize : result.size = 8 := by
    dsimp only [result]
    induction blocks.val with
    | zero => simp [Spec.compressBlocks_zero]
    | succ n ih => rw [Spec.compressBlocks_succ,Spec.compressBlock_eq]; unfold Spec.feedForward; rfl
  have hrestore : words (Array.make 8#usize
      [word result[0]!,word result[1]!,word result[2]!,word result[3]!,
        word result[4]!,word result[5]!,word result[6]!,word result[7]!] (by rfl)) = result := by
    apply _root_.Array.ext
    · simp only [words_size,UScalar.ofNatCore_val_eq,hsize]
    · intro i h1 h2
      have hi8 : i < 8 := by omega
      interval_cases i <;>
        simp only [words,Array.make,List.map_cons,List.map_nil,ofWord_word,
          List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ]
      all_goals exact getElem!_pos result _ (by omega)
  change words (Array.make 8#usize
    [word result[0]!,word result[1]!,word result[2]!,word result[3]!,
      word result[4]!,word result[5]!,word result[6]!,word result[7]!] (by rfl)) = _
  rw [hrestore]
  apply Spec.compressBlocks_congr
  intro i hi
  rw [Spec.bytes_get,Spec.bytes_get]
  rw [getElem!_pos _ (0+i) (by simp only [List.length_map]; omega),
    getElem!_pos _ (offset.val+i) (by simp only [List.length_map]; omega)]
  simp [input,List.slice,List.getElem_map,List.getElem_take,List.getElem_drop]

end LeanBlsSimd.Sha256.Extensions
