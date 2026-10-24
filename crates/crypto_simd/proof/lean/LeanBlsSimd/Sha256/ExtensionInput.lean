import LeanBlsSimd.Sha256.ExtensionLoad
import LeanBlsSimd.Sha256.ExtensionLoop

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open private EthLib.Cryptography.Bls.Sha256.big32 from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Extensions

set_option maxRecDepth 2048
attribute [local irreducible] Spec.schedule

def loadChunk (data : Slice U8) (start : Nat) (h : start+16 ≤ data.val.length) : Array U8 16#usize :=
  ⟨data.val.slice start (start+16),by simp [List.slice]; omega⟩

theorem loadChunk_get (data : Slice U8) (start : Nat) (h : start+16 ≤ data.val.length)
    (i : Nat) (hi : i < 16) :
    (Spec.bytes ((loadChunk data start h).val.map ofU8))[i]! =
      (Spec.bytes (data.val.map ofU8))[start+i]! := by
  simp only [Spec.bytes_get]
  rw [getElem!_pos _ i (by simp only [List.length_map,(loadChunk data start h).property]; exact hi),
    getElem!_pos _ (start+i) (by simp only [List.length_map]; omega)]
  simp [loadChunk,List.slice,List.getElem_map,List.getElem_take,List.getElem_drop]

theorem loadChunk_big32 (data : Slice U8) (start : Nat) (h : start+16 ≤ data.val.length)
    (i : Nat) (hi : i+4 ≤ 16) :
    Spec.big32 (Spec.bytes ((loadChunk data start h).val.map ofU8)) i =
      Spec.big32 (Spec.bytes (data.val.map ofU8)) (start+i) := by
  simp only [Spec.big32,EthLib.Cryptography.Bls.Sha256.big32]
  simp (disch := omega) only [loadChunk_get,Nat.add_assoc]

theorem load_step (data : Slice U8) (block : Usize) (w : Array M128 4#usize)
    (i : Usize) (hi : i.val < 4) (hdata : 64*block.val+64 ≤ data.val.length) :
    ∃ next, sha256.extensions.compress_blocks_loop0_loop0.body data byteSwap block w i =
      ok (cont (w.set i (quad (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) (4*i.val)),next)) ∧
      next.val = i.val+1 := by
  have hbound := data.property
  have hchunk : 64*block.val+16*i.val+16 ≤ data.val.length := by omega
  let start : Usize := UScalar.ofNatCore (64*block.val+16*i.val) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (64*block.val+16*i.val+16) (by scalar_tac)
  let next : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
  let chunk := loadChunk data (64*block.val+16*i.val) hchunk
  let src := Array.to_slice chunk
  have hindex : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
      data {start, «end» := stop} = ok src := by
    simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeUsizeSlice.index,
      start,stop,src,chunk,loadChunk,Array.to_slice,hchunk]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 16#usize 0#u8)) src = ok src := by
    simp [core.slice.Slice.copy_from_slice,UScalar.eq_equiv,src,Array.to_slice,chunk.property]
  have hback : Array.from_slice (Array.repeat 16#usize 0#u8) src = chunk := by
    simp [Array.from_slice,src,Array.to_slice,chunk.property]
  have hload : (do
      let v ← sha256.extensions.load_bytes chunk
      core.core_arch.x86.ssse3._mm_shuffle_epi8 v byteSwap) =
      ok (quad (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) (4*i.val)) := by
    rw [load_swapped_words]
    apply congrArg ok
    apply Vector.ext
    intro j hj
    interval_cases j <;>
      norm_num only [quad,Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ]
    all_goals
      simp (disch := omega) only [Spec.schedule_get_initial]
      rw [loadChunk_big32 (hi := by omega)]
      congr 1
      omega
  refine ⟨next,?_,rfl⟩
  have hi' : i < 4#usize := hi
  simp only [sha256.extensions.compress_blocks_loop0_loop0.body,hi',if_true,
    lift,Array.to_slice_mut,bind_tc_ok,Function.uncurry_apply_pair,sha256.BLOCK]
  simp (disch := scalar_tac) only [mul_ok,add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  change (do
    let s1 ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
      data {start, «end» := stop}
    let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 16#usize 0#u8)) s1
    let v ← sha256.extensions.load_bytes (Array.from_slice (Array.repeat 16#usize 0#u8) s2)
    let v1 ← core.core_arch.x86.ssse3._mm_shuffle_epi8 v byteSwap
    let a ← Array.update w i v1
    ok (cont (a,next))) = _
  rw [hindex]
  simp only [bind_tc_ok,hcopy,hback]
  rw [← bind_assoc,hload]
  simp only [bind_tc_ok]
  rw [update_eq _ _ _ hi]
  rfl

theorem window_get (w : _root_.Array UInt32) (q j : Nat) (hj : j < 4) :
    (window w q)[j]! = quad w (4*min (q+j) 15) := by
  interval_cases j <;> rfl

theorem load_loop_refines (data : Slice U8) (block : Usize) (w : Array M128 4#usize)
    (i : Usize) (hi : i.val ≤ 4) (hdata : 64*block.val+64 ≤ data.val.length)
    (hp : ∀ j : Nat, j < i.val → w[j]! =
      quad (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) (4*j)) :
    sha256.extensions.compress_blocks_loop0_loop0 data byteSwap block w i =
      ok (window (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) 0) := by
  induction hn : 4-i.val generalizing w i with
  | zero =>
    have hstop : ¬ i < 4#usize := by change ¬ i.val < 4; omega
    have hw : w = window (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) 0 := by
      apply Subtype.ext
      apply List.ext_getElem
      · simp only [w.property,(window _ _).property]
      · intro j hj hj'
        have hj4 : j < 4 := by simpa only [w.property] using hj
        have h := hp j (by omega)
        have hh := window_get (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) 0 j hj4
        simp only [Nat.zero_add,Nat.min_eq_left (by omega : j ≤ 15)] at hh
        simp only [Array.getElem!_Nat_eq] at h hh
        rw [getElem!_pos w.val j hj] at h
        rw [getElem!_pos (window _ _).val j hj'] at hh
        exact h.trans hh.symm
    rw [sha256.extensions.compress_blocks_loop0_loop0,loop.eq_1]
    simp only [sha256.extensions.compress_blocks_loop0_loop0.body,hstop,if_false,hw]
  | succ n ih =>
    obtain ⟨next,hbody,hnext⟩ := load_step data block w i (by omega) hdata
    have hp' : ∀ j : Nat, j < next.val →
        (w.set i (quad (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) (4*i.val)))[j]! =
          quad (Spec.schedule (Spec.bytes (data.val.map ofU8)) (64*block.val)) (4*j) := by
      intro j hj
      by_cases he : i.val = j
      · rw [Array.getElem!_Nat_set_eq _ _ _ _ ⟨he,by simp only [Array.length,w.property,UScalar.ofNatCore_val_eq]; omega⟩,he]
      · rw [Array.getElem!_Nat_set_ne _ _ _ _ he]
        exact hp j (by omega)
    have hr := ih _ next (by omega) hp' (by omega)
    rw [sha256.extensions.compress_blocks_loop0_loop0,loop.eq_1]
    simpa only [hbody] using hr

end LeanBlsSimd.Sha256.Extensions
