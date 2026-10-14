import LeanBlsSimd.Refines.DecompressG1

open Aeneas Aeneas.Std Result ControlFlow
open silver_bls_simd

namespace LeanBlsSimd.UncompressG1

theorem simd_body_runs [G1Externals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (stop start next : Usize) (target : List (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) (htarget : target.length = inputs.val.length)
    (hlt : start.val < stop.val) (hnext : next.val = start.val + 8)
    (hbound : next.val ≤ inputs.val.length)
    (hchunk : ∀ (c : Array (Array U8 48#usize) 8#usize)
      (s : Slice (Option blst.blst_p1_affine)),
      c.val = inputs.val.slice start.val next.val → s.val.length = 8 →
      ∃ r, silver_bls_simd.decompress_g1_chunk c s = ok r ∧
        r.val = target.slice start.val next.val) :
    ∃ result, silver_bls_simd.uncompress_in_g1_loop0.body inputs stop out true start =
        ok (cont (result, true, next)) ∧
      result.val.length = out.val.length ∧
      ∀ i, i < out.val.length → result.val[i]! =
        if start.val ≤ i ∧ i < next.val then target[i]! else out.val[i]! := by
  let ss : Slice (Array U8 48#usize) :=
    ⟨inputs.val.slice start.val next.val,
      le_trans (List.slice_length_le _ _ _) inputs.property⟩
  let os : Slice (Option blst.blst_p1_affine) :=
    ⟨out.val.slice start.val next.val, le_trans (List.slice_length_le _ _ _) out.property⟩
  have hss : ss.val.length = 8 := by
    dsimp [ss]
    rw [List.slice_length]
    omega
  have hos : os.val.length = 8 := by
    dsimp [os]
    rw [List.slice_length]
    omega
  let initial : Array (Array U8 48#usize) 8#usize :=
    Array.repeat 8#usize (Array.repeat 48#usize 0#u8)
  let c := Array.from_slice initial ss
  have hc : c.val = inputs.val.slice start.val next.val := by
    simp [c, Array.from_slice, hss, ss]
  obtain ⟨r, hr, hrv⟩ := hchunk c os hc hos
  let result := out.setSlice! start.val r.val
  refine ⟨result, ?_, ?_, ?_⟩
  · have hadd : start + silver_bls_simd.LANES = ok next := by
      rw [silver_bls_simd.LANES, add_ok start 8#usize
        (by have := next.hBounds; simpa [hnext] using this)]
      congr 1
      exact UScalar.eq_of_val_eq (by simp [hnext])
    have hindex : core.slice.index.Slice.index
        (core.slice.index.SliceIndexRangeUsizeSlice (Array U8 48#usize)) inputs
        { start, «end» := next } = ok ss :=
      slice_index_ok inputs start next (by omega) hbound
    have hcopy : core.slice.Slice.copy_from_slice
        (Array.Insts.CoreMarkerCopy 48#usize core.marker.CopyU8)
        (Array.to_slice initial) ss = ok ss := by
      apply copy_from_slice_ok
      simp [Array.to_slice, initial, hss]
    have hmut : core.slice.index.Slice.index_mut
        (core.slice.index.SliceIndexRangeUsizeSlice (Option blst.blst_p1_affine)) out
        { start, «end» := next } = ok (os, fun s => out.setSlice! start.val s.val) := by
      simp only [core.slice.index.Slice.index_mut,
        core.slice.index.SliceIndexRangeUsizeSlice.index_mut, UScalar.le_equiv]
      rw [if_pos (by simp only [Slice.length]; constructor <;> omega)]
      rfl
    simp only [silver_bls_simd.uncompress_in_g1_loop0.body, show start < stop from hlt,
      if_true, Array.to_slice_mut, lift, bind_tc_ok, hadd, hindex, hmut]
    simp only [Function.uncurry_apply_pair]
    rw [hcopy]
    simp only [bind_tc_ok]
    change (do let r ← silver_bls_simd.decompress_g1_chunk c os
               ok (cont (out.setSlice! start.val r.val, true, next))) = _
    rw [hr]
    rfl
  · simp [result, Slice.setSlice!]
  · intro i hi
    simp only [result, Slice.setSlice!_val, hrv]
    by_cases h : start.val ≤ i ∧ i < next.val
    · rw [if_pos h, List.getElem!_setSlice!_middle]
      · rw [List.getElem!_slice _ _ _ _ (by omega)]
        congr 1
        omega
      · rw [List.slice_length]
        omega
    · rw [if_neg h]
      apply List.getElem!_setSlice!_same
      rw [List.slice_length]
      omega

end LeanBlsSimd.UncompressG1
