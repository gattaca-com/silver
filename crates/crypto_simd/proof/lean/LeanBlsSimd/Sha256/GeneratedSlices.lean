import LeanBlsSimd.Sha256.Generated

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd.Sha256.Generated

def range (s : Slice U8) (start stop : Nat) : Slice U8 :=
  ⟨s.val.slice start stop,by have h := s.property; simp [List.slice]; omega⟩

@[simp] theorem range_length (s : Slice U8) (start stop : Nat)
    (hi : stop ≤ s.val.length) :
    (range s start stop).val.length = stop-start := by simp [range,List.slice]; omega

theorem index_range (s : Slice U8) (start stop : Usize)
    (hlo : start.val ≤ stop.val) (hi : stop.val ≤ s.val.length) :
    core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8)
      s {start, «end» := stop} = ok (range s start.val stop.val) := by
  simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeUsizeSlice.index,
    range,hlo,hi,UScalar.le_equiv,Slice.length]

theorem index_to (s : Slice U8) (stop : Usize) (hi : stop.val ≤ s.val.length) :
    core.slice.index.Slice.index (core.slice.index.SliceIndexRangeToUsizeSlice U8)
      s {«end» := stop} = ok (range s 0 stop.val) := by
  simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeToUsizeSlice.index,
    range,hi,Slice.length]

theorem index_from (s : Slice U8) (start : Usize) (hi : start.val ≤ s.val.length) :
    core.slice.index.Slice.index (core.slice.index.SliceIndexRangeFromUsizeSlice U8)
      s {start} = ok (range s start.val s.val.length) := by
  simp [core.slice.index.Slice.index,core.slice.index.SliceIndexRangeFromUsizeSlice.index,
    range,hi,Slice.length,Slice.drop,List.slice]
  apply Subtype.ext
  simpa only [List.length_drop] using (@List.take_length U8 (s.val.drop start.val)).symm

theorem array_index_to {n : Usize} (a : Array U8 n) (stop : Usize) (hi : stop.val ≤ n.val) :
    core.array.Array.index (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeToUsizeSlice U8))
      a {«end» := stop} = ok (range a.to_slice 0 stop.val) := by
  apply index_to
  simpa only [Array.to_slice,a.property] using hi

theorem index_mut_range {n : Usize} (a : Array U8 n) (start stop : Usize)
    (hlo : start.val ≤ stop.val) (hi : stop.val ≤ n.val) :
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeUsizeSlice U8)) a {start, «end» := stop} =
      ok (range a.to_slice start.val stop.val,fun s : Slice U8 => a.setSlice! start.val s.val) := by
  simp [core.array.Array.index_mut,core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut,core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
    Array.to_slice,Slice.length,UScalar.le_equiv,hlo,hi,a.property,
    Array.from_slice,range]
  rfl

theorem index_mut_to {n : Usize} (a : Array U8 n) (stop : Usize) (hi : stop.val ≤ n.val) :
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice U8)) a {«end» := stop} =
      ok (range a.to_slice 0 stop.val,fun s : Slice U8 => a.setSlice! 0 s.val) := by
  simp [core.array.Array.index_mut,core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut,core.slice.index.SliceIndexRangeToUsizeSlice.index_mut,
    Array.to_slice,Slice.length,hi,a.property,Array.from_slice,range]
  rfl

theorem index_mut_from {n : Usize} (a : Array U8 n) (start : Usize) (hi : start.val ≤ n.val) :
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeFromUsizeSlice U8)) a {start} =
      ok (range a.to_slice start.val n.val,fun s : Slice U8 => a.setSlice! start.val s.val) := by
  simp [core.array.Array.index_mut,core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut,core.slice.index.SliceIndexRangeFromUsizeSlice.index_mut,
    Array.to_slice,Slice.length,Slice.drop,hi,a.property,Array.from_slice,range,List.slice]
  constructor
  · apply Subtype.ext
    simpa only [List.length_drop,a.property] using (@List.take_length U8 (a.val.drop start.val)).symm
  · rfl

theorem copy_eq (dest src : Slice U8) (h : dest.val.length = src.val.length) :
    core.slice.Slice.copy_from_slice core.marker.CopyU8 dest src = ok src := by
  simp [core.slice.Slice.copy_from_slice,UScalar.eq_equiv,h]

theorem take_setSlice {α : Type} (xs ys : List α) (start : Nat)
    (h : start+ys.length ≤ xs.length) :
    (xs.setSlice! start ys).take (start+ys.length) = xs.take start ++ ys := by
  have hs : start ≤ xs.length := by omega
  simp only [List.setSlice!,Nat.min_eq_left (show ys.length ≤ xs.length-start by omega),List.take_length]
  have hl : (xs.take start ++ ys).length = start+ys.length := by simp [hs]
  rw [← hl,List.take_left]

theorem take_setSlice_zero {α : Type} (xs ys : List α) (h : ys.length ≤ xs.length) :
    (xs.setSlice! 0 ys).take ys.length = ys := by
  simpa only [Nat.zero_add,List.take_zero,List.nil_append] using take_setSlice xs ys 0 (by omega)

end LeanBlsSimd.Sha256.Generated
