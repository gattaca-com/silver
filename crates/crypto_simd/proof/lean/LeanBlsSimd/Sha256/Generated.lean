import LeanBlsSimd.Sha256.PortableCompress
import LeanBlsSimd.Sha256.Streaming

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Generated

abbrev Compressor := Array U32 8#usize → Slice U8 → Usize → Usize → Result (Array U32 8#usize)

def CompressorRefines (compress : Compressor) : Prop :=
  ∀ state data offset blocks, offset.val+64*blocks.val ≤ data.val.length →
    ∃ out, compress state data offset blocks = ok out ∧
      words out = Spec.compressBlocks (words state) (Spec.bytes (data.val.map ofU8)) offset.val blocks.val

def view (state : Array U32 8#usize) (pending : Array U8 64#usize) (pending_len : Usize)
    (length : U64) : Streaming.State :=
  ⟨words state,(pending.val.take pending_len.val).map ofU8,ofU64 length⟩

def updateBlocks {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (state : Array U32 8#usize) (pending : Array U8 64#usize)
    (start : Usize) (length : U64) (data : Slice U8) : Result S := do
  let i4 := Slice.len data
  let i5 ← i4 - start
  let blocks ← i5 / sha256.BLOCK
  let a2 ← compress state data start blocks
  let i6 ← sha256.BLOCK * blocks
  let start1 ← start + i6
  let i7 := Slice.len data
  let i8 ← i7 - start1
  let (s, index_mut_back) ←
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8)) pending
      { «end» := i8 }
  let s1 ←
    core.slice.index.Slice.index
      (core.slice.index.SliceIndexRangeFromUsizeSlice Std.U8) data
      { start := start1 }
  let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
  let a3 := index_mut_back s2
  ok (mk a2 a3 i8 length)

def update {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (state : Array U32 8#usize) (pending : Array U8 64#usize)
    (pending_len : Usize) (length : U64) (data : Slice U8) : Result S := do
  let i := Slice.len data
  let i1 ← lift (UScalar.cast .U64 i)
  let i2 ← lift (core.num.U64.wrapping_add length i1)
  let room ← sha256.BLOCK - pending_len
  let i3 := Slice.len data
  if i3 < room
  then
    let i4 := Slice.len data
    let i5 ← pending_len + i4
    let (s, index_mut_back) ←
      core.array.Array.index_mut (core.ops.index.IndexMutSlice
        (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) pending
        { start := pending_len, «end» := i5 }
    let s1 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s data
    let i6 := Slice.len data
    let i7 ← pending_len + i6
    let a := index_mut_back s1
    ok (mk state a i7 i2)
  else
    let (a, a1, start) ←
      if pending_len > 0#usize
      then
        do
        let (s, index_mut_back) ←
          core.array.Array.index_mut (core.ops.index.IndexMutSlice
            (core.slice.index.SliceIndexRangeFromUsizeSlice Std.U8))
            pending { start := pending_len }
        let s1 ←
          core.slice.index.Slice.index
            (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8) data
            { «end» := room }
        let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
        let a2 := index_mut_back s2
        let s3 ← lift (Array.to_slice a2)
        let a3 ←
          compress state s3 0#usize 1#usize
        ok (a3, a2, room)
      else ok (state, pending, 0#usize)
    updateBlocks mk compress a a1 start i2 data


def finish (compress : Compressor) (state : Array U32 8#usize) (pending : Array U8 64#usize)
    (pending_len : Usize) (length : U64) : Result (Array U8 32#usize) := do
  let tail := Array.repeat 128#usize 0#u8
  let (s, index_mut_back) ←
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8)) tail
      { «end» := pending_len }
  let s1 ←
    core.array.Array.index (core.ops.index.IndexSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8)) pending
      { «end» := pending_len }
  let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
  let tail1 := index_mut_back s2
  let tail2 ← Array.update tail1 pending_len 128#u8
  let i ← sha256.BLOCK - 8#usize
  let blocks ← if pending_len < i
                 then ok 1#usize
                 else ok 2#usize
  let i1 ← sha256.BLOCK * blocks
  let i2 ← i1 - 8#usize
  let (s3, index_mut_back1) ←
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) tail2
      { start := i2, «end» := i1 }
  let i3 ← length <<< 3#i32
  let a ← lift (core.num.U64.to_be_bytes i3)
  let s4 ← lift (Array.to_slice a)
  let s5 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s3 s4
  let tail3 := index_mut_back1 s5
  let s6 ← lift (Array.to_slice tail3)
  let state ← compress state s6 0#usize blocks
  let digest := Array.repeat 32#usize 0#u8
  sha256.portable.Sha256.finish_loop state digest 0#usize


theorem portable_update_eq (s : sha256.portable.Sha256) (data : Slice U8) :
    sha256.portable.Sha256.update s data =
      update sha256.portable.Sha256.mk sha256.portable.compress_blocks
        s.state s.pending s.pending_len s.length data := rfl

theorem extensions_update_eq (s : sha256.extensions.Sha256) (data : Slice U8) :
    sha256.extensions.Sha256.update s data =
      update sha256.extensions.Sha256.mk sha256.extensions.compress_blocks
        s.state s.pending s.pending_len s.length data := rfl

theorem portable_finish_eq (s : sha256.portable.Sha256) :
    sha256.portable.Sha256.finish s = finish sha256.portable.compress_blocks
      s.state s.pending s.pending_len s.length := rfl

theorem extensions_finish_eq (s : sha256.extensions.Sha256) :
    sha256.extensions.Sha256.finish s = finish sha256.extensions.compress_blocks
      s.state s.pending s.pending_len s.length := by
  unfold sha256.extensions.Sha256.finish finish
  rfl

end LeanBlsSimd.Sha256.Generated
