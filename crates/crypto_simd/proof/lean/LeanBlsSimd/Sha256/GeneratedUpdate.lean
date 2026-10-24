import LeanBlsSimd.Sha256.GeneratedSlices

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Generated

set_option maxRecDepth 2048

def absorbedLength (length : U64) (data : Slice U8) : U64 :=
  core.num.U64.wrapping_add length (UScalar.cast .U64 (Slice.len data))

theorem absorbedLength_model (length : U64) (data : Slice U8) :
    ofU64 (absorbedLength length data) = ofU64 length + UInt64.ofNat data.val.length := by
  have hc : ofU64 (UScalar.cast .U64 (Slice.len data)) = UInt64.ofNat data.val.length := by
    apply UInt64.toNat_inj.mp
    change ((Slice.len data).bv.setWidth 64).toNat = data.val.length % 2^64
    rw [BitVec.toNat_setWidth]
    change (Slice.len data).val % 2^64 = _
    rw [Slice.len_val]
  change ofU64 length + ofU64 (UScalar.cast .U64 (Slice.len data)) = _
  rw [hc]

theorem update_short {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (state : Array U32 8#usize) (pending : Array U8 64#usize)
    (p : Usize) (length : U64) (data : Slice U8) (hp : p.val < 64)
    (hshort : data.val.length < 64-p.val) :
    ∃ next, next.val = p.val+data.val.length ∧
      update mk compress state pending p length data =
        ok (mk state (pending.setSlice! p.val data.val) next (absorbedLength length data)) := by
  let next : Usize := UScalar.ofNatCore (p.val+data.val.length) (by scalar_tac)
  refine ⟨next,rfl,?_⟩
  simp only [update,lift,bind_tc_ok,sha256.BLOCK]
  rw [sub_ok _ _ (by scalar_tac)]
  simp only [bind_tc_ok,UScalar.lt_equiv,UScalar.ofNatCore_val_eq,Slice.len_val,Slice.length,
    hshort,if_true]
  simp (disch := scalar_tac) only [add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq,Slice.len_val]
  rw [index_mut_range _ _ _ (by scalar_tac) (by scalar_tac)]
  simp only [bind_tc_ok,Function.uncurry_apply_pair]
  rw [copy_eq _ data (by
    rw [range_length _ _ _ (by simp only [UScalar.ofNatCore_val_eq,Slice.len_val,Slice.length,Array.to_slice,pending.property]; omega)]
    simp only [UScalar.ofNatCore_val_eq,Slice.len_val,Slice.length]; omega)]
  rfl

theorem update_blocks {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (hc : CompressorRefines compress) (state : Array U32 8#usize)
    (pending : Array U8 64#usize) (start : Usize) (length : U64) (data : Slice U8)
    (hs : start.val ≤ data.val.length) :
    ∃ out next,
      updateBlocks mk compress state pending start length data =
        ok (mk out (pending.setSlice! 0 (data.val.drop (start.val+64*((data.val.length-start.val)/64)))) next length) ∧
      words out = Spec.compressBlocks (words state) (Spec.bytes (data.val.map ofU8)) start.val
        ((data.val.length-start.val)/64) ∧
      next.val = (data.val.length-start.val)%64 := by
  have hbound := data.property
  let blocks : Usize := UScalar.ofNatCore ((data.val.length-start.val)/64) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (start.val+64*((data.val.length-start.val)/64)) (by scalar_tac)
  let next : Usize := UScalar.ofNatCore (data.val.length-stop.val) (by scalar_tac)
  have hstop : stop.val ≤ data.val.length := by simp only [stop,UScalar.ofNatCore_val_eq]; omega
  have hnext : next.val = (data.val.length-start.val)%64 := by
    simp only [next,stop,UScalar.ofNatCore_val_eq]; omega
  have hnextlt : next.val < 64 := by rw [hnext]; omega
  obtain ⟨out,hout,hmodel⟩ := hc state data start blocks (by simp only [blocks,UScalar.ofNatCore_val_eq]; omega)
  refine ⟨out,next,?_,hmodel,hnext⟩
  simp only [updateBlocks,sha256.BLOCK]
  simp (disch := scalar_tac) only [sub_ok,div_ok,bind_tc_ok,UScalar.ofNatCore_val_eq,Slice.len_val]
  change (do
    let a2 ← compress state data start blocks
    let i6 ← 64#usize * blocks
    let start1 ← start+i6
    let i8 ← Slice.len data-start1
    let (s, back) ← core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice U8)) pending {«end» := i8}
    let s1 ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeFromUsizeSlice U8)
      data {start := start1}
    let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
    ok (mk a2 (back s2) i8 length)) = _
  rw [hout]
  simp (disch := scalar_tac) only [bind_tc_ok,mul_ok,add_ok,sub_ok,UScalar.ofNatCore_val_eq,Slice.len_val]
  change (do
    let (s, back) ← core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeToUsizeSlice U8)) pending {«end» := next}
    let s1 ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeFromUsizeSlice U8) data {start := stop}
    let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
    ok (mk out (back s2) next length)) = _
  rw [index_mut_to _ _ (by change next.val ≤ 64; omega)]
  simp only [bind_tc_ok,Function.uncurry_apply_pair,index_from _ _ hstop]
  rw [copy_eq _ _ (by
    rw [range_length _ _ _ (by simpa only [Array.to_slice,pending.property] using
      (show next.val ≤ 64 by omega)),range_length _ _ _ (by omega)]
    simp only [Nat.sub_zero,next,UScalar.ofNatCore_val_eq])]
  simp only [bind_tc_ok]
  have hr : (range data stop.val data.val.length).val = data.val.drop stop.val := by
    simpa only [range,List.slice,List.length_drop] using (@List.take_length U8 (data.val.drop stop.val))
  rw [hr]
  rfl


theorem filled_pending (pending : Array U8 64#usize) (p : Usize) (data : Slice U8)
    (hp : p.val < 64) (hlong : 64-p.val ≤ data.val.length) :
    (pending.setSlice! p.val (data.val.take (64-p.val))).val =
      pending.val.take p.val ++ data.val.take (64-p.val) := by
  have hlen : (data.val.take (64-p.val)).length = 64-p.val := by simp [hlong]
  have h := take_setSlice pending.val (data.val.take (64-p.val)) p.val (by rw [hlen]; have hb : pending.val.length = 64 := pending.property; omega)
  have hn : p.val+(data.val.take (64-p.val)).length = 64 := by omega
  rw [hn] at h
  have ht := @List.take_length U8 (pending.setSlice! p.val (data.val.take (64-p.val))).val
  simp only [(pending.setSlice! p.val (data.val.take (64-p.val))).property] at ht
  exact ht.symm.trans h

theorem update_fill {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (hc : CompressorRefines compress) (state : Array U32 8#usize)
    (pending : Array U8 64#usize) (p : Usize) (length : U64) (data : Slice U8)
    (hp : p.val < 64) (hlong : 64-p.val ≤ data.val.length) (hpos : 0 < p.val) :
    ∃ out room, room.val = 64-p.val ∧
      update mk compress state pending p length data =
        updateBlocks mk compress out (pending.setSlice! p.val (data.val.take (64-p.val))) room
          (absorbedLength length data) data ∧
      words out = Spec.compressBlocks (words state)
        (Spec.bytes ((pending.val.take p.val ++ data.val.take (64-p.val)).map ofU8)) 0 1 := by
  let room : Usize := UScalar.ofNatCore (64-p.val) (by scalar_tac)
  let filled := pending.setSlice! p.val (data.val.take (64-p.val))
  obtain ⟨out,hout,hm⟩ := hc state filled.to_slice 0#usize 1#usize
    (by simp only [Array.to_slice,filled.property]; decide)
  refine ⟨out,room,rfl,?_,?_⟩
  · simp only [update,lift,bind_tc_ok,sha256.BLOCK]
    rw [sub_ok _ _ (by scalar_tac)]
    simp only [bind_tc_ok,UScalar.lt_equiv,UScalar.ofNatCore_val_eq,Slice.len_val,Slice.length,
      show ¬data.val.length < 64-p.val by omega,if_false]
    rw [if_pos (by scalar_tac),index_mut_from _ _ (by change p.val ≤ 64; omega)]
    simp only [bind_tc_ok,Function.uncurry_apply_pair]
    rw [index_to _ _ (by simpa only [UScalar.ofNatCore_val_eq] using hlong)]
    simp only [bind_tc_ok]
    rw [copy_eq _ _ (by
      simp only [UScalar.ofNatCore_val_eq]
      rw [range_length _ _ _ (by simp only [Array.to_slice,pending.property]; exact Nat.le_refl _),
        range_length _ _ _ hlong]
      rfl)]
    simp only [bind_tc_ok,range,List.slice,List.drop_zero,Nat.sub_zero,UScalar.ofNatCore_val_eq]
    rw [hout]
    rfl
  · simpa only [Array.to_slice,filled,filled_pending pending p data hp hlong] using hm

end LeanBlsSimd.Sha256.Generated
