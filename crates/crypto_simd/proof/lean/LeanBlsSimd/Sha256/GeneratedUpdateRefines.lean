import LeanBlsSimd.Sha256.GeneratedUpdate

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Generated

attribute [local irreducible] Spec.compressBlock Spec.schedule Spec.compressBlocks

private theorem join_blocks (state : _root_.Array UInt32) (pre data : List UInt8)
    (hp : pre.length < 64) (hlong : 64-pre.length ≤ data.length) :
    Spec.compressBlocks state (Spec.bytes (pre++data)) 0 ((pre.length+data.length)/64) =
      Spec.compressBlocks
        (Spec.compressBlocks state (Spec.bytes (pre++data.take (64-pre.length))) 0 1)
        (Spec.bytes data) (64-pre.length) ((data.length-(64-pre.length))/64) := by
  have hn : (pre.length+data.length)/64 = 1+(data.length-(64-pre.length))/64 := by omega
  have hfirst : (pre++data.take (64-pre.length)).length = 64 := by
    simp only [List.length_append,List.length_take,Nat.min_eq_left hlong]; omega
  have hjoin : pre++data = (pre++data.take (64-pre.length))++data.drop (64-pre.length) := by
    simp only [List.append_assoc,List.take_append_drop]
  have hd : (pre++data).drop 64 = data.drop (64-pre.length) := by
    rw [List.drop_append,List.drop_eq_nil_of_le (by omega),List.nil_append]
  rw [hn,Spec.compressBlocks_append]
  have hpre : Spec.compressBlocks state (Spec.bytes (pre++data)) 0 1 =
      Spec.compressBlocks state (Spec.bytes (pre++data.take (64-pre.length))) 0 1 := by
    conv_lhs => rw [hjoin]
    exact Spec.compressBlocks_prefix _ _ _ _ (by rw [hfirst])
  rw [hpre]
  conv_lhs => rw [Spec.compressBlocks_drop]
  conv_rhs => rw [Spec.compressBlocks_drop]
  simp only [Nat.zero_add,Nat.mul_one,hd]

private theorem pending_remainder (pending : Array U8 64#usize) (data : Slice U8)
    (start : Usize) (hs : start.val ≤ data.val.length) (next : Usize)
    (hn : next.val = (data.val.length-start.val)%64) :
    ((pending.setSlice! 0 (data.val.drop (start.val+64*((data.val.length-start.val)/64)))).val.take next.val) =
      data.val.drop (start.val+64*((data.val.length-start.val)/64)) := by
  have hl : (data.val.drop (start.val+64*((data.val.length-start.val)/64))).length = next.val := by
    rw [List.length_drop,hn]; omega
  rw [← hl]
  exact take_setSlice_zero _ _ (by rw [hl,hn]; have h := pending.property; change pending.val.length = 64 at h; omega)

theorem update_refines {S : Type} (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (hc : CompressorRefines compress) (state : Array U32 8#usize)
    (pending : Array U8 64#usize) (p : Usize) (length : U64) (data : Slice U8) (hp : p.val < 64) :
    ∃ out pending' next,
      update mk compress state pending p length data = ok (mk out pending' next (absorbedLength length data)) ∧
      next.val < 64 ∧
      view out pending' next (absorbedLength length data) = Streaming.update (view state pending p length) (data.val.map ofU8) := by
  have hplen : (pending.val.take p.val).length = p.val := by
    rw [List.length_take,pending.property]; change min p.val 64 = p.val; omega
  by_cases hshort : data.val.length < 64-p.val
  · obtain ⟨next,hn,he⟩ := update_short mk compress state pending p length data hp hshort
    refine ⟨state,pending.setSlice! p.val data.val,next,he,by omega,?_⟩
    have hj : ((pending.val.take p.val).map ofU8 ++ data.val.map ofU8).length < 64 := by
      simp only [List.length_append,List.length_map,hplen]; omega
    simp only [view,Streaming.update,Nat.div_eq_of_lt hj,Spec.compressBlocks_zero,Nat.mul_zero,
      List.drop_zero,absorbedLength_model,List.length_map]
    congr 1
    rw [hn]
    change ((pending.val.setSlice! p.val data.val).take (p.val+data.val.length)).map ofU8 = _
    rw [take_setSlice _ _ _ (by have h := pending.property; change pending.val.length = 64 at h; omega),List.map_append]
  · have hlong : 64-p.val ≤ data.val.length := by omega
    by_cases hpos : 0 < p.val
    · obtain ⟨first,room,hr,he,hfirst⟩ := update_fill mk compress hc state pending p length data hp hlong hpos
      let filled := pending.setSlice! p.val (data.val.take (64-p.val))
      obtain ⟨out,next,he',hm,hn⟩ := update_blocks mk compress hc first filled room
        (absorbedLength length data) data (by omega)
      let pending' := filled.setSlice! 0 (data.val.drop (room.val+64*((data.val.length-room.val)/64)))
      refine ⟨out,pending',next,he.trans he',by rw [hn]; omega,?_⟩
      have hrem := pending_remainder filled data room (by omega) next hn
      have hjoin := join_blocks (words state) ((pending.val.take p.val).map ofU8) (data.val.map ofU8)
        (by simpa only [List.length_map,hplen] using hp)
        (by simpa only [List.length_map,hplen] using hlong)
      simp only [List.length_map,hplen,← List.map_take,← List.map_append] at hjoin
      have hdrop :
          (((pending.val.take p.val).map ofU8)++data.val.map ofU8).drop
            (64*((p.val+data.val.length)/64)) =
          (data.val.drop (room.val+64*((data.val.length-room.val)/64))).map ofU8 := by
        rw [List.drop_append,List.drop_eq_nil_of_le (by simp only [List.length_map,hplen]; omega),List.nil_append,← List.map_drop]
        simp only [List.length_map,hplen]
        congr 2
        omega
      simp only [view,Streaming.update,List.length_append,List.length_map,hplen,absorbedLength_model]
      congr 1
      · rw [hm,hfirst,hr]
        simpa only [List.map_append] using hjoin.symm
      · exact (congrArg (List.map ofU8) hrem).trans hdrop.symm
    · have hz : p.val = 0 := by omega
      have he : update mk compress state pending p length data =
          updateBlocks mk compress state pending 0#usize (absorbedLength length data) data := by
        simp only [update,lift,bind_tc_ok,sha256.BLOCK]
        rw [sub_ok _ _ (by scalar_tac)]
        simp only [bind_tc_ok,UScalar.lt_equiv,UScalar.ofNatCore_val_eq,Slice.len_val,Slice.length,
          hshort,if_false,show ¬p > 0#usize from hpos]
        rfl
      obtain ⟨out,next,he',hm,hn⟩ := update_blocks mk compress hc state pending 0#usize
        (absorbedLength length data) data (by change 0 ≤ data.val.length; omega)
      refine ⟨out,pending.setSlice! 0 (data.val.drop (0+64*((data.val.length-0)/64))),next,
        he.trans he',by rw [hn]; omega,?_⟩
      have hrem := pending_remainder pending data 0#usize (by change 0 ≤ data.val.length; omega) next hn
      simp only [view,Streaming.update,hz,List.take_zero,List.map_nil,List.nil_append,List.length_map,
        absorbedLength_model]
      congr 1
      simpa only [← List.map_drop,show (0#usize).val = 0 from rfl,Nat.zero_add,Nat.sub_zero] using congrArg (List.map ofU8) hrem

end LeanBlsSimd.Sha256.Generated
