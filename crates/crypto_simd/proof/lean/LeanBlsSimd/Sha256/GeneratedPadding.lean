import LeanBlsSimd.Sha256.GeneratedFinish

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd.Sha256.Generated

set_option maxRecDepth 2048
attribute [local irreducible] Spec.digest Spec.compressBlocks Spec.padWithBits

theorem array_read_set {α : Type} [Inhabited α] {n : Usize} (a : Array α n)
    (p : Usize) (x : α) (i : Nat) (hp : p.val < n.val) :
    (a.set p x).val[i]! = if i=p.val then x else a.val[i]! := by
  by_cases he : i=p.val
  · rw [if_pos he,← Array.getElem!_Nat_eq,Array.getElem!_Nat_set_eq _ _ _ _
      ⟨he.symm,by change i < a.val.length; rw [a.property]; omega⟩]
  · rw [if_neg he,← Array.getElem!_Nat_eq,Array.getElem!_Nat_set_ne _ _ _ _ (by omega),Array.getElem!_Nat_eq]

theorem paddedBytes_get (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (hp : p.val < 64) (i : Nat) (hi : i < 64*Spec.tailBlocks p.val) :
    ofU8 (paddedBytes pending p length).val[i]! =
      if i<p.val then ofU8 pending.val[i]!
      else if i=p.val then 128
      else if 64*Spec.tailBlocks p.val-8 ≤ i then
        Spec.wordByte (ofU64 length <<< (3 : UInt64)) (i-(64*Spec.tailBlocks p.val-8))
      else 0 := by
  have hblocks : Spec.tailBlocks p.val = 1 ∨ Spec.tailBlocks p.val = 2 := by
    unfold Spec.tailBlocks; split <;> simp
  have hspace : p.val < 64*Spec.tailBlocks p.val-8 := by unfold Spec.tailBlocks; split <;> omega
  have hi128 : i < 128 := by rcases hblocks with h | h <;> rw [h] at hi <;> omega
  have hlen : (pending.val.take p.val).length = p.val := by
    rw [List.length_take,pending.property]; change min p.val 64 = p.val; omega
  let a := (Array.repeat 128#usize 0#u8).setSlice! 0 (pending.val.take p.val)
  let marked := a.set p 128#u8
  change ofU8 ((marked.val.setSlice! (64*Spec.tailBlocks p.val-8)
    (core.num.U64.to_be_bytes (bitLength length)).val)[i]!) = _
  by_cases hlast : 64*Spec.tailBlocks p.val-8 ≤ i
  · rw [List.getElem!_setSlice!_middle]
    · rw [be_u64 _ _ (by rcases hblocks with h | h <;> rw [h] at hi hlast ⊢ <;> omega)]
      rw [if_neg (by omega),if_neg (by omega),if_pos hlast]
      rfl
    · rw [(core.num.U64.to_be_bytes _).property,marked.property]
      change 64*Spec.tailBlocks p.val-8 ≤ i ∧ i-(64*Spec.tailBlocks p.val-8) < 8 ∧ i < 128
      rcases hblocks with h | h <;> rw [h] at hi hlast ⊢ <;> omega
  · rw [List.getElem!_setSlice!_same _ _ _ _ (by left; omega)]
    change ofU8 (a.set p 128#u8).val[i]! = _
    rw [array_read_set _ _ _ _ (by change p.val < 128; omega)]
    by_cases he : i=p.val
    · rw [if_pos he,if_neg (by omega),if_pos he]
      rfl
    · rw [if_neg he,if_neg he,if_neg hlast]
      change ofU8 (((List.replicate 128 0#u8).setSlice! 0 (pending.val.take p.val))[i]!) = _
      by_cases hpre : i<p.val
      · rw [if_pos hpre,List.getElem!_setSlice!_middle]
        · rw [Nat.sub_zero,getElem!_pos _ _ (by rw [hlen]; exact hpre),List.getElem_take,
            ← getElem!_pos pending.val i (by rw [pending.property]; change i < 64; omega)]
        · rw [hlen,List.length_replicate]; omega
      · rw [if_neg hpre,List.getElem!_setSlice!_same _ _ _ _ (by right; rw [hlen]; omega)]
        rw [List.getElem!_replicate _ hi128]
        rfl

theorem paddedBytes_matches (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (hp : p.val < 64) (i : Nat) (hi : i < 64*Spec.tailBlocks p.val) :
    (Spec.bytes ((paddedBytes pending p length).val.map ofU8))[i]! =
      (Spec.padWithBits (Spec.bytes ((pending.val.take p.val).map ofU8))
        (ofU64 length <<< (3 : UInt64)))[i]! := by
  have hlen : (pending.val.take p.val).length = p.val := by
    rw [List.length_take,pending.property]; change min p.val 64 = p.val; omega
  have hsize : (Spec.bytes ((pending.val.take p.val).map ofU8)).size = p.val := by
    rw [Spec.bytes_size,List.length_map,hlen]
  have hpad : Spec.paddedLength (Spec.bytes ((pending.val.take p.val).map ofU8)).size =
      64*Spec.tailBlocks p.val := by rw [hsize,Spec.paddedLength_short _ hp]
  have hi128 : i < 128 := by unfold Spec.tailBlocks at hi; split at hi <;> omega
  rw [Spec.bytes_get,getElem!_pos _ _ (by rw [List.length_map,(paddedBytes pending p length).property]; exact hi128),
    List.getElem_map,← getElem!_pos (paddedBytes pending p length).val i
      (by rw [(paddedBytes pending p length).property]; exact hi128),paddedBytes_get _ _ _ hp i hi,
    Spec.padWithBits_get _ _ i (by rw [hpad]; exact hi),hsize,Spec.paddedLength_short _ hp]
  by_cases hpre : i<p.val
  · rw [if_pos hpre,if_pos hpre,Spec.bytes_get,
      getElem!_pos ((pending.val.take p.val).map ofU8) i (by rw [List.length_map,hlen]; exact hpre),List.getElem_map,List.getElem_take,
      getElem!_pos pending.val i (by rw [pending.property]; change i < 64; omega)]
  · rw [if_neg hpre,if_neg hpre]

theorem finish_refines (compress : Compressor) (hc : CompressorRefines compress)
    (state : Array U32 8#usize) (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (hp : p.val < 64) :
    ∃ out, finish compress state pending p length = ok out ∧
      Spec.bytes (out.val.map ofU8) = Streaming.finish (view state pending p length) := by
  obtain ⟨out,he,hm⟩ := finish_compress compress hc state pending p length hp
  refine ⟨writtenBytes out,?_,?_⟩
  · rw [he]
    exact digest_loop_refines out _ 0#usize (by decide) (by intro k hk; change k < 4*0 at hk; omega)
  · rw [writtenBytes_model,hm]
    unfold Streaming.finish view
    have hlen : ((pending.val.take p.val).map ofU8).length = p.val := by
      rw [List.length_map,List.length_take,pending.property]; change min p.val 64 = p.val; omega
    rw [hlen]
    apply congrArg Spec.digest
    apply Spec.compressBlocks_congr
    intro i hi
    simpa only [Nat.zero_add] using paddedBytes_matches pending p length hp i hi

end LeanBlsSimd.Sha256.Generated
