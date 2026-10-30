import LeanBlsSimd.Sha256.GeneratedDigest

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Generated

set_option maxRecDepth 2048

def bitLength (length : U64) : U64 := ⟨length.bv <<< 3⟩

def paddedBytes (pending : Array U8 64#usize) (p : Usize) (length : U64) : Array U8 128#usize :=
  (((Array.repeat 128#usize 0#u8).setSlice! 0 (pending.val.take p.val)).set p 128#u8).setSlice!
    (64*Spec.tailBlocks p.val-8) (core.num.U64.to_be_bytes (bitLength length)).val

theorem finish_compress (compress : Compressor) (hc : CompressorRefines compress)
    (state : Array U32 8#usize) (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (hp : p.val < 64) :
    ∃ out, finish compress state pending p length =
      sha256.portable.Sha256.finish_loop out (Array.repeat 32#usize 0#u8) 0#usize ∧
      words out = Spec.compressBlocks (words state)
        (Spec.bytes ((paddedBytes pending p length).val.map ofU8)) 0 (Spec.tailBlocks p.val) := by
  let n : Usize := if p.val < 56 then 1#usize else 2#usize
  have hn : n.val = Spec.tailBlocks p.val := by dsimp [n,Spec.tailBlocks]; split <;> rfl
  have hb : 1 ≤ n.val ∧ n.val ≤ 2 := by dsimp [n]; split <;> decide
  obtain ⟨out,hout,hm⟩ := hc state (paddedBytes pending p length).to_slice 0#usize n
    (by simp only [Array.to_slice, Slice.from_val,(paddedBytes pending p length).property]; change 0+64*n.val ≤ 128; omega)
  refine ⟨out,?_,by simpa only [Array.to_slice, Slice.from_val,hn, UScalar.ofNatCore_val_eq] using hm⟩
  simp only [finish]
  rw [index_mut_to _ _ (by change p.val ≤ 128; omega)]
  simp only [bind_tc_ok, bind_ok,Function.uncurry_apply_pair, Aeneas.Std.uncurry_apply_pair]
  rw [array_index_to _ _ (by change p.val ≤ 64; omega)]
  simp only [bind_tc_ok, bind_ok]
  rw [copy_eq _ _ (by
    rw [range_length _ _ _ (by simp only [Array.to_slice, Slice.from_val,(Array.repeat 128#usize 0#u8).property]; change p.val ≤ 128; omega),
      range_length _ _ _ (by simp only [Array.to_slice, Slice.from_val,pending.property]; change p.val ≤ 64; omega)])]
  simp only [bind_tc_ok, bind_ok,range,Array.to_slice, Slice.from_val,List.slice,List.drop_zero,Nat.sub_zero]
  rw [update_eq _ _ _ (by change p.val < 128; omega)]
  simp only [bind_tc_ok, bind_ok,sha256.BLOCK]
  rw [show 64#usize-8#usize = ok 56#usize by simp (disch := scalar_tac) only [sub_ok]; rfl]
  simp only [bind_tc_ok, bind_ok,UScalar.lt_equiv]
  have hnres : (if p.val < (56#usize).val then ok 1#usize else ok 2#usize) = ok n := by
    change (if p.val < 56 then ok 1#usize else ok 2#usize) = ok n
    by_cases h : p.val < 56 <;> simp [n,h]
  rw [hnres]
  simp (disch := scalar_tac) only [bind_tc_ok, bind_ok,mul_ok,sub_ok]
  rw [index_mut_range _ _ _ (by scalar_tac) (by scalar_tac)]
  simp only [bind_tc_ok, bind_ok,Function.uncurry_apply_pair, Aeneas.Std.uncurry_apply_pair]
  rw [show length <<< 3#i32 = ok (bitLength length) from rfl]
  simp only [bind_tc_ok, bind_ok,lift]
  rw [copy_eq _ _ (by
    rw [range_length _ _ _ (by
      simp only [UScalar.ofNatCore_val_eq,Array.to_slice, Slice.from_val]
      rw [(((Array.repeat 128#usize 0#u8).setSlice! 0 (pending.val.take p.val)).set p 128#u8).property]
      change 64*n.val ≤ 128
      omega)]
    simp only [UScalar.ofNatCore_val_eq,Array.to_slice, Slice.from_val,(core.num.U64.to_be_bytes _).property]
    change 64*n.val-(64*n.val-8) = 8; omega)]
  simp only [bind_tc_ok, bind_ok,lift,UScalar.ofNatCore_val_eq,hn]
  simp only [Slice.from_val]
  change (do
    let s ← compress state (paddedBytes pending p length).to_slice 0#usize n
    sha256.portable.Sha256.finish_loop s (Array.repeat 32#usize 0#u8) 0#usize) = _
  rw [hout]
  exact bind_ok _ _

end LeanBlsSimd.Sha256.Generated
